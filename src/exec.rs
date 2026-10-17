//! Detection of executable-like files: ELF executable programs (not shared
//! objects), classic a.out / PE / Mach-O executable images, and scripts
//! with a shebang.

use std::io::{self, Read};
use std::path::Path;

/// Bytes scanned from a file: the ELF header (64) plus a realistic program
/// header table (a few hundred entries).
const SCAN: usize = 65536;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const DT_FLAGS_1: u64 = 0x6ffffffb;
const DF_1_PIE: u64 = 0x08000000;
/// Cap on how many dynamic-section entries are scanned.
const MAX_DYN_ENTRIES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfKind {
    /// Not a valid ELF executable: non-ELF, ET_REL, ET_CORE, or malformed.
    NotElf,
    /// ELF shared object (ET_DYN without an interpreter or `DF_1_PIE`).
    Library,
    /// ELF executable program (ET_EXEC, or ET_DYN with `PT_INTERP` or
    /// `DF_1_PIE`).
    Executable,
}

/// Classify the given bytes as an ELF kind.
///
/// `ET_EXEC` is unconditionally an executable program. `ET_DYN` covers both
/// shared objects and position-independent executables; the two are told
/// apart by a `PT_INTERP` program header (the interpreter) or the
/// `DF_1_PIE` flag in the dynamic section, which in practice only
/// executable programs carry. A small number of shared objects (such as
/// glibc's `libc.so`, which can even be run directly) also carry a
/// `PT_INTERP`; they are misclassified as executables, an accepted, low
/// rate (~0.1%) false positive.
pub fn classify_elf(data: &[u8]) -> ElfKind {
    if data.len() < 20 || &data[0..4] != b"\x7fELF" {
        return ElfKind::NotElf;
    }
    let (class, encoding) = (data[4], data[5]);
    let le = match (class, encoding) {
        (1, 1) | (2, 1) => true,
        (1, 2) | (2, 2) => false,
        _ => return ElfKind::NotElf,
    };
    let e_type = rd16(data, 16, le);
    match e_type {
        ET_EXEC => return ElfKind::Executable,
        ET_DYN => {}
        // ET_REL (relocatable object), ET_CORE, reserved types...
        _ => return ElfKind::NotElf,
    }
    let (phoff, phentsize, phnum) = if class == 1 {
        (
            rd32(data, 28, le) as usize,
            rd16(data, 42, le) as usize,
            rd16(data, 44, le) as usize,
        )
    } else {
        (
            rd64(data, 32, le) as usize,
            rd16(data, 54, le) as usize,
            rd16(data, 56, le) as usize,
        )
    };
    let expected = if class == 1 { 32 } else { 56 };
    if phentsize != expected {
        return ElfKind::NotElf;
    }
    let mut dynamic: Option<(usize, usize)> = None;
    if phnum > 0 {
        let table_end = phoff + phentsize * phnum;
        if table_end > data.len() {
            // The program header table runs past the scanned window; a
            // truncated view cannot be proven to contain (or lack) an
            // interpreter or dynamic section.
            return ElfKind::NotElf;
        }
        for i in 0..phnum {
            let base = phoff + i * phentsize;
            match rd32(data, base, le) {
                PT_INTERP => return ElfKind::Executable,
                PT_DYNAMIC => {
                    // p_offset / p_filesz point at the dynamic section.
                    dynamic = if class == 1 {
                        Some((
                            rd32(data, base + 4, le) as usize,
                            rd32(data, base + 16, le) as usize,
                        ))
                    } else {
                        Some((
                            rd64(data, base + 8, le) as usize,
                            rd64(data, base + 32, le) as usize,
                        ))
                    };
                }
                _ => {}
            }
        }
    }
    if dynamic_pie(dynamic, class, le, data) {
        return ElfKind::Executable;
    }
    ElfKind::Library
}

/// Whether the dynamic section of an `ET_DYN` object marks it as a
/// position-independent executable (`DF_1_PIE` in `DT_FLAGS_1`).
///
/// Main toolchains have emitted the flag since around 2014; older PIEs
/// carry a `PT_INTERP` instead (handled by the caller), so a
/// `PT_DYNAMIC` section without the flag is treated as a shared object.
fn dynamic_pie(section: Option<(usize, usize)>, class: u8, le: bool, data: &[u8]) -> bool {
    let Some((offset, filesz)) = section else {
        return false;
    };
    if offset > data.len() || filesz > data.len() - offset {
        // The declared section runs past the scanned window; a truncated
        // view cannot prove the flag either way.
        return false;
    }
    let entry_size = if class == 1 { 8 } else { 16 };
    let entries = (filesz / entry_size).min(MAX_DYN_ENTRIES);
    for i in 0..entries {
        let base = offset + i * entry_size;
        let tag = if class == 1 {
            rd32(data, base, le) as u64
        } else {
            rd64(data, base, le)
        };
        match tag {
            0 => return false, // DT_NULL: end of the section.
            DT_FLAGS_1 => {
                let value = if class == 1 {
                    rd32(data, base + 4, le) as u64
                } else {
                    rd64(data, base + 8, le)
                };
                if value & DF_1_PIE != 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the file starts with a shebang (`#!`).
pub fn has_shebang(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'#' && data[1] == b'!'
}

/// Whether the regular file at `path` looks executable: a shebang script,
/// or an executable program image (ELF, a.out, PE, or Mach-O; shared
/// objects and other object files do not count).
pub fn detect(path: &Path) -> io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; SCAN];
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    buf.truncate(filled);
    Ok(has_shebang(&buf)
        || classify_elf(&buf) == ElfKind::Executable
        || is_aout_executable(&buf)
        || is_pe_executable(&buf)
        || is_macho_executable(&buf))
}

/// Whether the data starts with the magic bytes of an executable a.out
/// object.
///
/// `ZMAGIC` (0x01080005) and `ZMAGICI` (0x01080001) in either endianness
/// are modern a.out executables; `OMAGIC` (0x0104) and `QMAGIC` (0x00C5)
/// are the 16-bit legacy variants. The 32-bit magics are checked first so
/// a big-endian `ZMAGICI` (01 08 00 01) is not mistaken for `NMAGIC`
/// (01 08).
pub fn is_aout_executable(data: &[u8]) -> bool {
    const ZMAGIC: u32 = 0x01080005;
    const ZMAGICI: u32 = 0x01080001;
    const OMAGIC: u16 = 0x0104;
    const QMAGIC: u16 = 0x00C5;
    if data.len() >= 4 {
        let word = [data[0], data[1], data[2], data[3]];
        let (le, be) = (u32::from_le_bytes(word), u32::from_be_bytes(word));
        if le == ZMAGIC || le == ZMAGICI || be == ZMAGIC || be == ZMAGICI {
            return true;
        }
    }
    if data.len() >= 2 {
        let word = [data[0], data[1]];
        let (le, be) = (u16::from_le_bytes(word), u16::from_be_bytes(word));
        le == OMAGIC || le == QMAGIC || be == OMAGIC || be == QMAGIC
    } else {
        false
    }
}

/// Whether the data starts with the magic bytes of an executable PE image
/// (Windows-style, and what cross-compilers emit for that target).
///
/// A PE image with `IMAGE_FILE_DLL` set in `Characteristics` is a DLL
/// rather than a program and does not count.
pub fn is_pe_executable(data: &[u8]) -> bool {
    const IMAGE_FILE_DLL: u16 = 0x2000;
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    // `e_lfanew` is little-endian even in big-endian PE files.
    let pe = rd32(data, 0x3C, true) as usize;
    if pe + 24 > data.len() || &data[pe..pe + 4] != b"PE\0\0" {
        return false;
    }
    rd16(data, pe + 22, true) & IMAGE_FILE_DLL == 0
}

/// Whether the data starts with the magic bytes of an executable Mach-O
/// object (Apple's format; kept so cross-toolchain artifacts classify
/// sanely).
///
/// `MH_EXECUTE` and `MH_DYLIB_STUB` count; `MH_DYLIB` does not.
pub fn is_macho_executable(data: &[u8]) -> bool {
    const MH_MAGIC: u32 = 0xFEEDFACE;
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const MH_EXECUTE: u32 = 2;
    const MH_DYLIB_STUB: u32 = 7;
    if data.len() < 16 {
        return false;
    }
    for le in [true, false] {
        let magic = rd32(data, 0, le);
        if magic == MH_MAGIC || magic == MH_MAGIC_64 {
            let file_type = rd32(data, 12, le);
            return file_type == MH_EXECUTE || file_type == MH_DYLIB_STUB;
        }
    }
    false
}

fn rd16(data: &[u8], offset: usize, le: bool) -> u16 {
    if data.len() < offset + 2 {
        return 0;
    }
    let bytes = [data[offset], data[offset + 1]];
    if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}

fn rd32(data: &[u8], offset: usize, le: bool) -> u32 {
    if data.len() < offset + 4 {
        return 0;
    }
    let bytes = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn rd64(data: &[u8], offset: usize, le: bool) -> u64 {
    if data.len() < offset + 8 {
        return 0;
    }
    let bytes = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ];
    if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    }
}

/// Minimal, hand-built ELF blobs for tests.
///
/// The blobs are not runnable; they just carry a valid header and program
/// header table, which is all `classify_elf` inspects.
#[doc(hidden)]
pub mod fixtures {
    /// Build a minimal ELF blob.
    ///
    /// `e_type`: 1 = ET_REL, 2 = ET_EXEC, 3 = ET_DYN.
    /// `class`: 1 = ELF32, 2 = ELF64.
    /// `le`: little-endian byte order (`EI_DATA`).
    /// `ptypes`: each program header as `(p_type, p_offset)`.
    /// `dynamic`: if `Some`, a `PT_DYNAMIC` header is appended after the
    /// given program headers, pointing at a section holding these bytes,
    /// placed right after the program header table.
    pub fn elf(
        e_type: u16,
        class: u8,
        le: bool,
        ptypes: &[(u32, u64)],
        dynamic: Option<&[u8]>,
    ) -> Vec<u8> {
        const PT_DYNAMIC: u32 = 2;
        let is64 = class == 2;
        let (ehsize, phentsize): (usize, usize) = if is64 { (64, 56) } else { (52, 32) };
        let mut b = vec![0u8; ehsize];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = class;
        b[5] = if le { 1 } else { 2 };
        b[6] = 1;
        put16(&mut b, 16, e_type, le);
        put16(&mut b, 18, if is64 { 62 } else { 3 }, le);
        put32(&mut b, 20, 1, le);
        let phnum = ptypes.len() + usize::from(dynamic.is_some());
        if is64 {
            put64(&mut b, 32, ehsize as u64, le);
            put16(&mut b, 52, ehsize as u16, le);
            put16(&mut b, 54, phentsize as u16, le);
            put16(&mut b, 56, phnum as u16, le);
        } else {
            put32(&mut b, 28, ehsize as u32, le);
            put16(&mut b, 40, ehsize as u16, le);
            put16(&mut b, 42, phentsize as u16, le);
            put16(&mut b, 44, phnum as u16, le);
        }
        for (i, (p_type, p_offset)) in ptypes.iter().enumerate() {
            let off = ehsize + i * phentsize;
            b.resize(off + phentsize, 0);
            put32(&mut b, off, *p_type, le);
            if is64 {
                put64(&mut b, off + 8, *p_offset, le);
            } else {
                put32(&mut b, off + 4, *p_offset as u32, le);
            }
        }
        if let Some(section) = dynamic {
            let off = ehsize + ptypes.len() * phentsize;
            b.resize(off + phentsize, 0);
            let section_off = off as u64 + phentsize as u64;
            put32(&mut b, off, PT_DYNAMIC, le);
            if is64 {
                put64(&mut b, off + 8, section_off, le);
                put64(&mut b, off + 32, section.len() as u64, le);
            } else {
                put32(&mut b, off + 4, section_off as u32, le);
                put32(&mut b, off + 16, section.len() as u32, le);
            }
            b.extend_from_slice(section);
        }
        b
    }

    fn put16(b: &mut [u8], off: usize, v: u16, le: bool) {
        let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
        b[off..off + 2].copy_from_slice(&bytes);
    }

    fn put32(b: &mut [u8], off: usize, v: u32, le: bool) {
        let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
        b[off..off + 4].copy_from_slice(&bytes);
    }

    fn put64(b: &mut [u8], off: usize, v: u64, le: bool) {
        let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
        b[off..off + 8].copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures;
    use super::*;
    use std::fs;

    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;

    /// 64-bit little-endian dynamic section: `DT_FLAGS_1 = DF_1_PIE`, then
    /// `DT_NULL`.
    const DYN64_PIE: &[u8] = &[
        // d_tag = DT_FLAGS_1 (0x6ffffffb), 64-bit LE
        0xfb, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
        // d_val = DF_1_PIE (0x08000000), 64-bit LE
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, // DT_NULL
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    /// 64-bit dynamic section with a single `DT_NULL`.
    const DYN64_NULL: &[u8] = &[0u8; 16];
    /// 32-bit little-endian dynamic section: `DT_FLAGS_1 = DF_1_PIE`, then
    /// `DT_NULL`.
    const DYN32_PIE: &[u8] = &[
        // d_tag = DT_FLAGS_1 (0x6ffffffb), 32-bit LE
        0xfb, 0xff, 0xff, 0x6f, // d_val = DF_1_PIE (0x08000000), 32-bit LE
        0x00, 0x00, 0x00, 0x08, // DT_NULL
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    /// 32-bit dynamic section with a single `DT_NULL`.
    const DYN32_NULL: &[u8] = &[0u8; 8];

    /// A minimal PE image: DOS header with a fixed `e_lfanew`, the
    /// `PE\0\0` signature, and `Characteristics` as given.
    fn pe_image(characteristics: u16) -> Vec<u8> {
        const PE: u32 = 0x40;
        let mut b = vec![0u8; PE as usize + 24];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&PE.to_le_bytes());
        b[PE as usize..PE as usize + 4].copy_from_slice(b"PE\0\0");
        b[PE as usize + 22..PE as usize + 24].copy_from_slice(&characteristics.to_le_bytes());
        b
    }

    /// A minimal Mach-O header with the given magic and file type.
    fn macho_image(magic: u32, file_type: u32, le: bool) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        let m = if le {
            magic.to_le_bytes()
        } else {
            magic.to_be_bytes()
        };
        let f = if le {
            file_type.to_le_bytes()
        } else {
            file_type.to_be_bytes()
        };
        b[0..4].copy_from_slice(&m);
        b[12..16].copy_from_slice(&f);
        b
    }

    #[test]
    fn elf64_et_exec_is_executable() {
        assert_eq!(
            classify_elf(&fixtures::elf(2, 2, true, &[], None)),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf64_pie_is_executable() {
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                2,
                true,
                &[(PT_LOAD, 0), (PT_INTERP, 0)],
                None
            )),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf64_pie_dynamic_flag_is_executable() {
        assert_eq!(
            classify_elf(&fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(DYN64_PIE))),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf32_pie_dynamic_flag_is_executable() {
        assert_eq!(
            classify_elf(&fixtures::elf(3, 1, true, &[(PT_LOAD, 0)], Some(DYN32_PIE))),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf64_pie_dynamic_flag_big_endian() {
        let mut section = vec![0u8; 32];
        // ELF64 d_tag is 8 bytes; write the full big-endian value.
        section[0..8].copy_from_slice(&0x6ffffffbu64.to_be_bytes());
        section[8..16].copy_from_slice(&0x08000000u64.to_be_bytes());
        assert_eq!(
            classify_elf(&fixtures::elf(3, 2, false, &[(PT_LOAD, 0)], Some(&section))),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf64_pie_after_other_dynamic_entries() {
        let mut section = vec![0u8; 48];
        // DT_NEEDED (tag 1), then DT_FLAGS_1 = DF_1_PIE, then DT_NULL.
        section[0..4].copy_from_slice(&1u32.to_le_bytes());
        section[16..20].copy_from_slice(&0x6ffffffbu32.to_le_bytes());
        section[24..32].copy_from_slice(&0x08000000u64.to_le_bytes());
        assert_eq!(
            classify_elf(&fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(&section))),
            ElfKind::Executable
        );
    }

    #[test]
    fn elf64_shared_object_is_library() {
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                2,
                true,
                &[(PT_LOAD, 0)],
                Some(DYN64_NULL)
            )),
            ElfKind::Library
        );
    }

    #[test]
    fn elf64_dyn_without_pie_flag_is_library() {
        let mut section = DYN64_PIE.to_vec();
        section[8..16].fill(0); // clear the DF_1_PIE value
        assert_eq!(
            classify_elf(&fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(&section))),
            ElfKind::Library
        );
    }

    #[test]
    fn elf64_truncated_dynamic_section_is_library() {
        let d = fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(DYN64_PIE));
        let cut = d.len() - 8;
        assert_eq!(
            classify_elf(&d[..cut]),
            ElfKind::Library,
            "the declared dynamic section runs past the scanned data"
        );
    }

    #[test]
    fn elf32_variants() {
        assert_eq!(
            classify_elf(&fixtures::elf(2, 1, true, &[], None)),
            ElfKind::Executable
        );
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                1,
                true,
                &[(PT_LOAD, 0), (PT_INTERP, 0)],
                None
            )),
            ElfKind::Executable
        );
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                1,
                true,
                &[(PT_LOAD, 0)],
                Some(DYN32_NULL)
            )),
            ElfKind::Library
        );
    }

    #[test]
    fn big_endian_elf() {
        assert_eq!(
            classify_elf(&fixtures::elf(2, 2, false, &[], None)),
            ElfKind::Executable
        );
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                2,
                false,
                &[(PT_LOAD, 0), (PT_INTERP, 0)],
                None
            )),
            ElfKind::Executable
        );
        assert_eq!(
            classify_elf(&fixtures::elf(
                3,
                2,
                false,
                &[(PT_LOAD, 0)],
                Some(DYN64_NULL)
            )),
            ElfKind::Library
        );
    }

    #[test]
    fn et_rel_is_not_executable() {
        assert_eq!(
            classify_elf(&fixtures::elf(1, 2, true, &[], None)),
            ElfKind::NotElf
        );
    }

    #[test]
    fn bad_magic() {
        let mut d = fixtures::elf(2, 2, true, &[], None);
        d[0] = b'X';
        assert_eq!(classify_elf(&d), ElfKind::NotElf);
    }

    #[test]
    fn aout_zmagic_is_executable() {
        // ZMAGIC 0x01080005, little- and big-endian.
        assert!(is_aout_executable(b"\x05\x00\x08\x01"));
        assert!(is_aout_executable(b"\x01\x08\x00\x05"));
        // With trailing bytes, as in a real header.
        assert!(is_aout_executable(b"\x05\x00\x08\x01\x00\x00\x00\x00"));
    }

    #[test]
    fn aout_zmagici_is_executable() {
        // ZMAGICI 0x01080001, little- and big-endian.
        assert!(is_aout_executable(b"\x01\x00\x08\x01"));
        assert!(is_aout_executable(b"\x01\x08\x00\x01"));
    }

    #[test]
    fn aout_omagic_and_qmagic_are_executable() {
        // OMAGIC 0x0104, both endiannesses (including a 2-byte view).
        assert!(is_aout_executable(b"\x04\x01\x00\x00"));
        assert!(is_aout_executable(b"\x01\x04"));
        // QMAGIC 0x00C5, both endiannesses.
        assert!(is_aout_executable(b"\xc5\x00\x00\x00"));
        assert!(is_aout_executable(b"\x00\xc5"));
    }

    #[test]
    fn aout_nmagic_zero_and_short_are_not() {
        // NMAGIC 0x0108, both endiannesses.
        assert!(!is_aout_executable(b"\x08\x01\x00\x00"));
        assert!(!is_aout_executable(b"\x01\x08"));
        assert!(!is_aout_executable(b"\x00\x00\x00\x00"));
        assert!(!is_aout_executable(b"\x05\x00"));
        assert!(!is_aout_executable(b""));
    }

    #[test]
    fn aout_be_zmagici_wins_over_nmagic() {
        // 01 08 00 01: the first two bytes spell big-endian NMAGIC; the
        // 4-byte ZMAGICI check must take precedence.
        assert!(is_aout_executable(b"\x01\x08\x00\x01"));
    }

    #[test]
    fn pe_executable_is_executable() {
        assert!(is_pe_executable(&pe_image(0x0102)));
    }

    #[test]
    fn pe_dll_is_not_executable() {
        // IMAGE_FILE_DLL set: a DLL, not a program.
        assert!(!is_pe_executable(&pe_image(0x2102)));
    }

    #[test]
    fn pe_bogus() {
        assert!(!is_pe_executable(b""));
        assert!(!is_pe_executable(b"MZ"));
        let mut b = pe_image(0x0102);
        b[0] = b'X';
        assert!(!is_pe_executable(&b), "bad DOS magic");
        let mut b = pe_image(0x0102);
        b[0x40] = b'X';
        assert!(!is_pe_executable(&b), "bad PE signature");
        let mut b = pe_image(0x0102);
        b[0x3C..0x40].copy_from_slice(&1000u32.to_le_bytes());
        assert!(!is_pe_executable(&b), "e_lfanew past the end");
    }

    #[test]
    fn macho_execute_is_executable() {
        assert!(is_macho_executable(&macho_image(0xFEEDFACE, 2, true)));
        assert!(is_macho_executable(&macho_image(0xFEEDFACE, 2, false)));
        assert!(is_macho_executable(&macho_image(0xFEEDFACF, 2, true)));
        assert!(is_macho_executable(&macho_image(0xFEEDFACF, 2, false)));
    }

    #[test]
    fn macho_dylib_stub_is_executable() {
        assert!(is_macho_executable(&macho_image(0xFEEDFACF, 7, true)));
    }

    #[test]
    fn macho_dylib_is_not_executable() {
        assert!(!is_macho_executable(&macho_image(0xFEEDFACE, 6, true)));
        assert!(!is_macho_executable(&macho_image(0xFEEDFACF, 6, false)));
    }

    #[test]
    fn macho_bogus() {
        assert!(!is_macho_executable(b""));
        assert!(
            !is_macho_executable(&macho_image(0xFEEDFACE, 0, true)),
            "MH_OBJECT"
        );
        assert!(
            !is_macho_executable(&macho_image(0xCAFEBABE, 2, true)),
            "bad magic"
        );
    }

    #[test]
    fn too_short() {
        assert_eq!(classify_elf(&[]), ElfKind::NotElf);
        assert_eq!(classify_elf(b"\x7fELF"), ElfKind::NotElf);
        assert_eq!(
            classify_elf(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            ElfKind::NotElf
        );
    }

    #[test]
    fn bad_class_or_encoding() {
        let mut d = fixtures::elf(2, 2, true, &[], None);
        d[4] = 0;
        assert_eq!(classify_elf(&d), ElfKind::NotElf);
        let mut d = fixtures::elf(2, 2, true, &[], None);
        d[5] = 9;
        assert_eq!(classify_elf(&d), ElfKind::NotElf);
    }

    #[test]
    fn truncated_program_header_table() {
        let d = fixtures::elf(3, 2, true, &[(PT_INTERP, 0)], None);
        assert_eq!(
            classify_elf(&d[..64]),
            ElfKind::NotElf,
            "table starts at 64, nothing there"
        );
        assert_eq!(
            classify_elf(&d[..100]),
            ElfKind::NotElf,
            "first entry cut off"
        );
        assert_eq!(classify_elf(&d), ElfKind::Executable, "full table present");
    }

    #[test]
    fn shebang() {
        assert!(has_shebang(b"#!/bin/sh\necho hi\n"));
        assert!(has_shebang(b"#!"));
        assert!(has_shebang(b"#!\x00"));
        assert!(!has_shebang(b"#x"));
        assert!(!has_shebang(b"!#"));
        assert!(!has_shebang(b"#"));
        assert!(!has_shebang(b""));
    }

    #[test]
    fn detect_reads_regular_files() {
        let dir = tempfile::tempdir().unwrap();

        let exe = dir.path().join("exe");
        fs::write(&exe, fixtures::elf(2, 2, true, &[], None)).unwrap();
        assert!(detect(&exe).unwrap());

        let pie = dir.path().join("pie");
        fs::write(
            &pie,
            fixtures::elf(3, 2, true, &[(PT_LOAD, 0), (PT_INTERP, 0)], None),
        )
        .unwrap();
        assert!(detect(&pie).unwrap());

        let pie_dyn = dir.path().join("pie_dyn");
        fs::write(
            &pie_dyn,
            fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(DYN64_PIE)),
        )
        .unwrap();
        assert!(detect(&pie_dyn).unwrap());

        let lib = dir.path().join("lib.so");
        fs::write(
            &lib,
            fixtures::elf(3, 2, true, &[(PT_LOAD, 0)], Some(DYN64_NULL)),
        )
        .unwrap();
        assert!(!detect(&lib).unwrap());

        let script = dir.path().join("s.sh");
        fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        assert!(detect(&script).unwrap());

        let aout = dir.path().join("aout");
        fs::write(&aout, b"\x05\x00\x08\x01").unwrap();
        assert!(detect(&aout).unwrap());

        let pe = dir.path().join("pe");
        fs::write(&pe, pe_image(0x0102)).unwrap();
        assert!(detect(&pe).unwrap());

        let macho = dir.path().join("macho");
        fs::write(&macho, macho_image(0xFEEDFACF, 2, true)).unwrap();
        assert!(detect(&macho).unwrap());

        let text = dir.path().join("t.txt");
        fs::write(&text, b"hello world\n").unwrap();
        assert!(!detect(&text).unwrap());

        let empty = dir.path().join("empty");
        fs::write(&empty, b"").unwrap();
        assert!(!detect(&empty).unwrap());
    }

    #[test]
    fn system_true_is_executable() {
        for cand in [
            std::path::Path::new("/bin/true"),
            std::path::Path::new("/usr/bin/true"),
        ] {
            if cand.exists() {
                assert!(
                    detect(cand).unwrap(),
                    "{cand:?} must classify as executable"
                );
                return;
            }
        }
        eprintln!("note: no true(1) found on this system; skipped");
    }
}
