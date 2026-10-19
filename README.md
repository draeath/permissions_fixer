An AI-slopped rust program that recursively scans directories for scripts with shebangs and executables (ELF, a.out, Mach-O, PE) and "fixes" their permissions (respecting your umask). For example, regular files get 0644, executables and directories 0755.

This is intended to clean-up the packaging fuckups of people who distribute linux software via zip, or do stupid things like a recurshive chmod +x (GOG puts this in their start.sh for some stupid reason).

If it breaks, you get to keep what's left.
