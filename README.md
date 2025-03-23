# PE Parser and Dynamic Function Loader

This Rust project experiments with loading Windows API functions (`LoadLibraryA`, `MessageBoxA`) by parsing PE headers and export tables, avoiding dependencies in the import section.

## Features
- Retrieves the base address of `kernelbase.dll` via PEB/LDR.
- Parses PE headers to locate export tables and dynamically find functions (`LoadLibraryA`, `MessageBoxA`).
- Loads DLLs and calls exported functions at runtime.

When built, `user32.dll` and `MessageBoxA` should not appear in the import section. Note that `LoadLibraryA` might still be visible in some builds (e.g., with GNU tools), possibly due to linker behavior.
