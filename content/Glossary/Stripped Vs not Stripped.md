
In GDB, we can use the following command to list functions:

```bash
info functions
````
## Not Stripped

```
0x401176  win
0x40118b  vuln
0x4011b0  main
```

👉 Function names such as `main`, `vuln`, and `win` are clearly visible.
## Stripped

```
Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  fgets@plt
...
```

👉 Functions like `main` or `win` are not visible anymore.

## Why?

When a binary is **not stripped**, it contains a full symbol table, including:

- User-defined functions (e.g., `main`, `win`, `vuln`)
- Debug-related symbols (e.g., variable names, function names, and source-level information used by debuggers)

This makes it easy to identify functions and understand the program structure.

When a binary is **stripped**, most of the symbol information is removed, especially:

- User-defined function names (`main`, `win`, etc)
- Debug symbols such as:
  - Local/global variable names
  - Function names used for debugging
  - Source file references (e.g., `main.c`, line numbers)

As a result, functions like `main` or `win` are no longer visible in tools like GDB.

However, you may still see symbols like:

- `_init`
- `puts@plt`
- `fgets@plt`

These remain because:

- `_init` is part of the program's initialization code provided by the runtime
- `puts@plt`, `fgets@plt` are entries in the **PLT (Procedure Linkage Table)** used for dynamic linking
- These are required for the program to correctly call external libraries at runtime


Note: The actual code is still present in both cases. Only the symbol information is removed.
