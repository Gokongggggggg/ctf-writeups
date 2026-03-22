Dynamic linking = libraries are not included during the compilation process, but only referenced. These libraries are located and loaded at runtime when the program is executed.

Static linking = libraries are directly included into the binary during compilation, so the program does not require external libraries at runtime.

## Example

Suppose a program uses the `printf` function from libc:

- **Dynamic linking**  
  The binary does not contain the actual `printf` implementation, but instead loads it from `libc.so` at runtime.

- **Static linking**  
  The binary already contains `printf` at compile time, so it can run independently without requiring `libc` from the system.

## When we know a binary is statically or dynamically linked, what information can we derive from it?

**Answer:** We can check what dependencies the binary needs, so we can provide the required libraries and run it properly.

> [!tip]- Explanation
> If a binary uses [[Dynamic Linking]], it means the program depends on external libraries (such as libc) that must be available at runtime.
>
> We can check these dependencies using:
> ```bash
> ldd ./binary
> ```
>
> From this, we know what libraries are required to run the program correctly.
>
> In contrast, if the binary uses [[Static Linking]], all libraries are already included during compile time, so no external dependencies are needed.

> [!info]- more advance  
> Beyond just running the binary, this information can also be useful for more advanced analysis, such as identifying possible exploitation paths:  
> - ret2libc  
> - GOT / PLT hijacking  
>
> ⚠️ **Note (not yet understood):**  
> - ret2libc → not yet understood  
> - GOT / PLT → not yet understood  
>
> (will be studied and updated later)