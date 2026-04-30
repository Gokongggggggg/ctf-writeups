![[Pasted image 20260405131649.png]]

## laper.asm

![[Pasted image 20260405131801.png]]

> [!note]- Explanation & FLAG
>
> To read this assembly, we first need to know what the registers mean.
>
> - `sp` = **stack pointer**  
>   Think of this as a pointer to a temporary workspace used by the function.
>
> - `w0` = the **first integer argument** in ARM64, and also the register used for the **return value**  
>   So if the challenge asks for `laper(47)`, we assume:
>
>   ```text
>   w0 = 47
>   ```
>
> - `w8` = just another general-purpose register used as a temporary variable
>
> The number after `#` is an **immediate constant**, meaning a fixed value written directly in the instruction.
>
> So for example:
>
> - `#16` means the constant value `16`
> - `#12` means the constant value `12`
> - `#42` means the constant value `42`
> - `#2` means the constant value `2`
> - `#1` means the constant value `1`
>
> Now we can read the function line by line, assuming the input is `47`.
>
> ```asm
> sub sp, sp, #16
> ```
>
> This subtracts 16 from `sp`, which means the function reserves 16 bytes of stack space.
>
> ```asm
> str w0, [sp, #12]
> ```
>
> `str` means **store register**.  
> This stores the value of `w0` into memory at address `sp + 12`.
>
> Since our input is `47`, this means:
>
> ```text
> [sp + 12] = 47
> ```
>
> ```asm
> ldr w8, [sp, #12]
> ```
>
> `ldr` means **load register**.  
> This reads the value at `sp + 12` back into `w8`.
>
> So now:
>
> ```text
> w8 = 47
> ```
>
> ```asm
> subs w8, w8, #42
> ```
>
> This subtracts `42` from `w8`.
>
> ```text
> w8 = 47 - 42 = 5
> ```
>
> ```asm
> add w8, w8, #2
> ```
>
> Add `2`:
>
> ```text
> w8 = 5 + 2 = 7
> ```
>
> ```asm
> lsl w0, w8, #1
> ```
>
> `lsl` means **logical shift left**.  
> Shifting left by 1 bit is equivalent to multiplying by 2.
>
> So:
>
> ```text
> w0 = 7 << 1 = 14
> ```
>
> ```asm
> add sp, sp, #16
> ```
>
> Restore the stack pointer back to its original value.
>
> ```asm
> ret
> ```
>
> Return from the function.
>
> Since return values are placed in `w0`, the function returns:
>
> ```text
> 14
> ```
>
> So:
>
> ```text
> laper(47) = 14
> ```
>
> and the final flag is:
>
> ```text
> PETIR{14}
> ```