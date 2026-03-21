Dynamic linking = library tidak diikutsertakan saat proses compile, melainkan hanya disimpan sebagai referensi. Library tersebut akan dicari dan di-load saat program dijalankan (runtime).

Static linking = library diikutsertakan langsung ke dalam binary saat proses compile, sehingga program tidak membutuhkan library eksternal saat dijalankan.

## Contoh

Misalnya program menggunakan fungsi `printf` dari libc:

- **Dynamic linking**  
  Binary tidak menyimpan isi `printf`, tetapi akan mengambilnya dari `libc.so` saat runtime.

- **Static linking**  
  Binary sudah menyimpan `printf` di dalamnya sejak compile, jadi bisa langsung dijalankan tanpa butuh `libc` dari sistem.

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
> ⚠️ **Note (belum paham):**
> - ret2libc → belum paham
> - GOT / PLT → belum paham
>
> (akan dipelajari dan diupdate nanti)