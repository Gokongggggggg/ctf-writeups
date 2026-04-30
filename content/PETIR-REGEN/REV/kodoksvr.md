![[Pasted image 20260407090755.png]]

## Description

> We were given a file named `kodok.scr`.
>
> Even though the extension is `.scr`, this is still just a normal **Windows PE executable**. On Windows, screensavers are basically ordinary GUI applications that use a different file extension.
>
> When executed, the program displays bouncing frogs together with the caption:
>
>![[Pasted image 20260407094106.png]]
>
> At first glance, this looks like harmless decorative text. However, after reversing the binary, it turns out that this exact caption is part of the hidden validation logic.

## Recon

> [!note]- Initial recon
> I started with the usual quick checks:
>
> ```bash
> file kodok.scr
> ```
>
> Output:
>
> ```text
> PE32+ executable (GUI) x86-64, for MS Windows
> ```
>
> So the file is simply a 64-bit Windows GUI executable.
>
> I then checked whether the flag was stored directly in the binary:
>
> ```bash
> strings kodok.scr | grep "PETIR{"
> ```
>
> No result.
>
> Since Windows binaries often store strings as UTF-16, I also checked wide strings:
>
> ```bash
> strings -e l kodok.scr | grep "PETIR{"
> ```
>
> Still nothing.
>
> At this point, it was clear that the flag was not stored in plaintext, so the next step was static analysis in **Ghidra**.

## Entry Point

> [!note]- Entry point
> The program starts from a very small entry function:
>
>![[Pasted image 20260407095235.png]]
>
> From this alone, we can already split the early execution flow into two parts:
>
> - `FUN_140002398()`
> - `FUN_140001fd0()`
>
> So the next step is to inspect both of them and determine which one actually leads into the challenge logic.

> [!note]- Full decompile: `FUN_140002398`
> ```c
> void FUN_140002398(void)
> {
>     DWORD DVar1;
>     _FILETIME local_res8;
>     LARGE_INTEGER local_res10;
>     _FILETIME local_18[2];
>
>     if (DAT_140005040 == 0x2b992ddfa232) {
>         local_res8.dwLowDateTime = 0;
>         local_res8.dwHighDateTime = 0;
>         GetSystemTimeAsFileTime(&local_res8);
>         local_18[0] = local_res8;
>
>         DVar1 = GetCurrentThreadId();
>         local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
>
>         DVar1 = GetCurrentProcessId();
>         local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
>
>         QueryPerformanceCounter(&local_res10);
>
>         DAT_140005040 =
>             (
>                 (ulonglong)local_res10.s.LowPart << 0x20 ^
>                 CONCAT44(local_res10.s.HighPart, local_res10.s.LowPart) ^
>                 (ulonglong)local_18[0] ^
>                 (ulonglong)local_18
>             ) & 0xffffffffffff;
>
>         if (DAT_140005040 == 0x2b992ddfa232) {
>             DAT_140005040 = 0x2b992ddfa233;
>         }
>     }
>
>     _DAT_140005080 = ~DAT_140005040;
>     return;
> }
> ```

> [!note]- Reading `FUN_140002398`
> After looking at the decompiled code, this function appears to combine several runtime-dependent values such as:
>
> - system time
> - current thread ID
> - current process ID
> - performance counter
>
> and then store the result into global data.
>
> This is a very common startup pattern used to initialize a security cookie or guard value. It does not process the displayed caption, does not transform any challenge-specific data, and does not compare anything against a target value.
>
> So for the purpose of solving the challenge, `FUN_140002398()` can be treated as startup boilerplate.

> [!note]- Full decompile: `FUN_140001fd0`
> ```c
> /* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
> ulonglong FUN_140001fd0(void)
> {
>     bool bVar1;
>     bool bVar2;
>     int iVar3;
>     undefined8 uVar4;
>     longlong *plVar5;
>     ulonglong uVar6;
>     short *psVar7;
>     HWND pHVar8;
>     IMAGE_DOS_HEADER *pIVar9;
>     undefined8 unaff_RBX;
>
>     iVar3 = (int)unaff_RBX;
>     uVar4 = FUN_140002194(1);
>     if ((char)uVar4 == '\0') {
>         FUN_1400024c8(7);
>     }
>     else {
>         bVar1 = false;
>         uVar4 = __scrt_acquire_startup_lock();
>         iVar3 = (int)CONCAT71((int7)((ulonglong)unaff_RBX >> 8), (char)uVar4);
>
>         if (DAT_1400050a0 != 1) {
>             if (DAT_1400050a0 == 0) {
>                 DAT_1400050a0 = 1;
>                 iVar3 = _initterm_e(&DAT_140003350, &DAT_140003368);
>                 if (iVar3 != 0) {
>                     return 0xff;
>                 }
>                 _initterm(&DAT_140003338);
>                 DAT_1400050a0 = 2;
>             }
>             else {
>                 bVar1 = true;
>             }
>
>             __scrt_release_startup_lock((char)uVar4);
>
>             plVar5 = (longlong *)FUN_1400024ac();
>             if ((*plVar5 != 0) &&
>                 (uVar6 = FUN_14000225c((longlong)plVar5), (char)uVar6 != '\0')) {
>                 (*(code *)*plVar5)(0);
>             }
>
>             plVar5 = (longlong *)FUN_1400024b4();
>             if ((*plVar5 != 0) &&
>                 (uVar6 = FUN_14000225c((longlong)plVar5), (char)uVar6 != '\0')) {
>                 _register_thread_local_exe_atexit_callback(*plVar5);
>             }
>
>             __scrt_get_show_window_mode();
>             psVar7 = (short *)_get_wide_winmain_command_line();
>             pIVar9 = &IMAGE_DOS_HEADER_140000000;
>             pHVar8 = FUN_140001000((HINSTANCE)&IMAGE_DOS_HEADER_140000000, 0, psVar7);
>             iVar3 = (int)pHVar8;
>             bVar2 = FUN_140002658();
>
>             if (bVar2) {
>                 if (!bVar1) {
>                     _cexit();
>                 }
>                 __scrt_uninitialize_crt(CONCAT71((int7)((ulonglong)pIVar9 >> 8), 1), '\0');
>                 return (ulonglong)pHVar8 & 0xffffffff;
>             }
>             goto LAB_140002131;
>         }
>     }
>
>     FUN_1400024c8(7);
>
> LAB_140002131:
>     /* WARNING: Subroutine does not return */
>     exit(iVar3);
> }
> ```

> [!note]- Reading `FUN_140001fd0`
> This second function is much longer, but most of it is still CRT/runtime boilerplate.
>
> We can see the usual patterns here:
>
> - CRT startup checks
> - startup lock handling
> - `_initterm_e` and `_initterm`
> - thread-local cleanup registration
> - CRT shutdown / exit flow
>
> The important part is near the end:
>
> ```c
> psVar7 = (short *)_get_wide_winmain_command_line();
> pHVar8 = FUN_140001000((HINSTANCE)&IMAGE_DOS_HEADER_140000000, 0, psVar7);
> ```
>
> This is the first real handoff into the actual application logic.
>
> In other words, `FUN_140001fd0()` mainly acts as the bridge between runtime startup and the program's GUI code.

> [!note]- Moving forward
> Since `FUN_140002398()` is only initialization code and `FUN_140001fd0()` is mostly CRT setup, the first function that looks truly relevant to the challenge is:
>
> ```c
> FUN_140001000((HINSTANCE)&IMAGE_DOS_HEADER_140000000, 0, psVar7);
> ```
>
> So the next step is to inspect `FUN_140001000()`, because that is where the screensaver window is created and where the real GUI flow begins.

> [!note]- Full decompile: `FUN_140001000`
> ```c
> HWND FUN_140001000(HINSTANCE param_1, undefined8 param_2, short *param_3)
> {
>     short *psVar1;
>     wchar_t wVar2;
>     bool bVar3;
>     short sVar4;
>     ATOM AVar5;
>     int iVar6;
>     int nWidth;
>     HWND hWnd;
>     HWND pHVar7;
>     HWND pHVar8;
>     wchar_t *_Str;
>     WNDCLASSW local_8b8;
>     tagRECT local_868;
>     undefined1 local_858[2128];
> 
>     pHVar7 = (HWND)0x0;
>     bVar3 = false;
>     pHVar8 = (HWND)0x0;
>     hWnd = pHVar7;
>     DAT_140005120 = param_1;
> 
>     if ((param_3 != (short *)0x0) && (sVar4 = *param_3, hWnd = pHVar8, sVar4 != 0)) {
>         while ((sVar4 == 0x20 || (sVar4 == 9))) {
>             psVar1 = param_3 + 1;
>             param_3 = param_3 + 1;
>             sVar4 = *psVar1;
>         }
>         if (((*param_3 - 0x2dU & 0xfffd) == 0) && ((param_3[1] - 0x50U & 0xffdf) == 0)) {
>             bVar3 = true;
>             for (_Str = param_3 + 2;
>                 ((wVar2 = *_Str, wVar2 == L' ' || (wVar2 == L':')) || (wVar2 == L'\t'));
>                 _Str = _Str + 1) {
>             }
>             hWnd = (HWND)_wtoi64(_Str);
>         }
>     }
> 
>     local_8b8.hInstance = param_1;
> 
>     if (bVar3) {
>         memset(local_858, 0, 0x850);
>         memcpy(&DAT_140005120, local_858, 0x850);
>         local_8b8.hIcon = (HICON)0x0;
>         local_8b8.hCursor = (HCURSOR)0x0;
>         local_8b8.hbrBackground = (HBRUSH)0x0;
>         local_8b8.lpszMenuName = (LPCWSTR)0x0;
>         local_8b8.lpfnWndProc = FUN_140001770;
>         DAT_140005138 = 1;
>         local_8b8.style = 0;
>         local_8b8._4_4_ = 0;
>         local_8b8.cbClsExtra = 0;
>         local_8b8.cbWndExtra = 0;
>         local_8b8.lpszClassName = (LPCWSTR)0x0;
>         DAT_140005120 = param_1;
>         local_8b8.hCursor = LoadCursorW((HINSTANCE)0x0, (LPCWSTR)0x7f00);
>         local_8b8.lpszClassName = L"kodoksvrWindow";
>         AVar5 = RegisterClassW(&local_8b8);
> 
>         if (AVar5 != 0) {
>             GetClientRect(hWnd, &local_868);
>             CreateWindowExW(
>                 0,
>                 L"kodoksvrWindow",
>                 L"Preview",
>                 0x50000000,
>                 0,
>                 0,
>                 local_868.right,
>                 local_868.bottom,
>                 hWnd,
>                 (HMENU)0x0,
>                 param_1,
>                 (LPVOID)0x0
>             );
> 
>             local_8b8.style = 0;
>             local_8b8._4_4_ = 0;
>             local_8b8.lpfnWndProc = (WNDPROC)0x0;
>             local_8b8.cbClsExtra = 0;
>             local_8b8.cbWndExtra = 0;
>             local_8b8.hInstance = (HINSTANCE)0x0;
>             local_8b8.hIcon = (HICON)0x0;
>             local_8b8.hCursor = (HCURSOR)0x0;
>             iVar6 = GetMessageW((LPMSG)&local_8b8, (HWND)0x0, 0, 0);
> 
>             while (iVar6 != 0) {
>                 TranslateMessage((MSG *)&local_8b8);
>                 DispatchMessageW((MSG *)&local_8b8);
>                 iVar6 = GetMessageW((LPMSG)&local_8b8, (HWND)0x0, 0, 0);
>             }
> 
>             pHVar7 = (HWND)(local_8b8._16_8_ & 0xffffffff);
>         }
>     }
>     else {
>         local_8b8.hIcon = (HICON)0x0;
>         local_8b8.hCursor = (HCURSOR)0x0;
>         local_8b8.hbrBackground = (HBRUSH)0x0;
>         local_8b8.lpszMenuName = (LPCWSTR)0x0;
>         local_8b8.lpfnWndProc = FUN_140001770;
>         DAT_140005138 = 0;
>         local_8b8.style = 0;
>         local_8b8._4_4_ = 0;
>         local_8b8.cbClsExtra = 0;
>         local_8b8.cbWndExtra = 0;
>         local_8b8.lpszClassName = (LPCWSTR)0x0;
>         DAT_140005120 = param_1;
>         local_8b8.hCursor = LoadCursorW((HINSTANCE)0x0, (LPCWSTR)0x7f00);
>         local_8b8.lpszClassName = L"kodoksvrWindow";
>         RegisterClassW(&local_8b8);
>         iVar6 = GetSystemMetrics(1);
>         nWidth = GetSystemMetrics(0);
>         CreateWindowExW(
>             8,
>             L"kodoksvrWindow",
>             L"Kodok",
>             0x90000000,
>             0,
>             0,
>             nWidth,
>             iVar6,
>             (HWND)0x0,
>             (HMENU)0x0,
>             param_1,
>             (LPVOID)0x0
>         );
> 
>         local_8b8.style = 0;
>         local_8b8._4_4_ = 0;
>         local_8b8.lpfnWndProc = (WNDPROC)0x0;
>         local_8b8.cbClsExtra = 0;
>         local_8b8.cbWndExtra = 0;
>         local_8b8.hInstance = (HINSTANCE)0x0;
>         local_8b8.hIcon = (HICON)0x0;
>         local_8b8.hCursor = (HCURSOR)0x0;
>         iVar6 = GetMessageW((LPMSG)&local_8b8, (HWND)0x0, 0, 0);
> 
>         while (iVar6 != 0) {
>             TranslateMessage((MSG *)&local_8b8);
>             DispatchMessageW((MSG *)&local_8b8);
>             iVar6 = GetMessageW((LPMSG)&local_8b8, (HWND)0x0, 0, 0);
>         }
> 
>         pHVar7 = (HWND)(local_8b8._16_8_ & 0xffffffff);
>     }
> 
>     return pHVar7;
> }
> ```

> [!note]- Reading `FUN_140001000`
> This function is the first place where the binary starts behaving like a real GUI application rather than CRT startup code.
>
> The overall job of this function is to:
>
> - parse the command-line mode
> - register the window class
> - create the screensaver window
> - enter the normal Windows message loop
>
> So this is effectively the program's real **WinMain-like routine**.

> [!note]- Preview mode vs normal mode
> The first part of the function checks the command-line arguments in `param_3`.
>
> In particular, it looks for a `-p` / `/p` style argument, which is the normal Windows screensaver **preview mode**. If that mode is detected, `bVar3` is set and the program parses the preview window handle from the command line.
>
> This explains why the function has two branches:
>
> - **preview mode** → create a child preview window inside an existing parent window
> - **normal mode** → create the regular full-screen screensaver window
>
> This is standard screensaver behavior, not challenge-specific trickery.

> [!note]- The important line
> The most useful line in this function is the window procedure assignment:
>
> ```c
> local_8b8.lpfnWndProc = FUN_140001770;
> ```
>
> This tells us that `FUN_140001770` is the main **WndProc** for the screensaver window.
>
> Once that is known, the next step becomes clear: instead of spending too much time on the rest of the GUI boilerplate, we should inspect `FUN_140001770()` directly, because that is where the actual behavior of the window is implemented.

> [!note]- Why this function matters
> Even though most of `FUN_140001000()` is still standard GUI setup, it gives us two important facts:
>
> 1. this is a real screensaver-style GUI program  
> 2. the main application logic will be driven through `FUN_140001770`
>
> So this function acts as the bridge between startup code and the message-driven logic of the challenge.

> [!note]- Moving forward
> After identifying `FUN_140001770` as the window procedure, the next step is to inspect that function and follow the important message branches such as window creation and painting.

> [!note]- Full decompile: `FUN_140001770`
> ```c
> /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
> 
> LRESULT FUN_140001770(HWND param_1, uint param_2, WPARAM param_3, LPARAM param_4)
> {
>     int iVar1;
>     uint uVar2;
>     int iVar3;
>     int iVar4;
>     HDC hdc;
>     HDC hdc_00;
>     HBITMAP h;
>     HGDIOBJ h_00;
>     __time64_t _Var5;
>     LRESULT LVar6;
>     int *piVar7;
>     int iVar8;
>     tagRECT local_88[2];
>     tagPAINTSTRUCT local_68;
> 
>     if (param_2 < 0x101) {
>         if (param_2 != 0x100) {
>             if (param_2 == 1) {
>                 _DAT_140005128 = param_1;
>                 FUN_140001340(param_1, L"KEEP CALM AND PWN PETIR REGEN 2026",
>                               (wchar_t *)&DAT_14000513a, (DWORD)param_4);
>                 DAT_14000533c = FUN_140001410(L"Theme", 0);
>                 _DAT_140005340 = FUN_140001410(L"Bounce", 4);
>                 DAT_140005348 = LoadImageW(DAT_140005120, (LPCWSTR)0xc9, 0, 0, 0, 0x2000);
>                 DAT_140005350 = LoadImageW(DAT_140005120, (LPCWSTR)0xca, 0, 0, 0, 0x2000);
>                 DAT_140005358 = LoadImageW(DAT_140005120, (LPCWSTR)0xcb, 0, 0, 0, 0x2000);
>                 if (DAT_140005348 != (HANDLE)0x0) {
>                     GetObjectW(DAT_140005348, 0x20, local_88);
>                     DAT_140005360 = local_88[0].top;
>                     DAT_140005364 = local_88[0].right;
>                 }
>                 GetClientRect(param_1, local_88);
>                 _Var5 = _time64((__time64_t *)0x0);
>                 srand((uint)_Var5);
>                 DAT_140005968 = 0xf;
>                 piVar7 = &DAT_14000536c;
>                 iVar8 = 0;
>                 do {
>                     iVar3 = 1;
>                     if (DAT_140005360 < local_88[0].right) {
>                         iVar3 = local_88[0].right - DAT_140005360;
>                     }
>                     iVar1 = rand();
>                     piVar7[-1] = iVar1 % iVar3;
>                     iVar3 = 1;
>                     if (DAT_140005364 < local_88[0].bottom) {
>                         iVar3 = local_88[0].bottom - DAT_140005364;
>                     }
>                     iVar1 = rand();
>                     *piVar7 = iVar1 % iVar3;
>                     uVar2 = rand();
>                     iVar3 = rand();
>                     piVar7[1] = (iVar3 % 5 + 2) * ((uVar2 & 1) * 2 + -1);
>                     uVar2 = rand();
>                     iVar3 = rand();
>                     piVar7[2] = (iVar3 % 5 + 2) * ((uVar2 & 1) * 2 + -1);
>                     uVar2 = rand();
>                     uVar2 = uVar2 & 0x80000001;
>                     if ((int)uVar2 < 0) {
>                         uVar2 = (uVar2 - 1 | 0xfffffffe) + 1;
>                     }
>                     piVar7[3] = uVar2;
>                     iVar8 = iVar8 + 1;
>                     piVar7[4] = 0;
>                     piVar7 = piVar7 + 6;
>                 } while (iVar8 < DAT_140005968);
>                 SetTimer(param_1, 1, 0x21, (TIMERPROC)0x0);
>                 return 0;
>             }
>             if (param_2 == 2) {
>                 KillTimer(param_1, 1);
>                 if (DAT_140005348 != (HGDIOBJ)0x0) {
>                     DeleteObject(DAT_140005348);
>                 }
>                 if (DAT_140005350 != (HGDIOBJ)0x0) {
>                     DeleteObject(DAT_140005350);
>                 }
>                 if (DAT_140005358 != (HGDIOBJ)0x0) {
>                     DeleteObject(DAT_140005358);
>                 }
>                 DAT_140005358 = (HGDIOBJ)0x0;
>                 DAT_140005350 = (HGDIOBJ)0x0;
>                 DAT_140005348 = (HGDIOBJ)0x0;
>                 if (DAT_140005138 != '\0') {
>                     DAT_140005348 = (HGDIOBJ)0x0;
>                     DAT_140005350 = (HGDIOBJ)0x0;
>                     DAT_140005358 = (HGDIOBJ)0x0;
>                     return 0;
>                 }
>                 PostQuitMessage(0);
>                 return 0;
>             }
>             if (param_2 == 0xf) {
>                 local_68.hdc = (HDC)0x0;
>                 local_68.fErase = 0;
>                 local_68.rcPaint.left = 0;
>                 local_68.rcPaint.top = 0;
>                 local_68.rcPaint.right = 0;
>                 local_68.rcPaint.bottom = 0;
>                 local_68.fRestore = 0;
>                 local_68.rgbReserved[0x1c] = '\0';
>                 local_68.rgbReserved[0x1d] = '\0';
>                 local_68.rgbReserved[0x1e] = '\0';
>                 local_68.rgbReserved[0x1f] = '\0';
>                 local_68._68_4_ = 0;
>                 local_68.fIncUpdate = 0;
>                 local_68.rgbReserved[0] = '\0';
>                 local_68.rgbReserved[1] = '\0';
>                 local_68.rgbReserved[2] = '\0';
>                 local_68.rgbReserved[3] = '\0';
>                 local_68.rgbReserved[4] = '\0';
>                 local_68.rgbReserved[5] = '\0';
>                 local_68.rgbReserved[6] = '\0';
>                 local_68.rgbReserved[7] = '\0';
>                 local_68.rgbReserved[8] = '\0';
>                 local_68.rgbReserved[9] = '\0';
>                 local_68.rgbReserved[10] = '\0';
>                 local_68.rgbReserved[0xb] = '\0';
>                 local_68.rgbReserved[0xc] = '\0';
>                 local_68.rgbReserved[0xd] = '\0';
>                 local_68.rgbReserved[0xe] = '\0';
>                 local_68.rgbReserved[0xf] = '\0';
>                 local_68.rgbReserved[0x10] = '\0';
>                 local_68.rgbReserved[0x11] = '\0';
>                 local_68.rgbReserved[0x12] = '\0';
>                 local_68.rgbReserved[0x13] = '\0';
>                 local_68.rgbReserved[0x14] = '\0';
>                 local_68.rgbReserved[0x15] = '\0';
>                 local_68.rgbReserved[0x16] = '\0';
>                 local_68.rgbReserved[0x17] = '\0';
>                 local_68.rgbReserved[0x18] = '\0';
>                 local_68.rgbReserved[0x19] = '\0';
>                 local_68.rgbReserved[0x1a] = '\0';
>                 local_68.rgbReserved[0x1b] = '\0';
>                 hdc = BeginPaint(param_1, &local_68);
>                 GetClientRect(param_1, local_88);
>                 hdc_00 = CreateCompatibleDC(hdc);
>                 h = CreateCompatibleBitmap(hdc, local_88[0].right, local_88[0].bottom);
>                 h_00 = SelectObject(hdc_00, h);
>                 FUN_1400014c0(param_1, hdc_00);
>                 BitBlt(hdc, 0, 0, local_88[0].right, local_88[0].bottom, hdc_00, 0, 0, 0xcc0020);
>                 SelectObject(hdc_00, h_00);
>                 DeleteObject(h);
>                 DeleteDC(hdc_00);
>                 EndPaint(param_1, &local_68);
>                 return 0;
>             }
> LAB_140001b5c:
>             LVar6 = DefWindowProcW(param_1, param_2, param_3, param_4);
>             return LVar6;
>         }
>     }
>     else {
>         if (param_2 == 0x113) {
>             if (param_3 != 1) {
>                 return 0;
>             }
>             GetClientRect(param_1, local_88);
>             iVar8 = 0;
>             if (0 < DAT_140005968) {
>                 piVar7 = &DAT_14000536c;
>                 do {
>                     iVar1 = piVar7[-1] + piVar7[1];
>                     iVar3 = *piVar7 + piVar7[2];
>                     piVar7[-1] = iVar1;
>                     *piVar7 = iVar3;
>                     if ((iVar1 < 1) || (local_88[0].right <= DAT_140005360 + iVar1)) {
>                         piVar7[1] = -piVar7[1];
>                         iVar4 = local_88[0].right - DAT_140005360;
>                         if (iVar1 < 1) {
>                             iVar4 = 0;
>                         }
>                         piVar7[-1] = iVar4;
>                     }
>                     if ((iVar3 < 1) || (local_88[0].bottom <= DAT_140005364 + iVar3)) {
>                         piVar7[2] = -piVar7[2];
>                         iVar1 = local_88[0].bottom - DAT_140005364;
>                         if (iVar3 < 1) {
>                             iVar1 = 0;
>                         }
>                         *piVar7 = iVar1;
>                     }
>                     piVar7[4] = piVar7[4] + 1;
>                     if (7 < piVar7[4]) {
>                         piVar7[3] = piVar7[3] ^ 1;
>                         piVar7[4] = 0;
>                     }
>                     iVar8 = iVar8 + 1;
>                     piVar7 = piVar7 + 6;
>                 } while (iVar8 < DAT_140005968);
>             }
>             InvalidateRect(param_1, (RECT *)0x0, 0);
>             return 0;
>         }
>         if (param_2 != 0x201) goto LAB_140001b5c;
>     }
>     if (DAT_140005138 == '\0') {
>         DestroyWindow(param_1);
>     }
>     return 0;
> }
> ```

> [!note]- Reading `FUN_140001770`
> This function confirms that `FUN_140001770` is a normal Windows message handler. Instead of doing everything in one straight-line flow, the program reacts to different window messages such as creation, painting, timer updates, and mouse clicks. :contentReference[oaicite:0]{index=0}
>
> That means the next job is not to read the function top-to-bottom as if it were a linear algorithm, but to identify which message branches actually matter for the challenge.

> [!note]- The important branches
> There are four branches worth caring about here:
>
> - `WM_CREATE` (`param_2 == 1`)
> - `WM_PAINT` (`param_2 == 0xf`)
> - `WM_TIMER` (`param_2 == 0x113`)
> - `WM_LBUTTONDOWN` (`param_2 == 0x201`)
>
> Everything else mostly falls back to `DefWindowProcW`, so those paths are not where the hidden validation logic lives. :contentReference[oaicite:1]{index=1}

> [!note]- `WM_CREATE`
> The `WM_CREATE` branch is the first truly useful one.
>
> This branch initializes most of the screensaver state:
>
> - stores the window handle
> - loads the caption through `FUN_140001340(...)`
> - reads configuration values such as `Theme` and `Bounce`
> - loads the frog images
> - seeds `rand()` with the current time
> - generates the initial positions and movement directions of the frogs
> - starts a timer with `SetTimer(...)`
>
> So this branch is basically the setup phase for the animation. It also gives us our first important lead: the caption string is explicitly prepared here through `FUN_140001340(...)`, which makes that helper worth inspecting next. :contentReference[oaicite:2]{index=2}

> [!note]- `WM_PAINT`
> The `WM_PAINT` branch is the next important one.
>
> Here the program performs its drawing using double buffering:
>
> - `BeginPaint(...)`
> - create a compatible DC and bitmap
> - call `FUN_1400014c0(param_1, hdc_00)`
> - copy the finished image back with `BitBlt(...)`
>
> This is important because `FUN_1400014c0(...)` is the actual render helper. Since GUI challenges often hide interesting logic inside rendering code, this function is going to be another major stop later on. :contentReference[oaicite:3]{index=3}

> [!note]- `WM_TIMER`
> The `WM_TIMER` branch updates the frog positions on every timer tick.
>
> It adds the movement deltas to each frog position, bounces them off the window edges, flips animation state periodically, and then calls:
>
> ```c
> InvalidateRect(param_1, (RECT *)0x0, 0);
> ```
>
> That forces the window to repaint, which means the animation loop is basically:
>
> - timer fires
> - frog positions update
> - repaint requested
> - `WM_PAINT` runs
>
> This branch is useful for understanding the screensaver behavior, but it still looks like animation logic rather than flag logic. :contentReference[oaicite:4]{index=4}

> [!note]- `WM_LBUTTONDOWN`
> The mouse-click branch is simple:
>
> ```c
> if (DAT_140005138 == '\0') {
>     DestroyWindow(param_1);
> }
> ```
>
> So in normal mode, clicking closes the screensaver window. That is standard screensaver behavior and not part of the checker.

> [!note]- Why this function matters
> At this stage, `FUN_140001770()` gives us the high-level structure of the program:
>
> - `WM_CREATE` prepares the caption and animation state
> - `WM_TIMER` drives frog movement
> - `WM_PAINT` performs the actual rendering
>
> This is enough to decide the next analysis path.
>
> Since the caption is first introduced in `WM_CREATE`, the most natural next step is to inspect:
>
> ```c
> FUN_140001340(...)
> ```
>
> That should tell us exactly how the displayed text is loaded and whether it is only cosmetic or actually important to the challenge.

> [!note]- Moving forward
> So the next function to inspect is `FUN_140001340()`, because `WM_CREATE` shows that it is responsible for preparing the caption string that later gets rendered on screen.

> [!note]- Full decompile: `FUN_140001340`
> ```c
> void FUN_140001340(undefined8 param_1, wchar_t *param_2, wchar_t *param_3, DWORD param_4)
> {
>     LSTATUS LVar1;
>     undefined8 local_res8;
>     DWORD local_res20[2];
>     HKEY local_18[2];
> 
>     local_res8 = param_1;
>     local_res20[0] = param_4;
>     LVar1 = RegOpenKeyExW(
>         (HKEY)0xffffffff80000001,
>         L"Software\\kodoksvr",
>         0,
>         0x20019,
>         local_18
>     );
> 
>     if (LVar1 != 0) {
>         wcscpy_s(param_3, 0x100, param_2);
>         return;
>     }
> 
>     local_res8 = CONCAT44(local_res8._4_4_, 1);
>     local_res20[0] = 0x200;
>     LVar1 = RegQueryValueExW(
>         local_18[0],
>         L"Caption",
>         (LPDWORD)0x0,
>         (LPDWORD)&local_res8,
>         (LPBYTE)param_3,
>         local_res20
>     );
> 
>     if (LVar1 != 0) {
>         wcscpy_s(param_3, 0x100, param_2);
>     }
> 
>     RegCloseKey(local_18[0]);
>     return;
> }
> ```

> [!note]- Reading `FUN_140001340`
> This helper is much simpler than it first looks.
>
> Its job is just to prepare the caption string that will later be drawn on screen.
>
> The function first tries to open the registry key:
>
> ```text
> Software\kodoksvr
> ```
>
> If that fails, it copies the default caption from `param_2` into `param_3`:
>
> ```c
> wcscpy_s(param_3, 0x100, param_2);
> ```
>
> So the fallback behavior is simply: use the hardcoded default text.

> [!note]- Registry-backed caption
> If the registry key exists, the function then tries to read the value:
>
> ```text
> Caption
> ```
>
> into the destination buffer `param_3`.
>
> If that registry read also fails, it again falls back to the default caption:
>
> ```c
> wcscpy_s(param_3, 0x100, param_2);
> ```
>
> So in both failure cases, the program keeps using the built-in string passed by the caller.

> [!note]- Why this matters
> Going back to the `WM_CREATE` branch, this function was called as:
>
> ```c
> FUN_140001340(
>     param_1,
>     L"KEEP CALM AND PWN PETIR REGEN 2026",
>     (wchar_t *)&DAT_14000513a,
>     (DWORD)param_4
> );
> ```
>
> That means the default caption stored by the program is:
>
> ```text
> KEEP CALM AND PWN PETIR REGEN 2026
> ```
>
> and the resolved result is written into `DAT_14000513a`, which is the buffer later used for rendering.
>
> At this point, this function still does not look like the checker. It is just a loader for the text that will be displayed.
>
> But it does confirm one important thing: the caption is deliberately stored in a reusable buffer, which makes it more interesting than random cosmetic text.

> [!note]- What we learn from this
> This function gives us two useful conclusions:
>
> 1. the program has a default caption string built into the binary  
> 2. that caption is copied into a dedicated buffer and reused later
>
> So even though `FUN_140001340()` itself is not the flag checker, it tells us that the displayed caption is part of the program state and may later become input to something more interesting.

> [!note]- Moving forward
> After understanding how the caption is loaded, the next natural place to inspect is the render path reached from `WM_PAINT`, namely:
>
> ```c
> FUN_1400014c0(param_1, hdc_00);
> ```
>
> That function is responsible for drawing the frogs and the caption, and it is the most likely place where a hidden check would be triggered during rendering.

> [!note]- Full decompile: `FUN_1400014c0`
> ```c
> void FUN_1400014c0(HWND param_1, HDC param_2)
> {
>     int yoriginDest;
>     int xoriginDest;
>     int iVar1;
>     HBRUSH hbr;
>     HDC hdc;
>     HGDIOBJ h;
>     HFONT h_00;
>     HGDIOBJ pvVar2;
>     ulonglong uVar3;
>     int *piVar4;
>     COLORREF CVar5;
>     int iVar6;
>     tagRECT local_58;
>     tagRECT local_48;
>     undefined8 local_38;
>     undefined8 uStack_30;
> 
>     GetClientRect(param_1, &local_58);
>     iVar6 = 0;
>     CVar5 = 0;
> 
>     if (DAT_14000533c == 1) {
>         CVar5 = 0xa1e0a;
>     }
>     else if (DAT_14000533c == 2) {
>         CVar5 = 0x280a0a;
>     }
> 
>     hbr = CreateSolidBrush(CVar5);
>     FillRect(param_2, &local_58, hbr);
>     DeleteObject(hbr);
> 
>     if (0 < DAT_140005968) {
>         piVar4 = &DAT_14000536c;
>         iVar1 = DAT_140005968;
>         do {
>             pvVar2 = DAT_140005350;
>             if (piVar4[3] == 0) {
>                 pvVar2 = DAT_140005348;
>             }
> 
>             yoriginDest = *piVar4;
>             xoriginDest = piVar4[-1];
> 
>             if (pvVar2 != (HGDIOBJ)0x0) {
>                 hdc = CreateCompatibleDC(param_2);
>                 h = SelectObject(hdc, pvVar2);
>                 local_48.left = 0;
>                 local_48.top = 0;
>                 local_48.right = 0;
>                 local_48.bottom = 0;
>                 local_38 = 0;
>                 uStack_30 = 0;
>                 GetObjectW(pvVar2, 0x20, &local_48);
>                 TransparentBlt(
>                     param_2,
>                     xoriginDest,
>                     yoriginDest,
>                     DAT_140005360,
>                     DAT_140005364,
>                     hdc,
>                     0,
>                     0,
>                     local_48.top,
>                     local_48.right,
>                     0xffffff
>                 );
>                 SelectObject(hdc, h);
>                 DeleteDC(hdc);
>                 iVar1 = DAT_140005968;
>             }
> 
>             iVar6 = iVar6 + 1;
>             piVar4 = piVar4 + 6;
>         } while (iVar6 < iVar1);
>     }
> 
>     iVar6 = 0x28;
>     if (DAT_140005138 != '\0') {
>         iVar6 = 0x14;
>     }
> 
>     h_00 = CreateFontW(iVar6, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0x20, L"Arial");
>     pvVar2 = SelectObject(param_2, h_00);
>     uVar3 = FUN_140001c80();
>     if ((char)uVar3 != '\0') {
>         DAT_140005139 = '\x01';
>     }
> 
>     SetBkMode(param_2, 1);
>     CVar5 = 0xb4ffb4;
>     if (DAT_140005139 != '\0') {
>         CVar5 = 0x50dcff;
>     }
>     SetTextColor(param_2, CVar5);
>     DrawTextW(param_2, (LPCWSTR)&DAT_14000513a, -1, &local_48, 0x25);
>     SelectObject(param_2, pvVar2);
>     DeleteObject(h_00);
>     return;
> }
> ```

> [!note]- Reading `FUN_1400014c0`
> This function is the main render helper used by the `WM_PAINT` branch.
>
> Its overall job is straightforward:
>
> - clear the background
> - draw the frogs
> - prepare the font
> - draw the caption text
>
> So at first glance, this still looks like ordinary rendering code.

> [!note]- Background and frog rendering
> The first half of the function is purely visual.
>
> It gets the client rectangle, selects a background color depending on the configured theme, fills the window, and then loops over all frog objects stored in the global animation state.
>
> For each frog, it selects one of the loaded bitmaps and draws it with `TransparentBlt(...)`.
>
> This part explains the moving frog animation, but it does not yet look related to the flag.

> [!note]- The important line
> The key moment happens here:
>
> ```c
> uVar3 = FUN_140001c80();
> if ((char)uVar3 != '\0') {
>     DAT_140005139 = '\x01';
> }
> ```
>
> This is the first place where the hidden checker becomes visible.
>
> Right before the caption is drawn, the program calls `FUN_140001c80()`.
>
> If that function returns true, it flips `DAT_140005139` to `1`.

> [!note]- Why this matters
> This changes how we should read the whole challenge.
>
> The checker is not triggered by a button, a menu option, or any explicit user input.
>
> Instead, it is triggered during rendering.
>
> In other words, every time the screensaver repaints, the binary runs `FUN_140001c80()` and uses the result to modify the visual state of the text.

> [!note]- Visual effect of the checker
> After the checker call, the function selects the text color:
>
> ```c
> CVar5 = 0xb4ffb4;
> if (DAT_140005139 != '\0') {
>     CVar5 = 0x50dcff;
> }
> ```
>
> So the caption is normally drawn in one color, but if `FUN_140001c80()` succeeds, the color changes.
>
> That means the checker result is directly tied to the visible rendering output.

> [!note]- The caption is reused here
> The text drawn on screen is:
>
> ```c
> DrawTextW(param_2, (LPCWSTR)&DAT_14000513a, -1, &local_48, 0x25);
> ```
>
> This is the same caption buffer that was prepared earlier by `FUN_140001340()`.
>
> So the flow is now very clear:
>
> - `WM_CREATE` loads the caption into `DAT_14000513a`
> - `WM_PAINT` enters `FUN_1400014c0()`
> - `FUN_1400014c0()` calls `FUN_140001c80()`
> - the result changes how the caption is rendered
>
> At this point, `FUN_140001c80()` is no longer just suspicious — it is clearly the real checker function.

> [!note]- Moving forward
> After reaching this point, the next function to inspect is definitely:
>
> ```c
> FUN_140001c80()
> ```
>
> That function should contain the actual validation logic that transforms the caption and compares it against the hidden target data.

> [!note]- Full decompile: `FUN_140001c80`
> ```c
> ulonglong FUN_140001c80(void)
> {
>     wchar_t wVar1;
>     int iVar2;
>     undefined4 extraout_var;
>     ulonglong uVar3;
>     undefined4 extraout_var_00;
>     char cVar4;
>     wchar_t *pwVar5;
>     char *pcVar6;
>     ulonglong uVar7;
>     longlong lVar8;
>     ulonglong uVar9;
>     char local_a8[62];
>     undefined1 local_6a;
>     char local_68[32];
>     byte local_48[32];
>     byte local_28[32];
> 
>     iVar2 = lstrlenW(L"KEEP CALM AND PWN PETIR REGEN 2026");
>     uVar3 = CONCAT44(extraout_var, iVar2);
>     if (iVar2 == 0x1e) {
>         pwVar5 = L"REGEN 2026";
>         uVar7 = 0;
>         builtin_strncpy(local_a8 + 0x20, "KEEP CALM AND PWN PETIR ", 0x18);
>         lVar8 = 6;
>         _DAT_140005970 = 0x6bfb5bd3e3f16304;
>         _DAT_140005978 = 0x8b537304d2c9ab4b;
>         _DAT_140005988 = 0xfa9a7233;
>         _DAT_140005980 = 0x73f1d3b37b0cdad1;
>         _DAT_14000598c = 0x7ad2;
>         uVar3 = uVar7;
>         do {
>             wVar1 = *pwVar5;
>             pwVar5 = pwVar5 + 1;
>             local_a8[uVar3 + 0x38] = (char)wVar1;
>             uVar3 = uVar3 + 1;
>             lVar8 = lVar8 + -1;
>         } while (lVar8 != 0);
>         local_6a = 0;
> 
>         // zeroing buffers omitted here for brevity
> 
>         uVar9 = 0xffffffffffffffff;
>         do {
>             uVar3 = uVar9 + 1;
>             lVar8 = uVar9 + 0x21;
>             uVar9 = uVar3;
>         } while (local_a8[lVar8] != '\0');
> 
>         if (uVar3 == 0x1e) {
>             // more buffer initialization omitted here
> 
>             uVar9 = uVar7;
>             while (true) {
>                 cVar4 = 'a';
>                 uVar3 = uVar7;
>                 while (cVar4 != local_a8[uVar9 + 0x20]) {
>                     cVar4 =
>                         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"[uVar3 + 1];
>                     uVar3 = uVar3 + 1;
>                     if (cVar4 == '\0') goto LAB_140001e24;
>                 }
> 
>                 if ((longlong)uVar3 < 0) break;
> 
>                 local_a8[uVar9] =
>                     "mnbvcxzlkjhgfdsapoiuytrewqQWERTYUIOPASDFGHJKLZXCVBNM9876543210_}{"[uVar3];
>                 uVar9 = uVar9 + 1;
> 
>                 if (0x1d < uVar9) {
>                     pcVar6 = local_a8 + 0x1d;
>                     uVar3 = uVar7;
>                     do {
>                         cVar4 = *pcVar6;
>                         pcVar6 = pcVar6 + -1;
>                         local_68[uVar3] = cVar4;
>                         uVar3 = uVar3 + 1;
>                         uVar9 = uVar7;
>                     } while (uVar3 < 0x1e);
> 
>                     do {
>                         local_48[uVar9] =
>                             local_68[uVar9] + (char)(uVar9 / 5) * -5 + '\x03' + (char)uVar9;
>                         uVar9 = uVar9 + 1;
>                     } while (uVar9 < 0x1e);
> 
>                     do {
>                         local_28[uVar7] = local_48[uVar7] >> 5 | local_48[uVar7] << 3;
>                         uVar7 = uVar7 + 1;
>                     } while (uVar7 < 0x1e);
> 
>                     iVar2 = memcmp(local_28, &DAT_140005970, 0x1e);
>                     return CONCAT71((int7)(CONCAT44(extraout_var_00, iVar2) >> 8), iVar2 == 0);
>                 }
>             }
>         }
>     }
> LAB_140001e24:
>     return uVar3 & 0xffffffffffffff00;
> }
> ```

> [!note]- First reading of the checker
> Once we reach `FUN_140001c80()`, the structure of the challenge becomes much clearer.
>
> This function is not reading user input at all. Instead, it rebuilds the same caption we saw earlier, transforms it several times, and compares the final result against hardcoded bytes embedded in the binary.
>
> So from this point on, the task is no longer “find hidden input,” but rather:
>
> - understand the input being used
> - identify each transformation
> - reverse them to recover the original hidden string

> [!note]- Reconstructing the input
> The checker starts by validating the length of:
>
> ```c
> lstrlenW(L"KEEP CALM AND PWN PETIR REGEN 2026");
> ```
>
> and expects:
>
> ```c
> 0x1e
> ```
>
> which is **30 characters**.
>
> It then rebuilds the string in two parts:
>
> ```c
> builtin_strncpy(local_a8 + 0x20, "KEEP CALM AND PWN PETIR ", 0x18);
> ```
>
> followed by copying:
>
> ```c
> L"REGEN 2026"
> ```
>
> into the remaining bytes.
>
> So the exact input processed by the checker is:
>
> ```text
> KEEP CALM AND PWN PETIR REGEN 2026
> ```

> [!note]- Hardcoded comparison data
> Right after rebuilding the input, the function initializes the target bytes:
>
> ```c
> _DAT_140005970 = 0x6bfb5bd3e3f16304;
> _DAT_140005978 = 0x8b537304d2c9ab4b;
> _DAT_140005980 = 0x73f1d3b37b0cdad1;
> _DAT_140005988 = 0xfa9a7233;
> _DAT_14000598c = 0x7ad2;
> ```
>
> At the very end, the transformed buffer is checked with:
>
> ```c
> memcmp(local_28, &DAT_140005970, 0x1e);
> ```
>
> So the goal of the checker is simply to transform the caption into a 30-byte sequence that matches these embedded values exactly.

> [!note]- Transformation 1: substitution
> The first transformation is a lookup-table substitution.
>
> For each character of the caption, the checker searches in:
>
> ```text
> abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_
> ```
>
> and replaces it with the character at the same index from:
>
> ```text
> mnbvcxzlkjhgfdsapoiuytrewqQWERTYUIOPASDFGHJKLZXCVBNM9876543210_}{
> ```
>
> Decompiled core:
>
> ```c
> while (cVar4 != local_a8[uVar9 + 0x20]) {
>     cVar4 =
>         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"[uVar3 + 1];
>     uVar3 = uVar3 + 1;
>     if (cVar4 == '\0') goto LAB_140001e24;
> }
>
> local_a8[uVar9] =
>     "mnbvcxzlkjhgfdsapoiuytrewqQWERTYUIOPASDFGHJKLZXCVBNM9876543210_}{"[uVar3];
> ```
>
> So the first layer is just a fixed substitution cipher.

> [!note]- Transformation 2: reverse
> After substitution, the checker reverses the resulting 30-byte array:
>
> ```c
> pcVar6 = local_a8 + 0x1d;
> uVar3 = uVar7;
> do {
>     cVar4 = *pcVar6;
>     pcVar6 = pcVar6 + -1;
>     local_68[uVar3] = cVar4;
>     uVar3 = uVar3 + 1;
>     uVar9 = uVar7;
> } while (uVar3 < 0x1e);
> ```
>
> So the byte order is completely flipped before the next stage.

> [!note]- Transformation 3: add per position
> Next, each reversed byte is modified with:
>
> ```c
> local_48[uVar9] =
>     local_68[uVar9] + (char)(uVar9 / 5) * -5 + '\x03' + (char)uVar9;
> ```
>
> This looks messy in decompiled form, but:
>
> ```c
> (uVar9 / 5) * -5 + uVar9
> ```
>
> is just:
>
> ```c
> uVar9 % 5
> ```
>
> So the real logic is:
>
> ```c
> local_48[i] = local_68[i] + 3 + (i % 5);
> ```
>
> That means each byte gets a base offset of `+3` plus a repeating position-based offset.

> [!note]- Transformation 4: rotate-left by 3
> The final stage is:
>
> ```c
> local_28[uVar7] = local_48[uVar7] >> 5 | local_48[uVar7] << 3;
> ```
>
> This is an 8-bit **rotate-left by 3**.
>
> So instead of losing bits, the byte is rotated in a circle before the final comparison.

> [!note]- Why this function is the real checker
> At this point, everything lines up cleanly:
>
> - the caption is loaded earlier during `WM_CREATE`
> - the render path calls `FUN_140001c80()`
> - `FUN_140001c80()` rebuilds that caption internally
> - it applies several transformations
> - it compares the result against embedded target bytes
>
> So this is unquestionably the core validation routine of the challenge.

> [!note]- Moving toward the solver
> Once the transformation chain is identified, the solve strategy becomes straightforward.
>
> The checker applies its logic in this order:
>
> 1. substitution  
> 2. reverse  
> 3. add `3 + (i % 5)`  
> 4. rotate-left by 3
>
> So the solver simply has to undo them in reverse:
>
> 1. rotate-right by 3  
> 2. subtract `3 + (i % 5)`  
> 3. undo the reverse  
> 4. apply the inverse substitution mapping
>
> That is enough to recover the original hidden string directly from the hardcoded target bytes.

## Solver

> [!note]- Reversing the checker
> After understanding `FUN_140001c80()`, the solve path becomes very direct.
>
> The checker applies the following transformations in order:
>
> 1. substitution  
> 2. reverse  
> 3. add `3 + (i % 5)`  
> 4. rotate-left by 3
>
> So to recover the original hidden string, we simply undo those steps in reverse order:
>
> 1. rotate-right by 3  
> 2. subtract `3 + (i % 5)`  
> 3. undo the reverse  
> 4. apply the inverse substitution mapping
>
> Since the final comparison target is hardcoded in the binary, there is no need for brute force at all. We can start directly from those bytes and walk backward through the inverse transformations.

> [!note]- Python solver
> ```python
> import struct
> 
> # Rebuild the target bytes exactly as stored in the binary
> target_raw = b""
> target_raw += struct.pack("<Q", 0x6bfb5bd3e3f16304)
> target_raw += struct.pack("<Q", 0x8b537304d2c9ab4b)
> target_raw += struct.pack("<Q", 0x73f1d3b37b0cdad1)
> target_raw += struct.pack("<I", 0xfa9a7233)
> target_raw += struct.pack("<H", 0x7ad2)
> target = list(target_raw[:0x1e])
> 
> # Step 1: undo rotate-left-3 with rotate-right-3
> local_48 = [((v << 5) | (v >> 3)) & 0xff for v in target]
> 
> # Step 2: undo the position-based addition
> local_68 = [(local_48[i] - 3 - (i % 5)) & 0xff for i in range(0x1e)]
> 
> # Step 3: undo the reverse
> local_a8_sub = [local_68[0x1d - i] for i in range(0x1e)]
> 
> # Step 4: undo the substitution using the inverse mapping
> src = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"
> dst = "mnbvcxzlkjhgfdsapoiuytrewqQWERTYUIOPASDFGHJKLZXCVBNM9876543210_}{"
> inv = {ord(d): s for d, s in zip(dst, src)}
> 
> flag = "".join(inv.get(b, "?") for b in local_a8_sub)
> print(flag)
> ```
>
> Running the script gives:
>
> ```text
> PETIR{k0dok_W3bek_W3bek_kod0k}
> ```

> [!note]- Why the solver works
> The important thing here is that the solver is not guessing the flag.
>
> It directly mirrors the checker logic in reverse:
>
> - the binary gives us the final target bytes
> - we undo the bit rotation
> - we undo the addition
> - we undo the reverse
> - we undo the substitution
>
> So this is a clean reconstruction of the original hidden string from the checker itself.

## Flag

![[Pasted image 20260407100147.png]]


