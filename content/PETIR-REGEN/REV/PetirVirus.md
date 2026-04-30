![[Pasted image 20260407100849.png]]

## Recon

![[Pasted image 20260407101023.png]]

> [!note]- Identifying the file type
> I started by checking what kind of file was provided:
>
> ```bash
> file petir-antivirus.crx
> ```
>
> Output:
>
> ```text
> petir-antivirus.crx: Google Chrome extension, version 3
> ```
>
> This immediately tells us that the challenge is packaged as a **Chrome extension** rather than a native executable.
>
> So instead of opening it in a disassembler right away, the first step is to extract the extension contents and inspect its web assets.

> [!note]- Extracting the extension
> Since a `.crx` file is essentially a packaged Chrome extension, I first copied it to a `.zip` file and then extracted it with `unzip`:
>
> ```bash
> cp petir-antivirus.crx petir-antivirus.zip
> unzip petir-antivirus.zip
> ```
>
> During extraction, `unzip` printed:
>
> ```text
> warning [petir-antivirus.zip]: 593 extra bytes at beginning or within zipfile
> (attempting to process anyway)
> ```
>
> This warning is expected here.
>
> A `.crx` file is not a plain ZIP from byte 0 — it contains a Chrome-specific header before the actual ZIP payload. That is why `unzip` reports extra bytes at the beginning. However, it can still locate the embedded ZIP data and extract the files successfully.

> [!note]- Extracted files
> After extraction, the extension contents became visible:
>
> - `challenge.js`
> - `challenge.wasm`
> - `manifest.json`
> - `petir-logo.webp`
> - `popup.html`
> - `popup.js`
> - `README.md`
>
> At this stage, several files already look useful for analysis:
>
> - `manifest.json`, to understand how the extension is structured
> - `popup.html` and `popup.js`, to trace the user-facing flag check flow
> - `challenge.js` and `challenge.wasm`, since they likely contain the actual verification logic
> - `README.md`, because challenge authors sometimes leave hints, usage notes, or context there
>
> So instead of assuming the solution lives in only one place, the next step is to inspect these files and follow the validation flow from the extension UI into the underlying WebAssembly code.

## Inspecting the Extension Files

![[Pasted image 20260407101431.png]]

> [!note]- `README.md`
> I first checked the included `README.md` file:
>
> ```text
> Because This is a baby challenge I won't do anything malicious in this extension.
> To test this please load this chrome extension to your browser.
> Good Luck Have Fun!
> ```
>
> This file does not reveal the flag or the verification logic directly.
>
> However, it is still useful as context:
>
> - it confirms that the extension is intended to be loaded normally in the browser
> - it suggests that the challenge is not about malicious browser behavior
> - it implies that the real task is to reverse the validation logic hidden inside the extension files
>
> So `README.md` is not the solution path by itself, but it helps frame the challenge properly.

> [!note]- `popup.js`
> The next file worth inspecting was `popup.js`, since this is usually where the user-facing logic lives in a Chrome extension.
>
> The script first keeps the submit button disabled until the WebAssembly module is loaded:
>
> ```javascript
> let wasmModule = null;
>
> const checkBtn = document.getElementById('check-btn');
> checkBtn.disabled = true;
> checkBtn.innerText = "Loading...";
> ```
>
> It then initializes the module through:
>
> ```javascript
> createWasmModule().then((instance) => {
>     wasmModule = instance;
>     checkBtn.disabled = false;
>     checkBtn.innerText = "Submit";
> });
> ```
>
> This already tells us something important: the actual verification logic is not implemented directly in plain JavaScript. Instead, the JavaScript waits for a WebAssembly-backed module to finish loading.

> [!note]- The important call in `popup.js`
> The most useful part appears inside the click handler:
>
> ```javascript
> const isCorrect = wasmModule.ccall(
>     'check_flag',
>     'boolean',
>     ['string', 'number'],
>     [input, input.length]
> );
> ```
>
> This is the key transition point in the challenge.
>
> The popup reads the user input, then calls an exported WebAssembly function named:
>
> ```text
> check_flag
> ```
>
> with:
>
> - the input string
> - the input length
>
> So from this point onward, it becomes clear that the real verification logic lives inside the WASM module rather than in `popup.js` itself.

> [!note]- Why `popup.js` matters
> Even though `popup.js` does not contain the checker implementation, it gives us the solve direction very clearly:
>
> - user input is collected in the popup
> - JavaScript forwards that input into WebAssembly
> - the exported function responsible for validation is `check_flag`
>
> That means the next important file is not the rest of the UI code, but the underlying module that provides `check_flag`.

> [!note]- `manifest.json`
> I also checked `manifest.json` to understand how the extension is structured:
>
> ```json
> {
>   "manifest_version": 3,
>   "name": "PETIR Antivirus",
>   "version": "1.0",
>   "action": {
>     "default_popup": "popup.html"
>   },
>   "content_security_policy": {
>     "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
>   }
> }
> ```
>
> This confirms that the extension uses `popup.html` as its main UI entry point.
>
> The interesting detail here is the content security policy:
>
> ```text
> 'wasm-unsafe-eval'
> ```
>
> That is a strong hint that WebAssembly is intentionally part of the challenge design.
>
> So `manifest.json` does not reveal the flag logic directly, but it supports what we already observed from `popup.js`: the extension is expected to load and execute a WASM module.

> [!note]- Conclusion from the frontend files
> After checking `README.md`, `popup.js`, and `manifest.json`, the analysis direction becomes much clearer.
>
> - `README.md` only provides context
> - `manifest.json` confirms the popup-based extension structure and allows WASM execution
> - `popup.js` shows the exact bridge from user input into the exported WASM function `check_flag`
>
> So the next step is to move away from the frontend files and start inspecting the WebAssembly module itself, since that is where the real checker lives.

## Disassembling the WebAssembly Module

> [!note]- Converting `.wasm` into a readable format
> Since `challenge.wasm` is a compiled WebAssembly binary, reading it directly with `cat` is not useful for real analysis.
>
> So the next step was to disassemble it into **WAT** (WebAssembly Text format):
>
> ```bash
> wasm2wat challenge.wasm -o challenge.wat
> ```
>
> After that, the directory contained a new readable file:
>
> - `challenge.wat`
>
> This gives us a text representation of the WebAssembly module, which is much easier to inspect than raw binary output. :contentReference[oaicite:0]{index=0}

## Challenge.wat

``` text
(module
  (type (;0;) (func (param i32 i32 i32) (result i32)))
  (type (;1;) (func (param i32 i64 i32) (result i64)))
  (type (;2;) (func))
  (type (;3;) (func (result i32)))
  (type (;4;) (func (param i32 i32) (result i32)))
  (type (;5;) (func (param i32)))
  (type (;6;) (func (param i32) (result i32)))
  (func (;0;) (type 2)
    call 8)
  (func (;1;) (type 3) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 0
    local.get 0
    i32.const 0
    i32.load offset=65748
    i32.const 0
    i32.shr_u
    i32.const 0
    i32.load offset=65748
    i32.const 2
    i32.shr_u
    i32.xor
    i32.const 0
    i32.load offset=65748
    i32.const 3
    i32.shr_u
    i32.xor
    i32.const 0
    i32.load offset=65748
    i32.const 5
    i32.shr_u
    i32.xor
    i32.const 1
    i32.and
    i32.store offset=12
    i32.const 0
    i32.load offset=65748
    i32.const 1
    i32.shr_u
    local.get 0
    i32.load offset=12
    i32.const 31
    i32.shl
    i32.or
    local.set 1
    i32.const 0
    local.get 1
    i32.store offset=65748
    i32.const 0
    i32.load offset=65748
    return)
  (func (;2;) (type 4) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    i32.const 240
    i32.sub
    local.set 2
    local.get 2
    global.set 0
    local.get 2
    local.get 0
    i32.store offset=232
    local.get 2
    local.get 1
    i32.store offset=228
    i32.const 65536
    local.set 3
    i32.const 211
    local.set 4
    local.get 2
    i32.const 16
    i32.add
    local.get 3
    local.get 4
    memory.copy
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=228
        i32.const 211
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 0
        i32.const 1
        i32.and
        i32.store8 offset=239
        br 1 (;@1;)
      end
      local.get 2
      i32.const 0
      i32.store offset=12
      block  ;; label = @2
        loop  ;; label = @3
          local.get 2
          i32.load offset=12
          local.get 2
          i32.load offset=228
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 2
          call 1
          i32.const 255
          i32.and
          i32.store8 offset=11
          local.get 2
          i32.load offset=232
          local.get 2
          i32.load offset=12
          i32.add
          i32.load8_s
          local.set 5
          i32.const 255
          drop
          local.get 5
          local.get 2
          i32.load8_u offset=11
          i32.xor
          i32.const 255
          i32.and
          local.set 6
          local.get 2
          i32.load offset=12
          local.get 2
          i32.const 16
          i32.add
          i32.add
          local.set 7
          i32.const 255
          drop
          block  ;; label = @4
            local.get 6
            local.get 7
            i32.load8_u
            i32.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 2
            i32.const 0
            i32.const 1
            i32.and
            i32.store8 offset=239
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=12
          i32.const 1
          i32.add
          i32.store offset=12
          br 0 (;@3;)
        end
      end
      local.get 2
      i32.const 1
      i32.const 1
      i32.and
      i32.store8 offset=239
    end
    local.get 2
    i32.load8_u offset=239
    i32.const 1
    i32.and
    local.set 8
    local.get 2
    i32.const 240
    i32.add
    global.set 0
    local.get 8
    return)
  (func (;3;) (type 5) (param i32))
  (func (;4;) (type 5) (param i32))
  (func (;5;) (type 3) (result i32)
    i32.const 65752
    call 3
    i32.const 65756)
  (func (;6;) (type 2)
    i32.const 65752
    call 4)
  (func (;7;) (type 6) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      i32.const 0
      local.set 1
      block  ;; label = @2
        i32.const 0
        i32.load offset=65760
        i32.eqz
        br_if 0 (;@2;)
        i32.const 0
        i32.load offset=65760
        call 7
        local.set 1
      end
      block  ;; label = @2
        i32.const 0
        i32.load offset=65760
        i32.eqz
        br_if 0 (;@2;)
        i32.const 0
        i32.load offset=65760
        call 7
        local.get 1
        i32.or
        local.set 1
      end
      block  ;; label = @2
        call 5
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        loop  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.load offset=20
            local.get 0
            i32.load offset=28
            i32.eq
            br_if 0 (;@4;)
            local.get 0
            call 7
            local.get 1
            i32.or
            local.set 1
          end
          local.get 0
          i32.load offset=56
          local.tee 0
          br_if 0 (;@3;)
        end
      end
      call 6
      local.get 1
      return
    end
    block  ;; label = @1
      local.get 0
      i32.load offset=20
      local.get 0
      i32.load offset=28
      i32.eq
      br_if 0 (;@1;)
      local.get 0
      i32.const 0
      i32.const 0
      local.get 0
      i32.load offset=36
      call_indirect (type 0)
      drop
      local.get 0
      i32.load offset=20
      br_if 0 (;@1;)
      i32.const -1
      return
    end
    block  ;; label = @1
      local.get 0
      i32.load offset=4
      local.tee 1
      local.get 0
      i32.load offset=8
      local.tee 2
      i32.eq
      br_if 0 (;@1;)
      local.get 0
      local.get 1
      local.get 2
      i32.sub
      i64.extend_i32_s
      i32.const 1
      local.get 0
      i32.load offset=40
      call_indirect (type 1)
      drop
    end
    local.get 0
    i32.const 0
    i32.store offset=28
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=4 align=4
    i32.const 0)
  (func (;8;) (type 2)
    i32.const 65536
    global.set 2
    i32.const 0
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    global.set 1)
  (func (;9;) (type 3) (result i32)
    global.get 0
    global.get 1
    i32.sub)
  (func (;10;) (type 3) (result i32)
    global.get 2)
  (func (;11;) (type 3) (result i32)
    global.get 1)
  (func (;12;) (type 5) (param i32)
    local.get 0
    global.set 0)
  (func (;13;) (type 6) (param i32) (result i32)
    (local i32 i32)
    global.get 0
    local.get 0
    i32.sub
    i32.const -16
    i32.and
    local.tee 1
    global.set 0
    local.get 1)
  (func (;14;) (type 3) (result i32)
    global.get 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 258 258)
  (global (;0;) (mut i32) (i32.const 65536))
  (global (;1;) (mut i32) (i32.const 0))
  (global (;2;) (mut i32) (i32.const 0))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func 0))
  (export "check_flag" (func 2))
  (export "__indirect_function_table" (table 0))
  (export "fflush" (func 7))
  (export "emscripten_stack_init" (func 8))
  (export "emscripten_stack_get_free" (func 9))
  (export "emscripten_stack_get_base" (func 10))
  (export "emscripten_stack_get_end" (func 11))
  (export "_emscripten_stack_restore" (func 12))
  (export "_emscripten_stack_alloc" (func 13))
  (export "emscripten_stack_get_current" (func 14))
  (data (;0;) (i32.const 65536) "wV\dd\8d0J\cc$\cf \f6=YJ\eb\1aVd|\eb0H\f1$\fb\a6\86+\d7\bc\05\d2\04L\c9\a9\8a\1f[\c3(\ce\a1\9a\80%J{\d0)F\f4,{\e6\a6\bb\02K\f9>\c6\a1\8c+N\f5\ab\b8\1aW{|\e2'H\f5\a6\10AFE\f2\9c\02_\f6\bf\8f\00M\ef\11\c85\f6:Ca\f8,A\ce)\c7;M\cb\b9\10\de\bf\19Dr\ee\19B\f2\a1\80\ad\1eP\e7,\c2\a1\80\1ae\ee\a1\83\9a\8c\11\e1=F\f4\aa\17\d0\b6\02\d7\af\88)\f7\b4\9a\9a\0eN\c1?\c6#\cc\a6\b5\96\15Ij\e0\a9<\d6-Bfd\f2\a6\84\82\a7=P\fb\90\93\9b\9c#\ce-@t\ee!Wc\ed\9b\8b\02g}}\d8%\ce\bc\84\9b\8d\00")
  (data (;1;) (i32.const 65748) "OLEH"))

```

## Reading the WAT Output

> [!note]- First overview of `challenge.wat`
> After disassembling `challenge.wasm` into `challenge.wat`, the binary becomes much easier to inspect.
>
> At a glance, the module already shows several important components:
>
> ```wat
> (module
>   (type (;0;) ...)
>   (type (;1;) ...)
>   (type (;2;) ...)
>   (type (;3;) (func (result i32)))
>   (type (;4;) (func (param i32 i32) (result i32)))
>   ...
>   (func (;1;) (type 3) (result i32)
>   ...
>   (func (;2;) (type 4) (param i32 i32) (result i32)
>   ...
>   (memory (;0;) 258 258)
>   ...
>   (export "check_flag" (func 2))
>   ...
>   (data (;0;) (i32.const 65536) ...)
>   (data (;1;) (i32.const 65748) "OLEH"))
> ```
>
> Even before analyzing any single function in detail, this already tells us that the module contains:
>
> - multiple internal functions
> - an exported checker function
> - linear memory
> - embedded data segments
>
> So from this point onward, the task becomes much more structured: identify which function performs the check, what helper functions it depends on, and what data is stored in memory. :contentReference[oaicite:0]{index=0}

> [!note]- Exported symbols
> One of the first useful parts to inspect in the WAT file is the export section:
>
> ```wat
> (export "memory" (memory 0))
> (export "__wasm_call_ctors" (func 0))
> (export "check_flag" (func 2))
> (export "__indirect_function_table" (table 0))
> (export "fflush" (func 7))
> (export "emscripten_stack_init" (func 8))
> (export "emscripten_stack_get_free" (func 9))
> (export "emscripten_stack_get_base" (func 10))
> (export "emscripten_stack_get_end" (func 11))
> (export "_emscripten_stack_restore" (func 12))
> (export "_emscripten_stack_alloc" (func 13))
> (export "emscripten_stack_get_current" (func 14))
> ```
>
> This section is important because it immediately answers one of the main questions from the frontend analysis.
>
> In `popup.js`, the extension calls:
>
> ```javascript
> wasmModule.ccall("check_flag", ...)
> ```
>
> and the export table now shows exactly where that goes:
>
> ```wat
> (export "check_flag" (func 2))
> ```
>
> So the real checker is implemented by internal WebAssembly function `func (;2;)`. That becomes the main target for analysis. :contentReference[oaicite:1]{index=1}

> [!note]- Internal functions visible in the module
> Another useful observation is that the module is small enough that the key functions stand out fairly quickly:
>
> ```wat
> (func (;0;) (type 2)
>   call 8)
>
> (func (;1;) (type 3) (result i32)
>   ...)
>
> (func (;2;) (type 4) (param i32 i32) (result i32)
>   ...)
> ```
>
> At a high level:
>
> - `func 0` is just a tiny startup/helper wrapper
> - `func 2` is the exported checker
> - `func 1` is a helper returning an `i32`, and it is likely important because `func 2` calls it during verification
>
> So even before reading the body in detail, the overall structure already suggests a checker function plus at least one helper function. :contentReference[oaicite:2]{index=2}

> [!note]- Embedded memory data
> The data section is another major clue:
>
> ```wat
> (data (;0;) (i32.const 65536) "...")
> (data (;1;) (i32.const 65748) "OLEH")
> ```
>
> This tells us that the module stores embedded bytes directly in linear memory.
>
> Two things immediately stand out here:
>
> - a large blob of static data begins at offset `65536`
> - another data segment stores the ASCII string `"OLEH"` at offset `65748`
>
> At this stage, we do not yet need to fully explain what each one means. It is enough to notice that the checker likely depends on both function logic **and** embedded memory data, rather than doing a simple hardcoded string comparison. :contentReference[oaicite:3]{index=3}

> [!note]- Memory and runtime structure
> The WAT file also shows that the module exports its own linear memory:
>
> ```wat
> (memory (;0;) 258 258)
> (global (;0;) (mut i32) (i32.const 65536))
> (global (;1;) (mut i32) (i32.const 0))
> (global (;2;) (mut i32) (i32.const 0))
> ```
>
> Together with the Emscripten-related exports, this strongly suggests that the module was produced through an Emscripten toolchain.
>
> That matches what we already suspected from the frontend files and from the visible runtime symbols. So the module is not handwritten minimal WASM, but a small compiled WebAssembly program with its own memory layout and runtime helpers. :contentReference[oaicite:4]{index=4}

> [!note]- What this overview tells us
> Without diving into instruction-by-instruction analysis yet, the WAT overview already gives us the main roadmap:
>
> - the frontend calls exported symbol `check_flag`
> - that export maps to internal `func 2`
> - `func 2` likely depends on helper `func 1`
> - the checker probably uses embedded memory data at offsets `65536` and `65748`
>
> So after this overview, the natural next step is to inspect `func 2` first and understand the high-level structure of the flag verification routine. :contentReference[oaicite:5]{index=5}

## Understanding `check_flag`

> [!note]- Full WAT: `func 2`
> ```wat
> (func (;2;) (type 4) (param i32 i32) (result i32)
>   (local i32 i32 i32 i32 i32 i32 i32)
>   global.get 0
>   i32.const 240
>   i32.sub
>   local.set 2
>   local.get 2
>   global.set 0
>   local.get 2
>   local.get 0
>   i32.store offset=232
>   local.get 2
>   local.get 1
>   i32.store offset=228
>   i32.const 65536
>   local.set 3
>   i32.const 211
>   local.set 4
>   local.get 2
>   i32.const 16
>   i32.add
>   local.get 3
>   local.get 4
>   memory.copy
>   block  ;; label = @1
>     block  ;; label = @2
>       local.get 2
>       i32.load offset=228
>       i32.const 211
>       i32.ne
>       i32.const 1
>       i32.and
>       i32.eqz
>       br_if 0 (;@2;)
>       local.get 2
>       i32.const 0
>       i32.const 1
>       i32.and
>       i32.store8 offset=239
>       br 1 (;@1;)
>     end
>     local.get 2
>     i32.const 0
>     i32.store offset=12
>     block  ;; label = @2
>       loop  ;; label = @3
>         local.get 2
>         i32.load offset=12
>         local.get 2
>         i32.load offset=228
>         i32.lt_s
>         i32.const 1
>         i32.and
>         i32.eqz
>         br_if 1 (;@2;)
>         local.get 2
>         call 1
>         i32.const 255
>         i32.and
>         i32.store8 offset=11
>         local.get 2
>         i32.load offset=232
>         local.get 2
>         i32.load offset=12
>         i32.add
>         i32.load8_s
>         local.set 5
>         i32.const 255
>         drop
>         local.get 5
>         local.get 2
>         i32.load8_u offset=11
>         i32.xor
>         i32.const 255
>         i32.and
>         local.set 6
>         local.get 2
>         i32.load offset=12
>         local.get 2
>         i32.const 16
>         i32.add
>         i32.add
>         local.set 7
>         i32.const 255
>         drop
>         block  ;; label = @4
>           local.get 6
>           local.get 7
>           i32.load8_u
>           i32.ne
>           i32.const 1
>           i32.and
>           i32.eqz
>           br_if 0 (;@4;)
>           local.get 2
>           i32.const 0
>           i32.const 1
>           i32.and
>           i32.store8 offset=239
>           br 3 (;@1;)
>         end
>         local.get 2
>         local.get 2
>         i32.load offset=12
>         i32.const 1
>         i32.add
>         i32.store offset=12
>         br 0 (;@3;)
>       end
>     end
>     local.get 2
>     i32.const 1
>     i32.const 1
>     i32.and
>     i32.store8 offset=239
>   end
>   local.get 2
>   i32.load8_u offset=239
>   i32.const 1
>   i32.and
>   local.set 8
>   local.get 2
>   i32.const 240
>   i32.add
>   global.set 0
>   local.get 8
>   return)
> ```

> [!note]- First look at `func 2`
> After locating:
>
> ```wat
> (export "check_flag" (func 2))
> ```
>
> the next step is to inspect `func (;2;)` itself.
>
> Even before decoding every instruction, the high-level structure is already visible:
>
> - store the two input parameters
> - copy a fixed block of embedded data from memory
> - check the input length
> - loop over the input byte by byte
> - use `call 1` during each iteration
> - return `0` or `1` depending on whether all bytes match
>
> So this already looks like a classic verification routine rather than a direct plaintext comparison.

> [!note]- Function parameters
> The function takes two parameters:
>
> ```wat
> (func (;2;) (type 4) (param i32 i32) (result i32)
> ```
>
> and stores them here:
>
> ```wat
> local.get 2
> local.get 0
> i32.store offset=232
> local.get 2
> local.get 1
> i32.store offset=228
> ```
>
> From the earlier JavaScript call:
>
> ```javascript
> wasmModule.ccall("check_flag", "boolean", ["string", "number"], [input, input.length])
> ```
>
> this matches the expected interface nicely:
>
> - `param 0` = pointer to the input string
> - `param 1` = input length
>
> So `func 2` receives both the flag candidate and its size from the popup logic.

> [!note]- Copying the embedded target buffer
> One of the first important operations is:
>
> ```wat
> i32.const 65536
> local.set 3
> i32.const 211
> local.set 4
> local.get 2
> i32.const 16
> i32.add
> local.get 3
> local.get 4
> memory.copy
> ```
>
> This copies `211` bytes from memory offset `65536` into a local working area on the stack frame.
>
> So the checker does not compare the input against a plain constant string in code. Instead, it first copies an embedded target buffer from linear memory and uses that as the reference during verification.

> [!note]- Length check
> The next important branch is:
>
> ```wat
> local.get 2
> i32.load offset=228
> i32.const 211
> i32.ne
> i32.const 1
> i32.and
> i32.eqz
> br_if 0 (;@2;)
> ```
>
> This is the fixed-length check.
>
> In simpler terms, the function only continues if:
>
> ```text
> input.length == 211
> ```
>
> If the length is different, it stores a failure value and exits early.
>
> So the first hard requirement is that the correct input must be exactly `211` bytes long.

> [!note]- Initializing the loop counter
> If the length check passes, the checker initializes an index variable:
>
> ```wat
> local.get 2
> i32.const 0
> i32.store offset=12
> ```
>
> Then it enters a loop:
>
> ```wat
> loop  ;; label = @3
>   local.get 2
>   i32.load offset=12
>   local.get 2
>   i32.load offset=228
>   i32.lt_s
>   ...
> ```
>
> This is just a standard byte-by-byte loop:
>
> ```text
> while (i < input_len)
> ```
>
> So from here on, each input byte is checked individually.

> [!note]- A helper function is used inside the loop
> Inside the loop, the first standout instruction is:
>
> ```wat
> local.get 2
> call 1
> i32.const 255
> i32.and
> i32.store8 offset=11
> ```
>
> This means `func 2` calls `func 1` once per iteration, keeps only the low byte of its return value, and stores that byte temporarily.
>
> At this stage, we do not need to fully analyze `func 1` yet. What matters first is that each character check depends on a helper-generated byte.

> [!note]- Reading the current input byte
> The current input byte is read here:
>
> ```wat
> local.get 2
> i32.load offset=232
> local.get 2
> i32.load offset=12
> i32.add
> i32.load8_s
> local.set 5
> ```
>
> This is effectively:
>
> ```text
> input_byte = input[i]
> ```
>
> So now the loop has:
>
> - the current input byte
> - one byte returned indirectly through `call 1`

> [!note]- Per-byte transformation
> The next block is the most important one in `func 2`:
>
> ```wat
> local.get 5
> local.get 2
> i32.load8_u offset=11
> i32.xor
> i32.const 255
> i32.and
> local.set 6
> ```
>
> This means the checker transforms each input byte as:
>
> ```text
> transformed = input[i] XOR helper_byte
> ```
>
> So the verification is not comparing the raw input directly. Instead, it XORs each input byte with a generated byte and only then compares the result.

> [!note]- Comparing against the copied target data
> After that, the checker computes the address of the corresponding target byte:
>
> ```wat
> local.get 2
> i32.load offset=12
> local.get 2
> i32.const 16
> i32.add
> i32.add
> local.set 7
> ```
>
> and then performs the comparison:
>
> ```wat
> local.get 6
> local.get 7
> i32.load8_u
> i32.ne
> ```
>
> So the real per-byte condition is:
>
> ```text
> (input[i] XOR helper_byte) == target[i]
> ```
>
> If any byte mismatches, the function stores failure and exits immediately.

> [!note]- Success and failure behavior
> The checker uses a byte at offset `239` as its final boolean result.
>
> On mismatch, it stores:
>
> ```wat
> i32.const 0
> ...
> i32.store8 offset=239
> ```
>
> and exits early.
>
> If the loop finishes successfully for all 211 bytes, it stores:
>
> ```wat
> i32.const 1
> ...
> i32.store8 offset=239
> ```
>
> and returns success.
>
> So the function behaves exactly like a normal validator:
>
> - one mismatch → fail immediately
> - all bytes match → return true

> [!note]- High-level pseudocode
> After simplifying the control flow, `func 2` is roughly:
>
> ```python
> def check_flag(input_ptr, input_len):
>     target = memory[65536:65536+211]
>
>     if input_len != 211:
>         return False
>
>     for i in range(211):
>         helper_byte = func1() & 0xff
>         transformed = input[i] ^ helper_byte
>         if transformed != target[i]:
>             return False
>
>     return True
> ```
>
> So the role of `func 2` is now very clear: it implements a byte-by-byte XOR-based verification against an embedded 211-byte target buffer.

> [!note]- What `func 2` tells us
> Even before opening `func 1`, `func 2` already gives us the core structure of the checker:
>
> - the expected input length is exactly `211`
> - the module stores an embedded target buffer at memory offset `65536`
> - verification is done one byte at a time
> - each byte is transformed with XOR before comparison
> - the XOR byte comes from helper function `func 1`
>
> So only after this structure is clear does it make sense to inspect `func 1` and determine how that helper byte is generated.

## Understanding the Helper Function

> [!note]- Full WAT: `func 1`
> ```wat
> (func (;1;) (type 3) (result i32)
>   (local i32 i32)
>   global.get 0
>   i32.const 16
>   i32.sub
>   local.set 0
>   local.get 0
>   i32.const 0
>   i32.load offset=65748
>   i32.const 0
>   i32.shr_u
>   i32.const 0
>   i32.load offset=65748
>   i32.const 2
>   i32.shr_u
>   i32.xor
>   i32.const 0
>   i32.load offset=65748
>   i32.const 3
>   i32.shr_u
>   i32.xor
>   i32.const 0
>   i32.load offset=65748
>   i32.const 5
>   i32.shr_u
>   i32.xor
>   i32.const 1
>   i32.and
>   i32.store offset=12
>   i32.const 0
>   i32.load offset=65748
>   i32.const 1
>   i32.shr_u
>   local.get 0
>   i32.load offset=12
>   i32.const 31
>   i32.shl
>   i32.or
>   local.set 1
>   i32.const 0
>   local.get 1
>   i32.store offset=65748
>   i32.const 0
>   i32.load offset=65748
>   return)
> ```

> [!note]- Why `func 1` matters
> From the earlier analysis of `func 2`, we already know that the checker does this once per byte:
>
> ```text
> helper_byte = func1() & 0xff
> transformed = input[i] XOR helper_byte
> ```
>
> So `func 1` is not the main checker by itself, but it is the function responsible for generating the byte stream used during verification.
>
> In other words, once `func 2` gave us the checker structure, `func 1` became the missing piece needed to understand where the XOR value comes from.

> [!note]- Reading the state source
> The first thing that stands out in `func 1` is that it repeatedly loads a 32-bit value from the same memory location:
>
> ```wat
> i32.const 0
> i32.load offset=65748
> ```
>
> This happens several times in the function, which strongly suggests that offset `65748` stores the current internal state of the generator.
>
> So rather than using a fresh random value every time, `func 1` is repeatedly updating and returning a stateful 32-bit value.

> [!note]- Computing the feedback bit
> The middle of the function combines several shifted versions of that same state:
>
> ```wat
> i32.const 0
> i32.load offset=65748
> i32.const 0
> i32.shr_u
> ...
> i32.const 0
> i32.load offset=65748
> i32.const 2
> i32.shr_u
> i32.xor
> ...
> i32.const 0
> i32.load offset=65748
> i32.const 3
> i32.shr_u
> i32.xor
> ...
> i32.const 0
> i32.load offset=65748
> i32.const 5
> i32.shr_u
> i32.xor
> i32.const 1
> i32.and
> ```
>
> So the function takes bits derived from shifts by:
>
> - `0`
> - `2`
> - `3`
> - `5`
>
> XORs them together, and then keeps only the least significant bit.
>
> In simpler form, the feedback bit is:
>
> ```python
> bit = ((state >> 0) ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1
> ```
>
> This already looks exactly like the feedback rule of a linear feedback shift register.

> [!note]- Updating the state
> After computing that feedback bit, the function updates the state with:
>
> ```wat
> i32.const 0
> i32.load offset=65748
> i32.const 1
> i32.shr_u
> local.get 0
> i32.load offset=12
> i32.const 31
> i32.shl
> i32.or
> local.set 1
> ```
>
> This means:
>
> - shift the current state right by one
> - move the feedback bit into bit position 31
> - combine them with `or`
>
> In simplified form:
>
> ```python
> new_state = (state >> 1) | (bit << 31)
> ```
>
> So each call updates the 32-bit state in a deterministic way.

> [!note]- Writing the new state back
> The function then stores that updated state back into the same memory slot:
>
> ```wat
> i32.const 0
> local.get 1
> i32.store offset=65748
> ```
>
> and finally returns it:
>
> ```wat
> i32.const 0
> i32.load offset=65748
> return
> ```
>
> So the full role of `func 1` is:
>
> 1. read the current 32-bit state  
> 2. compute the next state  
> 3. write the new state back to memory  
> 4. return the updated state
>
> This confirms that `func 1` is a stateful generator rather than a simple arithmetic helper.

> [!note]- Identifying it as an LFSR
> Once simplified, the logic is:
>
> ```python
> bit = ((state >> 0) ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1
> state = (state >> 1) | (bit << 31)
> return state
> ```
>
> This is a classic **LFSR-style state update**.
>
> So the helper used by `check_flag` is effectively generating a deterministic byte stream from a 32-bit internal state, and `func 2` only uses the low byte of each updated state:
>
> ```python
> helper_byte = state & 0xff
> ```

> [!note]- Initial state
> Earlier, the WAT data section already showed:
>
> ```wat
> (data (;1;) (i32.const 65748) "OLEH")
> ```
>
> This means the generator state is initialized from the ASCII bytes:
>
> ```text
> OLEH
> ```
>
> Interpreted as a 32-bit little-endian value, that becomes the fixed seed used by the helper.
>
> So the generated byte stream is not random at all — it is fully reproducible as long as we start from the same initial state.

> [!note]- What this tells us
> After combining the `func 2` and `func 1` analysis, the full checker logic is now clear:
>
> - `func 2` expects an input of length `211`
> - it copies a 211-byte target buffer from memory offset `65536`
> - for each input byte, it calls `func 1`
> - `func 1` updates a 32-bit LFSR-like state seeded from `"OLEH"`
> - `func 2` takes the low byte of that state
> - the input byte is XORed with that generated byte
> - the result must match the embedded target byte
>
> So at this point, the solve strategy is straightforward: extract the target data, recreate the same state update in Python, regenerate the byte stream, and reverse the XOR to recover the original flag.

## Solve Strategy

> [!note]- Reversing the verification logic
> After understanding both `func 2` and `func 1`, the solve path becomes very direct.
>
> The checker verifies the input using this condition for each byte:
>
> ```text
> input[i] XOR helper_byte == target[i]
> ```
>
> where:
>
> - `target[i]` comes from the 211-byte buffer stored at memory offset `65536`
> - `helper_byte` is the low byte of the updated state returned by `func 1`
>
> Since XOR is reversible, we can recover the original input byte with:
>
> ```text
> input[i] = target[i] XOR helper_byte
> ```
>
> So instead of trying to guess the flag, we can reconstruct it directly as long as we:
>
> 1. extract the 211-byte target buffer from the WASM file  
> 2. recreate the same state update used by `func 1`  
> 3. generate the helper byte for each position  
> 4. XOR it back with the target data

> [!note]- What needs to be extracted
> From the earlier WAT overview, we already know that:
>
> - the encrypted/target buffer starts at memory offset `65536`
> - the input length is `211`
> - the generator state is seeded from the bytes `"OLEH"` at offset `65748`
>
> So the only remaining task is to extract the correct 211 bytes from the WASM file and reproduce the same helper stream offline.

> [!note]- Why this is enough
> No brute force is needed here.
>
> The WASM checker already gives us everything required:
>
> - the exact expected input length
> - the exact target bytes
> - the exact helper state transition
> - the exact seed
>
> So the challenge is fully solvable by re-implementing the logic in Python.

## Solver

``` python
import struct

def solve():
    with open("challenge.wasm", "rb") as f:
        wasm_content = f.read()

    # Extract the embedded target data
    start_offset = 0x4c8
    length = 211
    target_data = wasm_content[start_offset:start_offset + length]

    # Initial state from "OLEH"
    state = struct.unpack("<I", b"OLEH")[0]

    def next_state(s):
        bit = ((s >> 0) ^ (s >> 2) ^ (s >> 3) ^ (s >> 5)) & 1
        return ((s >> 1) | (bit << 31)) & 0xFFFFFFFF

    out = []
    curr_state = state

    for i in range(length):
        curr_state = next_state(curr_state)
        helper_byte = curr_state & 0xFF
        out.append(chr(target_data[i] ^ helper_byte))

    print("".join(out))

if __name__ == "__main__":
    solve()

```


> [!note]- Why the solver works
> The checker validates:
>
> ```text
> input[i] XOR helper_byte == target[i]
> ```
>
> so the solver simply inverts that relation:
>
> ```text
> input[i] = target[i] XOR helper_byte
> ```
>
> Since the generator is deterministic and the seed is fixed, the helper stream can be reproduced exactly outside the browser.

## FLAG

![[Pasted image 20260407121955.png]]
