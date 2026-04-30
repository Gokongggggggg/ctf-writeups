![[Pasted image 20260407122350.png]]

## Recon

> [!note]- Given file
> The challenge provided a single file:
>
> ```text
> pirates_hook.exe
> ```
>
> I started with a quick file identification check:
>
>![[Pasted image 20260407122859.png]]
>
> From this, it was clear that the challenge was a normal Windows executable, so the next step was to begin with lightweight static analysis first.

## Strings pirates_hook.exe | grep "{"

![[Pasted image 20260407123211.png]]

==The visible `{` made this look less like random data and more like a distorted flag string. So instead of ignoring it, I treated it as an encoded message and tried simple reversible decodings.==
## Recovering the Original String

> [!note]- Why XOR was a reasonable guess
> After extracting the suspicious string, the next question was what kind of lightweight obfuscation had been used.
>
> For an easy reverse challenge, the most common possibilities are usually:
>
> - character shifting
> - addition/subtraction by a constant
> - single-byte XOR
>
> Here, XOR was a reasonable first candidate because the extracted text still looked structured, but many characters had turned into symbols such as:
>
> ```text
> \ / ` { ~
> ```
>
> That kind of output is very common when readable text has been XORed with a small constant. A simple Caesar-style shift usually keeps the result closer to letters and digits, while XOR often produces this exact mix of readable and strange punctuation.
>
> So instead of assuming the exact key immediately, I brute-forced all single-byte XOR keys and searched for anything matching the expected flag format.

## Solve.py

``` python
s = r"SFWJQxe2mbooz--zlv\s76pfg\2pGfavdd0qSqfpfmw/\sql`ffg\wl\m0{w\`kboo~"

for key in range(1, 256):
    out = ''.join(chr(ord(c) ^ key) for c in s)
    if "PETIR{" in out or "RETIP{" in out:
        print(f"[+] key = {key}")
        print(out)
        print("-" * 40)
```

## FLAG

![[Pasted image 20260407123644.png]]
