![[Pasted image 20260405074322.png]]
## Recon  
  
We are given a file named `encrypted.bin`.  
  
A quick check of the first bytes shows this:

![[Pasted image 20260405114013.png]]

At first glance, this is unusual.  
Instead of looking random, the file starts with a long sequence of ASCII `'0'` and `'1'`.
## Why is this suspicious?

At a high level, AES-CBC encryption should produce output that looks random.

In other words, if a file is encrypted normally, we would expect the beginning of the file to look like random bytes, not a neat text pattern like:

1000001011010010...

So this is already a strong clue that the beginning of the file is **not normal ciphertext**, but some kind of encoded data.
## AES-CBC

Broadly speaking, AES-CBC works like this:

1. take a block of plaintext
2. mix it with a **starting value**
3. then encrypt it
4. the result of one block affects the next block

That starting value is called the **IV**.

You can think of it as a random starting point that makes the encrypted result change even if the plaintext is the same.

So, in AES-CBC, two important things are involved:

- the **key** → the main secret used to encrypt/decrypt
- the **IV** → the random starting point
## Connecting This to the Clue

The challenge says:

> "2 hal yang seharusnya dirahasiakan justru diletakkan di awal file"

That matches very well with AES-CBC, because the two important values here are:

- **Key**
- **IV**

So once we see that the file starts with a suspicious bitstring, the natural intuition becomes:

> maybe the beginning of the file is not ciphertext at all,  
> but an encoded form of the **key and IV**

## How many bits do we read?

From the description:

- **"Demi terlihat aman dia memilih kunci paling panjang"** → AES-256 → key = **256 bits**
- AES block size is always **128 bits** → so IV = **128 bits**

So total needed:

```text
256 + 128 = 384 bits
```

![[Pasted image 20260405114545.png]]

> [!note]- Explanation
>
> We verify this directly from the file:
>
> ```bash
> head -c 384 encrypted.bin | xxd
> ```
>
> The output still shows a clean pattern of ASCII `'0'` and `'1'`, meaning it is still structured data.
>
> But when we try:
>
> ```bash
> head -c 385 encrypted.bin | xxd
> ```
>
> At the end, we start seeing values like:
>
> ```text
> b0
> ```
>
> This is no longer `'0'` or `'1'`, but actual binary data.
>
> This confirms:
>
> - first **384 bytes** → encoded bitstring (key + IV)
> - after that → ciphertext (random-looking data)
>
> So **384 is the exact boundary**, confirmed by both theory and observation.
## Decoding the Header

We use a short Python script to convert the first 384 bytes from ASCII bitstring form into actual bytes:

```python
with open("encrypted.bin", "rb") as f:
    bits = f.read(384).decode()
    decoded = bytes(int(bits[i:i+8], 2) for i in range(0, 384, 8))

key = decoded[:32]
iv = decoded[32:]

print(f"Key: {key.hex()}")
print(f"IV : {iv.hex()}")

```

![[Pasted image 20260405115751.png]]

This confirms that the first 384 bytes of the file really store:

- a **32-byte AES-256 key**
- followed by a **16-byte IV**

==Next natural step habis ini:==
- ==decrypt remaining ciphertext pakai key+iv itu.==

## Decrypting the Ciphertext

Now that we already have the correct **key** and **IV**, the remaining part of the file should be the AES-CBC ciphertext.

So the next step is:

- skip the first **384 bytes** (the encoded header)
- read the rest as ciphertext
- decrypt it using the extracted key and IV
- save the output first, then inspect what file type it actually is

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

with open("encrypted.bin", "rb") as f:
    f.read(384)  
    ciphertext = f.read()

key = bytes.fromhex("82d231eda4cd23ee8d253ad94141fd86203ea5e9bd374582012406d1a03f6f4a")
iv  = bytes.fromhex("dd1ecbd5f5fa7327328abc598ebeabbe")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

with open("output.bin", "wb") as f:
    f.write(plaintext)
```

## Verifying the Decrypted Output

After decrypting the ciphertext, we do not immediately assume the output type.  
Instead, we inspect it first:

```bash
file output.bin
xxd output.bin | head
```

![[Pasted image 20260405120207.png]]

Oke now kita tau hasilnya PNG

## FLAG

![[Pasted image 20260405120357.png]]
