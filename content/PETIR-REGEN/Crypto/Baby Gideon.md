![[Pasted image 20260405074541.png]]

## Recon  
  
The given string immediately looks like **Base64**.  
  
Why?  
  
- it only uses characters commonly seen in Base64:  
  - uppercase letters  
  - lowercase letters  
  - numbers  
  - etc
  
```text  
So the first intuition is simply:

> try Base64 decoding it
```

## DECODE BASE 64

We paste the string into a Base64 decoder and decode it.

The output is still another Base64-looking string, so we repeat the same step again.

In other words, the challenge is just:

- decode
- see if the result still looks like Base64
- if yes, decode again

After repeating this several times, we finally get the plaintext password.

![[Pasted image 20260405124123.png]]

![[Pasted image 20260405124216.png]]

## OPEN ZIP FILE WITH PASSWORD WE GET

![[Pasted image 20260405125201.png]]

## After Extraction

![[Pasted image 20260405125330.png]]
## What is this?

The symbols match a known cipher used in _Gravity Falls_, called:

Bill Cipher

This is a type of **symbol substitution cipher**, where:

- each symbol represents a letter
- the mapping is predefined (not random)
## Solve

Using an online tool:
https://www.dcode.fr/gravity-falls-bill-cipher

## FLAG

![[Pasted image 20260405125823.png]]
