![[Pasted image 20260405125954.png]]
## Given

![[Pasted image 20260405130146.png]]

## Initial Check

Since the challenge gives us a PNG file, the first thing we check is its metadata:

![[Pasted image 20260405130224.png]]

From the output, one field immediately stands out:

Comment : 50 45 54 49 52 7b 66 6c 61 67 5f 69 6e 69 5f 64 69 62 75 61 74 5f

The value in the `Comment` field looks like a sequence of **hex bytes**, so the next natural step is to convert it to ASCII.

After converting, we get:

PETIR{flag_ini_dibuat_

However, the flag is still incomplete because it does not end with `}` yet.

So we look back at the metadata output and notice another interesting clue:

Warning : [minor] Trailer data after PNG IEND chunk

![[Pasted image 20260405130823.png]]

we got :
xneran_prevgen_n_tagnatha}

This looks like **ROT13**, so decoding it gives:

karena_ceritra_a_gntangun

## Using zsteg

![[Pasted image 20260405131428.png]]

At this point, we already know two things:  
  
- the `Comment` metadata contains a partial flag  
- there is extra data after the PNG `IEND` chunk  
  
That means this challenge is likely hiding information in **multiple places inside the PNG**, not just in the metadata.  
  
So instead of checking each possibility one by one manually, we use:  
  
```bash  
zsteg udin.png
```

`zsteg` is useful here because it can quickly inspect common places where PNG challenges hide data, such as:

- metadata
- extra/appended data
- hidden bitplanes inside the image

From the result, we get three important parts:

meta Comment  -> PETIR{flag_ini_dibuat_  
b1,r,lsb,xy   -> amFtX3NldGVuZ2FoXzRfcGFnaV8=  
extradata:0   -> xneran_prevgn_tnaghatna}

## FLAG

PETIR{flag_ini_dibuat_nam_setengah_4_pagi_karena_citevta_gantungan}