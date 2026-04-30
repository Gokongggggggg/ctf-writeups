![[Pasted image 20260404222726.png]]

# Given

![[joe.jpg]]

## Googling JL Joe

![[Pasted image 20260404223113.png]]

> [!note]- Explanation
> The image shows the text **"Joe"**, which is likely a road name.  
> So we search:
>
> ```
> jl joe
> ```
>
> Then check **Google Images** and find references pointing to  
> 👉 **Flyover Tapal Kuda Lenteng Agung**  
>
> Even though the image is not an exact match, the sign style and road context align,  
> so the location can be inferred to be around that area.

## Flyover tapal kuda

![[Pasted image 20260404223846.png]]


![[Pasted image 20260404223746.png]]

> [!note]- Explanation  
> From the previous finding, we open **Google Maps** and locate the area.  
> The red marker shows the location roughly in the middle of the flyover.  
>  
> From there, an interesting detail is a **junction/intersection nearby**.  
> The Street View image we found earlier also shows a similar road split.  
>  
> So the intuition is:  
> - inspect the area around that intersection  
> - because road signs like this are usually placed near junctions  
>  
> Combined with the fact that the sign wouldn’t be far from this area,  
> we narrow it down to that specific part of the flyover.

## Furthermore

![[Pasted image 20260404224436.png]]

> [!note]- Explanation  
> From the intersection we found earlier, the location is already close but not an exact match with the challenge image.  
>  
> The key clue is:  
> - to reach **Jl. Joe**, you have to go **left at the intersection**  
>  
> So the intuition becomes:  
> - since this is a **flyover**, there must be another road **under / around it**  
> - that road is likely the actual path leading toward Jl. Joe  
>  
> Meaning, instead of staying on the flyover itself,  
> we should inspect the **lower road that connects to that left direction**.



![[Pasted image 20260404224751.png]]

![[Pasted image 20260404224819.png]]

> [!note]- Explanation  
> After zooming in around the red marker, we notice there’s another road under the flyover.  
>  
> We try exploring that path, and it turns out:  
> - the view matches the challenge image perfectly  
>  
> So this confirms that the actual location is **not on the flyover**,  
> but on the road beneath it that leads toward Jl. Joe.  
>  
> Finally, we just take the coordinates from that spot  
> and round it to **4 decimal places**.

## FLAG

#### PETIR{-6.3235,106.8348}