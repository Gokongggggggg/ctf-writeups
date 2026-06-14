## Given interface Like game

![[Pasted image 20260614180125.png]]

Karena ini web exp chall , rasanya ga mungkin kita harus kelarin game labirin bginian

![[Pasted image 20260614180326.png]]

above code looks like starter command , dan dia melakukan / execure fetchOptions()

### fetchOptions()

![[Pasted image 20260614180438.png]]
dia ngefetch ke /api/options

We try open /api/options endpoint

![[Pasted image 20260614181040.png]]
"secret" seems fishy jadi kita take a note aja dlu , lalu lanjut baca code main.js selanjutnya

![[Pasted image 20260614180346.png]]

kita highlight bagian : availableOptions['secret'].includes(currentCommand) , berarti artinya kalau currComand == availableOptions maka lolos logic IF nya

next question : dari mana current command diisi -> dari commandHistory

![[Pasted image 20260614181550.png]]

commandHistory di push dari commandText.innerHtml

![[Pasted image 20260614182622.png]]

commandText.innerHTML datang dari userText input

berarti basicly we just need , input nilai dari 'secrets' yg kita dapatkan dari /api/options & then done

## FLAG

![[Pasted image 20260614182940.png]]
