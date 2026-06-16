Given web

![[Pasted image 20260616170811.png]]

Inspect Source

![[Pasted image 20260616170839.png]]

Actually g ada yg menarik selain ?format=%H:%M"%S

test ?format=AAAA

![[Pasted image 20260616170928.png]]

based on result above , user input disini digunakan ( tpi belum tentu diexecute )

test  ?format=%c

![[Pasted image 20260616171008.png]]

it's confirm berarti user input dianggap sebagai format string di function time like strftime , dll

test  ?format=AAAA'

![[Pasted image 20260616171232.png]]

AAAA not printed , maybe ' nyebabin error dan klo error print it's doang

test  ?format=AAAA''

![[Pasted image 20260616171323.png]]

we try double single quote dan bisa ke print AAAA , berarti kemungkinan isiannya gini
berada di single quote context like xxx('lala') , so kalau di tutup ' error , ditutup " aman

test  ?format=';cat /flag'

![[Pasted image 20260616171617.png]]
