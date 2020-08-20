;Vatafu Tiffany Monica grupa 8
.386
.model flat, stdcall
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
includelib msvcrt.lib
extern exit: proc
extern printf : proc
extern fopen : proc
extern fprintf : proc
extern fscanf : proc
extern scanf : proc
extern fclose :proc
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

public start
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

.data
caracter db ?
format db "%c",0
mode_W db "w",0
pointerW dd ?
mode_R db "r",0
fileNameR db 50 dup(0)
fileNameW db 60 dup(0)
eroareFisier db "Nu s-a putut deschide fisierul ales.",0
extensie db ".txt"
criptareSir db "cript.txt",0
decriptareSir db "decript.txt",0
pointerR dd 0
mesajFisier db "Alegeti ce fisier doriti sa prelucrati",10,0
formatS db "%s",0 
mesajOperatie db "Operatii:",10,"00 -> Criptare.Algoritm1",10,"01 -> Criptare.Algoritm2",10,"10 ->Decriptare.Algoritm1",10,"11 ->Decriptare.Algoritm2",10,"Introduceti operatie:",0
eroareOP db "Nu ati ales o operatie valida.",0
operatie db 3 dup(0)
mesajCheie1 db "Cheia de criptare/decriptare : 0-7",10,0
mesajCheie2 db "Cheia de criptare/decriptare : 64 biti  -- cuvant 8 caractere",10,0
eroareKEY db "Cheie invalida",0
formatD db "%d",0
cheie dd 3
cheie8 db 30 dup(0)
.code

criptare proc   ;--fastcall criptare(caracter,cheie) - this function represent the first encrypting algorithm
	push ebp
	mov ebp,esp
	xor eax,eax ;--eax=0
	mov ecx,[ebp+8]  ;--eax=caracterul/the character
	mov al,[ecx]
	mov ecx, [ebp+12] ;--ecx=cheia de criptare/encryption key
	not al     ; -- complement fata de 1/ one's complement
	add eax,1   ;--complement fata de 2 /  two's complement
	ror_loop:
	ror al,1
	loop ror_loop
	mov esp,ebp
	pop ebp
	ret 8
criptare endp

decriptare proc ; decryption
	push ebp
	mov ebp,esp
	xor eax,eax
	mov ecx,[ebp+8]
	mov al,[ecx] ;--caracterul de decriptat/the character to be decrypted
	mov ecx,[ebp+12]
	rol_loop:
	rol al,1
	loop rol_loop
	not al
	add eax,1
	mov esp,ebp
	pop ebp
	ret 8
decriptare endp

algoritmC2 proc  ;fastcall(caracter,cheie)  - the second algorithm for encryption
	push ebp
	mov ebp,esp
	mov eax,[ebp+8] ;--caracterul de criptat
	mov edx,[ebp+12];--caracterul cheie
	not al ;--complement fata de 1
	xor al,dl;--xor cu cheia data
	mov esp,ebp
	pop ebp
	ret 8
algoritmC2 endp


algoritmD2 proc ; decryption 2nd algorithm
	push ebp
	mov ebp,esp
	mov eax,[ebp+8];--caracterul de decriptat/the character to be decrypted
	mov edx,[ebp+12];--caracterul cheie
	xor al,dl ;--functia inversa a lui xor este tot xor
	not al 
	mov esp,ebp
	pop ebp
	ret 8
algoritmD2 endp

start

	;--se cere calea catre fisierul dorit / the txt file is demanded
	push offset mesajFisier
	call printf
	add esp,4
	
	push offset fileNameR ;--calea pt fisier
	push offset formatS
	call scanf
	add esp,8
	
	;--se deschide pt verificare / it is verified 
	push offset mode_R
	push offset fileNameR
	call fopen;--fisierul din care se citeste
	add esp,8
	
	cmp eax,0 ;--daca nu exista fisierul cerut / if the file does not exist
	jne citireOperatie
	push offset eroareFisier
	call printf
	add esp,4
	push 0
	call exit
	
	citireOperatie:
	mov pointerR,eax

	;--se cere operatia care urmeaza sa fie efectuata asupra fisierului/ it is chosen the action to be performed
	push offset mesajOperatie
	call printf
	add esp,4
	
	push offset operatie
	push offset formatS
	call scanf
	add esp,8
	
	
	;verific daca am introdus codul valid pentru operatia de criptare/decriptare / it is verified if the action exists
	cmp operatie,'0'
	je verificareOP
	cmp operatie,'1'
	jne eroareOperatie
	
	
	
	verificareOP:
	cmp operatie[1],'1'
	je newKey
	cmp operatie[1],'0'
	jne eroareOperatie
	push offset mesajCheie1
	call printf
	add esp,4
	

	push offset cheie ; the key is demanded
	push offset formatD
	call scanf
	add esp,8
	
	
	; it is verified the key
	cmp eax,0 ;--daca nu se da un intreg
	je eroareCheie
	;--cheie trebuie sa fie intre 0 si 7
	cmp cheie,0
	jl eroareCheie
	cmp cheie,7
	jg eroareCheie
	jmp continue
	
	eroareCheie:
	push offset eroareKEY
	call printf
	add esp,4
	push pointerR
	call fclose
	add esp,4
	push 0
	call exit
	
	
	newKey:
	push offset mesajCheie2
	call printf
	add esp,4
	

	push offset cheie8
	push offset formatS
	call scanf
	add esp,8
	
	;--verific daca a fost citita cheia
	cmp eax,0
	je eroareCheie
	cmp cheie8[7],0;--daca al 8-lea byte e 0,atunci cheia nu are 8 bytes =>eroare
	je eroareCheie
	cmp cheie8[8],0
	jne eroareCheie ; -cheia are mai mult de 8 bytes => eroare
	jmp continue

	eroareOperatie:
	push offset eroareOP ;--mesaj eroare
	call printf
	add esp,4
	push pointerR ;-se inchide fisierul
	call fclose
	add esp,4
	push 0
	call exit ;- se iese din program

	
	;--se genereaza numele fisierului final/ it is generated a name for the encrypted/decrypted file
	continue:
	xor ecx,ecx
	numeFisier:
	lea esi,fileNameR[ecx]
	lea edi,extensie
	cmpsw
	je concatenare
	inc ecx
	jmp numeFisier

	concatenare:
	lea ESI, fileNameR  ;--in fileNameW se afla totul pana la .txt
	lea EDI, fileNameW
	rep movsb

	
	lea ESI,decriptareSir
	mov ECX,11
	cmp operatie,'0'
	jne fisierOUT
	lea ESI, criptareSir
	mov ECX, 9
	fisierOUT:
	rep movsb
	


	
	;--se deschide fisierul in care se va scrie
	push offset mode_W
	push offset fileNameW
	call fopen;--fisierul in care se scrie
	add esp,8
	mov pointerW,eax

	xor ebx,ebx
	
	citire: 
	push offset caracter
	push offset format
	push pointerR
	call fscanf
	add esp,12
	cmp eax,-1
	je final
	cmp operatie(1),'1'
	je algoritm2
	
	;---algoritmul 1 : criptare/decriptare / 1st algorithm
	push cheie
	push offset caracter
	cmp operatie,'0'
	je criptare1
	call decriptare
	jmp exitAlg1
	criptare1:call criptare
	exitAlg1:add esp,8
	jmp scriere
	
	; algoritm 2 criptare/decriptare / 2nd algorithm
	algoritm2:
	xor edx,edx
	xor eax,eax
	mov DL,cheie8[ebx]
	cmp ebx,7
	jg repetareCheie
	jmp next
	repetareCheie:
	mov DL,cheie8[ebx-8] ;--se reia cheia pt octetul 9 si 10
	next: 
	push edx
	mov AL,caracter
	push eax
	cmp operatie,'0'
	je criptare2
	call algoritmD2
	jmp exitAlg2
	criptare2 : call algoritmC2
	exitAlg2 : add esp,8
	inc ebx
	cmp ebx,10
	jne scriere
	xor ebx,ebx; --dupa cei 10 octeti,cheia se reia
		
	
	scriere:mov caracter,al
	push eax
	push offset format
	push pointerW
	call fprintf
	add esp,12
	
	jmp citire
	
	final:
	;--se inchid cele 2 fisiere / the files to be closed
	push pointerR
	call fclose
	add esp,4
	
	push pointerW
	call fclose
	add esp,4
	;terminarea programului
	push 0
	call exit
end start