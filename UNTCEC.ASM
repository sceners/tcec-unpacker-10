; TITLE      : TCEC Unpacker
; VERSION    : 1.0
; AUTHOR     : Christoph Gabler
; DATE       : 16th of october in 1999
; PROG TYPE  : Double int21 unpacker
; WORKS WITH : TCEC 3.55, TCEC 3.55b (*) by The Cleric
; USED MUSIC : In Flames[World domination]

; ADDITIONAL INFORMATION :
; The EXE loader of this source was in the past used in my CrackStopRemover
; and in my HackStopRemover.
; Files protected with TCEC 3.55b don't work because of a big bug in the
; TCEC envelope (infinitive loop, image decryptor bug).
; Without these bugs, UNTCEC would also be able to remove this new version.
; Large file support is also included (files up to 0.5 MB).

code segment
org  100h
assume cs:code,ds:code
.386p

CHRiSTOPH:

Call Logo
MainCode:

Mov Dx, 82h
Mov Ax, 3D02h                    ; Open file for r/w
Int 21h
Jc Open_Error
Mov Di, Ax

Mov Bx, Ax
mov al, 02
xor cx, cx
xor dx, dx
mov ah, 42h                      ; Filepointer to end of file.
Int 21h       
Mov CS:word ptr [FileSize], Ax
Mov CS:word ptr [FileSize2], Dx
Mov CS:word ptr [FileSize3], Dx

cwd
mov ax,4200h                     ; Filepointer to begin.
Xor Cx,Cx
Xor Dx,Dx
Mov Bx, Di
int 21h

Mov Bx, Di
Mov Dx, Offset Image
Mov Cx, 9000h
Mov Ah, 3Fh                      ; Read header.
Int 21h

Cmp DS:word ptr [Image], 'ZM'    ; Check for .exe header sign
Je Exefound
Cmp DS:word ptr [Image], 'MZ'    ; Check for reverse .exe header sign
Je Exefound
Mov Ah, 9
Mov Dx, Offset Comfile
Int 21h
Int 20h

Exefound:
cwd
Mov Dx, CS:word ptr [Image+8]    ; Get .EXE header size
iMul Dx, 16d
Mov CS:word ptr [Exe_Header], Dx

Mov Ax, CS:word ptr [Image+10h]  ; Get .EXE SP value
Mov CS:word ptr [Exe_Sp], Ax

Mov Cx, CS:word ptr [Image+16h]  ; Get .EXE offset
Cmp CS:word ptr [Image+0Eh], Cx
Jne RealExe                      ;
Cmp CS:word ptr [Image+14h], 100h;
Jne RealExe                      ; > Check for real exe or converted
Mov CS:byte ptr [NoExe], 1       ;
Sub Cx, Cx                       ;
RealExe:
Mov CS:word ptr [Exe_Offset], Cx

Mov Dx, CS:word ptr [Exe_Header]
Xor Cx, Cx
Mov Bx, Di
mov ax, 4200h                     ; Filepointer to module start.
int 21h

Mov Dx, CS:word ptr [Image+0Eh]   ; Get .EXE Stack Segment
Mov CS:word ptr [Exe_SS], Dx

Mov Dx, CS:word ptr [Image+14h]   ; Get .EXE IP
Mov CS:word ptr [Exe_IP], Dx

Mov Ax, Cs
Add Ax, 1000h
Mov DS, Ax
Mov CS:word ptr [Exe_CS], Ax

Mov EBP, CS:dword ptr [FileSize]
pUSH dS

Mov Si, CS:word ptr [Exe_CS]
Add Si, 10h
Mov Ds, Si
Cmp CS:byte ptr [NoExe], 1
Je OverNormal
Sub Si, 10h
OverNormal:
Mov CS:word ptr [Exe_Ds], Si

Xor Dx, Dx
Cmp CS:byte ptr [NoExe], 1
Jne OkAsAlways
Add Dx, 100h
OkAsAlways:

ReadFile:
Mov Cx, 2000h
Mov Bx, Di
Mov Ah, 3Fh                       ; Read whole file to EXE_CS:EXE_IP
Int 21h
Add CS:word ptr [FileSize2], Ax

Mov Ax, Ds
Add Ax, 200h
Mov Ds, Ax
Cmp Ebp, 2000h
Jbe FinishRead
Sub Ebp, 2000h
Jmp ReadFile

FinishRead:
pOP dS

Cwd
Mov Dx, CS:word ptr [Exe_Header]
Xor Cx,Cx
Mov Bx, Di
mov ax,4200h                      ; Filepointer to module start.
int 21h

Mov Bx, Di
Mov Ah, 3Eh
Int 21h

Mov Es, CS:word ptr [Exe_DS]

Push Cs
Pop Ds

Xor Si, Si
Xor Di, Di
Mov Cx, 0FFh
REPZ
MOVSB                             ; Move CX bytes from DS:SI to ES:DI

Mov Bx, CS:word ptr [Exe_CS]
Add Bx, CS:word ptr [Exe_Offset]
Add Bx, 10h
Mov CS:word ptr [Exe_CS], Bx

Push Cs
Pop Ds

; save old int21
Mov Ax, 3521h
Int 21h
Mov CS:word ptr [oldint21], Bx
Mov CS:word ptr [oldint21+2], Es
Push Cs
Pop Es

; hook int21
Push Ds
Push Cs
Pop Ds
Mov Ax, 2521h
Mov Dx, offset BrkPoint1
Int 21h
Pop Ds

; Set up the registers!

Mov Ds, CS:word ptr [Exe_DS]
Push Ds
Pop Es

CLi
Mov Dx, Ds
Cmp CS:byte ptr [NoExe], 1
Je NoNormExe
Mov Dx, CS:word ptr [Exe_SS]   ; Header SS
Mov Ax, Cs
Add Dx, Ax
Add Dx, 1010h
NoNormExe:
Mov SS, Dx
Mov Sp, CS:word ptr [Exe_Sp]
STi

Mov Si, CS:word ptr [Exe_Ip]

Push Ds
Mov DS, CS:word ptr [Exe_Cs]
Cmp DS:dword ptr [Si], 'CECT'  ; TCEC signature
Jne Cs_Error
Push Cs
Pop Ds
PushAD
Mov Ah, 9
Mov Dx, Offset CS_Found
Int 21h
PopAD
Detected:
Mov Ah,9
Mov Dx, Offset Success0
Int 21h

Pop Ds
Mov DS:word ptr [80h], 00
Xor Bp, Bp
Mov Dx, Ds
Xor Ax, Ax
Xor Bx, Bx
Xor Cx, Cx
Mov Di, Sp

; Launch victim file!
Jmp CS:dword ptr [Exe_Ip]

Open_Error:
Mov Ah, 9
Mov Dx, Offset ErrorMsg3
Int 21h
Mov Ax,4C03h
Int 21h

CS_Error:
Push Cs
Pop Ds
Mov Ah, 9
Mov Dx, Offset ErrorMsg4
Int 21h
Int16again:
Xor Ax, Ax
Int 16h
Cmp Al, 'c'
Je Detected
Cmp Al, 'a'
Je AbortUnpack
Jmp Int16again
AbortUnpack:
Call Unhook
Mov Ax,4C01h
Int 21h

BrkPoint1:

Cmp Ah, 0Dh
Jne DoNormalInt21

Mov CS:word ptr [Save_Bx], Bx
Mov CS:word ptr [Save_Ds], Ds

PushAD
Push Cs
Pop Ds
Mov Ah, 9
Mov Dx, Offset First
Int 21h

Call unhook
PopAD

Pop Bx ; IP
Pop Ds ; CS
Push Ds Bx
Mov Cx, 300h
SearchL:
Cmp DS:word ptr [Bx], 0DB87h
Je Found1
Back:
Inc Bx
Loop SearchL
Push Cs
Pop Ds
Mov Ah, 9
Mov Dx, Offset DecodeError
Int 21h
Mov Ah, 4Ch
Int 21h
Found1:
Cmp DS:byte ptr [Bx+2], 0EAh
Jne Back

PushAD
Mov DS:word ptr [Bx], 099CDh
Push Cs
Pop Ds
Mov Ax, 2599h
Mov Dx, Offset BrkPoint2
Int 21h
PopAD

Mov Bx, CS:word ptr [Save_Bx]
Mov Ds, CS:word ptr [Save_Ds]
Iret

DoNormalInt21:
db 0EAh
OldInt21 db 0,0,0,0

unhook:
; unhook int21
Mov Dx, CS:word ptr [oldint21]
Mov Ds, CS:word ptr [oldint21+2]
Mov Ax, 2521h
Int 21h
Ret

;++
; New breakpoint handler [dump/reconstruct]
;
BrkPoint2:

Push Ds
Pop Es

Push Cs
Pop Ds

Mov Bp, Es

Mov Ah, 9
Mov Dx, Offset Second
Int 21h

Mov Dx, Offset FileName
Xor Cx, Cx
Mov Ah, 3Ch      ; Create file "UNPACKED.EXE"
Int 21h
Mov Di, Ax

Mov Ah, 9
Mov Dx, Offset Reconstruct
Int 21h

; Reconstruct old header

Xor Ecx, Ecx
Mov Cx, CS:word ptr [Filesize]
Mov Ax, CS:word ptr [FileSize3]
Shl Eax, 10h
Add Ecx, Eax

Sub Ecx, 1300d

Mov CS:word ptr [SaveSize], Cx
Push Cx
Shr Ecx, 10h
Mov CS:word ptr [FileSize3], Cx
Pop Cx

; Image+2 and +4
Mov Ax, Cx
Mov Dx, Cx
And Ah, 1                       ; mod 512
Mov Cl, 9                       ; 2**9 = 512
Shr Dx, Cl                       
Inc Dx

Mov CS:word ptr [Image+2], Ax

Mov Cx, CS:word ptr [FileSize3]
Mov Bx, Cx
Imul Cx, 7Fh
Add Dx, Cx
Mov CS:word ptr [Image+4], Dx
Add CS:word ptr [Image+4], Bx

Mov Ax, Sp                          ;
Add Ax, 06h                         ; SP
Mov CS:word ptr [Image+10h], Ax     ;

Pop Bx  ; Get Ip                    ;
Pop Ds  ; Get Cs                    ;
;>Add Bx, 15h ; Modify because we aren't at real RETF
Push Ds Bx                          ; IP
Mov Ax, DS:word ptr [Bx+1]          ;
Mov CS:word ptr [Image+14h], Ax     ;   

Mov Ax, Ss                          ; -ES    ;
Mov Dx, Es
Sub Ax, Dx
Sub Ax, 20h                         ; -10h   ;   -> SS
Mov CS:word ptr [Image+0Eh], Ax     ; SS     ;

Mov Dx, Es
Mov Cx, Ss
Cmp Cx, Dx
Jne ReallyAnExe
Mov CS:word ptr [Image+16h], Dx
ReallyAnExe:
Add CS:word ptr [Image+0Eh], 10h    ; -10h   ;   -> SS  
notdothis:

Mov Ax, DS:word ptr [Bx+3]          ; CS
Sub Ax, 10h                         ;
Mov Dx, Es
Sub Ax, Dx
Mov CS:word ptr [Image+16h], Ax     ; -> CodeSegment Offset

Push Cs
Pop Ds
Mov Dx, Offset Image
Mov Cx, CS:word ptr [Exe_Header]
Mov Bx, Di

Mov Ah, 40h      ; Write old header to unpacked file
Int 21h

Mov Dx, Bp       ;
Add Dx, 10h      ; Point to DS+10:0000
Mov Ds, Dx       ;
Xor Ecx, Ecx
Xor Eax, Eax
Mov Cx, CS:word ptr [SaveSize]
Sub Cx, CS:word ptr [Exe_Header]
Mov Ax, CS:word ptr [FileSize3]
Shl Eax, 10h
Add Eax, Ecx
Mov Ebp, Eax     ; EBP=Filesize

Mov Bx, Di
Xor Dx, Dx
Cmp Ebp, 2000h
Jbe LastWrite

WriteFile:
Mov Bx, Di
Xor Dx, Dx
Mov Cx, 2000h
Mov Ah, 40h      ; Write unpacked image to disk
Int 21h
Mov Ax, Ds
Add Ax, 200h
Mov Ds, Ax
Sub Ebp, 2000h

Cmp Ebp, 2000h
Jbe LastWrite
Jmp WriteFile
LastWrite:
Mov Bx, Di
Xor Dx, Dx
Mov Cx, Bp
Mov Ah, 40h      ; Last write to disk
Int 21h

Push Cs
Pop Ds

Mov Ah, 3Eh
Mov Bx, Di
Int 21h

Mov Ah, 9
Mov Dx, Offset Success
Int 21h

exittodos:
Mov Ax, 4C00h
Int 21h

; messages
Second db 10h,' SECOND BREAKPOiNT REACHED',0Dh,0Ah,'$'
First  db 10h,' FiRST BREAKPOiNT REACHED',0Dh,0Ah,'$'
Success0 db 'þ UNPACKiNG FiLE',0Dh,0Ah,'$'
Success db  'þ UNPACKED.EXE WRiTTEN AND DONE!',0Dh,0Ah,'$'
Comfile db 'þ ERROR: WOULD YOU BE SO KiND TO ONLY SPECiFY .EXE FiLES?!',0Dh,0Ah,'$'
CS_Found     db 'þ TCEC DETECTED',0Dh,0Ah,'$'
CS_Regged    db 'þ REGiSTERED VERSiON FOUND',0Dh,0Ah,'$'
CS_ShareWare db 'þ SHAREWARE VERSiON FOUND',0Dh,0Ah,'$'
Reconstruct  db 'þ RECONSTRUCTiNG HEADER VALUES',0Dh,0Ah,'$'
ErrorMsg3  db  'þ ERROR: FiLE NOT FOUND',0Dh,0Ah,'$'
DecodeError db 'þ ERROR: INTERNAL DECODE ERROR, VERSiON?',0Dh,0Ah,'$'
ErrorMsg4  db 'þ ERROR: FiLE DOESN''T SEEM TO BE PROTECTED WiTH TCEC!',0Dh,0Ah
           db '         (C)ontinue or (A)bort unpacking?',0Dh,0Ah,'$'


; vars
FileName db 'UNPACKED.EXE',00
Handle db 0,0
Version10bcheck db 0
ReggedVersion db 0
FileSize db 0,0
FileSize2 db 0,0
FileSize3 db 0,0
SaveSize db 0,0
Exe_Ip db 0,0
Exe_Cs db 0,0
Exe_Header db 0,0
Exe_Offset db 0,0
Exe_SS db 0,0
Exe_Sp db 0,0
Exe_Ds db 0,0
NoExe db 0
Save_Bx db 0,0
Save_Ds db 0,0
SaveEntry db 0,0
Save_XX db 0,0

Logo:
		push	cs
		pop	ds
		jmp	short loc_1
data_1		db	7
data_2		db	0Dh, 0Ah, '$'
data_3		db	0FFh
		db	24h
loc_1:
		mov	si,offset data_3
loc_2:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_3			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_1
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_2
loc_3:
		mov	ah,9
		mov	dx,offset data_2	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_4
data_4		db	9
data_5		db	0Dh, 0Ah, '$'
data_6		db	20h
		db	0C4h
		db	40 dup (0C4h)
		db	24h
loc_4:
		mov	si,offset data_6
loc_5:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_6			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_4
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_5
loc_6:
		mov	ah,9
		mov	dx,offset data_5	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_7
data_8		db	0Fh
data_9		db	0Dh, 0Ah, '$'
data_10		db	20h
		db	0CDh
                db      5 dup (0CDh)
		db	 10h, 10h
                db      ' UNPACKER FOR TCEC 3.55x '
		db	 11h, 11h,0CDh
                db      5 dup (0CDh)
		db	24h
loc_7:
		mov	si,offset data_10
loc_8:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_9			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_8
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_8
loc_9:
		mov	ah,9
		mov	dx,offset data_9	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_10
data_13		db	0Fh
data_14		db	0Dh, 0Ah, '$'
data_15		db	20h
		db	0CDh
		db	40 dup (0CDh)
		db	24h
loc_10:
		mov	si,offset data_15
loc_11:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_12			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_13
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_11
loc_12:
		mov	ah,9
		mov	dx,offset data_14	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_13
data_17		db	0Fh
data_18		db	0Dh, 0Ah, '$'
data_19		dw	2020h, 2020h, 2020h
		db	 20h,0FFh
                db      '  Coded by CHRiSTOPH / DTG'
		db	0FFh
		db	7 dup (0FFh)
		db	24h
loc_13:
		mov	si,offset data_19
loc_14:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_15			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_17
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_14
loc_15:
		mov	ah,9
		mov	dx,offset data_18	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_16
data_21		db	9
data_22		db	0Dh, 0Ah, '$'
data_23		db	20h
		db	0C4h
		db	40 dup (0C4h)
		db	24h
loc_16:
		mov	si,offset data_23
loc_17:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_18			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_21
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_17
loc_18:
		mov	ah,9
		mov	dx,offset data_22	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_19
data_25		db	0Fh
data_26		db	0Dh, 0Ah, '$'
data_27		db	0FFh
		db	24h
loc_19:
		mov	si,offset data_27
loc_20:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_21			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_25
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_20
loc_21:
		mov	ah,9
		mov	dx,offset data_26	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_22
data_28		db	7
data_29		db	0Dh, 0Ah, '$'
data_30         db      ''
                db      'USAGE: CSR.EXE [FILE_TO_UNPACK]'
		db	'$'
loc_22:

		push	cs
		pop	ds
                jmp     short abc_1
abcd_1          db      7
abcd_2          db      0Dh, 0Ah, '$'
abcd_3          dw      4 dup (0FFFFh)
		db	0FFh, 24h
abc_1:
                mov     si,offset abcd_3
abc_2:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
                je      abc_3                   ; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
                mov     bl,abcd_1
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
                jmp     short abc_2
abc_3:
		mov	ah,9
                mov     dx,offset abcd_2        ; ('')
		int	21h			; DOS Services  ah=function 09h

Cmp DS:byte ptr [80h], 00
Jne OkPara

		mov	ah,9
                mov     dx,offset data_30       ; ('')
		int	21h			; DOS Services  ah=function 09h
TillHere:

Mov Ax, 4C01h
Int 21h

OkPara:
Mov Bh, 00
Mov Bl, Ds:[80h]
Mov DS:byte ptr [81h+Bx], 00
Ret

; beyond this place, the file is loaded
Image:

code ends
end CHRiSTOPH
