# shellGo
A Microsoft windows x86_64 Golang shellcode tester that includes example calc.exe shellcode.

go run main.go : runs calc.exe
go run main.go <myShellcodeFile> : loads the binary data from <myShellcodeFile> and attempts to call it as shellcode 
