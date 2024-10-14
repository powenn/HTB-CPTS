# Assembling & Disassembling

## Assembling
```
nasm -f elf64 helloWorld.s
```

> Note: The `-f elf64` flag is used to note that we want to assemble a 64-bit assembly code. If we wanted to assemble a 32-bit code, we would use `-f elf`.

## Linking

```
ld -o helloWorld helloWorld.o
```
> Note: if we were to assemble a 32-bit binary, we need to add the '-m elf_i386' flag.


build a simple bash script to make it easier

**assembler.sh**

```
#!/bin/bash

fileName="${1%%.*}" # remove .s extension

nasm -f elf64 ${fileName}".s"
ld ${fileName}".o" -o ${fileName}
[ "$2" == "-g" ] && gdb -q ${fileName} || ./${fileName}
```

we can use the assembler.sh script we wrote in the previous section with the `-g` flag. It will assemble and link the code, and then run it with gdb

## Disassembling

To disassemble a file, we will use the objdump tool, which dumps machine code from a file and interprets the assembly instruction of each hex code. We can disassemble a binary using the -D flag.

> Note: we will also use the flag -M intel, so that objdump would write the instructions in the Intel syntax, which we are using, as we discussed before.
```
powen@htb[/htb]$ objdump -M intel -d helloWorld

helloWorld:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	b8 01 00 00 00       	mov    eax,0x1
  401005:	bf 01 00 00 00       	mov    edi,0x1
  40100a:	48 be 00 20 40 00 00 	movabs rsi,0x402000
  401011:	00 00 00
  401014:	ba 12 00 00 00       	mov    edx,0x12
  401019:	0f 05                	syscall
  40101b:	b8 3c 00 00 00       	mov    eax,0x3c
  401020:	bf 00 00 00 00       	mov    edi,0x0
  401025:	0f 05                	syscall
```

If we wanted to only show the assembly code, without machine code or addresses, we could add the `--no-show-raw-insn` `--no-addresses` flags, as follows:

```
powen@htb[/htb]$ objdump -M intel --no-show-raw-insn --no-addresses -d helloWorld

helloWorld:     file format elf64-x86-64

Disassembly of section .text:

<_start>:
        mov    eax,0x1
        mov    edi,0x1
        movabs rsi,0x402000
        mov    edx,0x12
        syscall 
        mov    eax,0x3c
        mov    edi,0x0
        syscall
```

> Note: Note that objdump has changed the third instruction into movabs. This is the same as mov, so in case you need to reassemble the code, you can change it back to mov.

The `-d` flag will only disassemble the .text section of our code. To dump any strings, we can use the `-s` flag, and add `-j` .data to only examine the .data section. This means that we also do not need to add `-M` intel. The final command is as follows:

```
powen@htb[/htb]$ objdump -sj .data helloWorld

helloWorld:     file format elf64-x86-64

Contents of section .data:
 402000 48656c6c 6f204854 42204163 6164656d  Hello HTB Academ
 402010 7921
```
