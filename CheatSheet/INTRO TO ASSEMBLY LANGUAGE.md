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

> Note: In assembly, moving data does not affect the source operand. So, we can consider `mov` as a copy function, rather than an actual move.


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

# Debugging with GDB

## Break

break or b
```
gef➤  b _start

Breakpoint 1 at 0x401000
```

If we want to set a breakpoint at a certain address, like _start+10, we can either b *_start+10 or b *0x40100a:
```
gef➤  b *0x40100a
Breakpoint 1 at 0x40100a
```

The * tells GDB to break at the instruction stored in 0x40100a.

If we want to see what breakpoints we have at any point of the execution, we can use the `info breakpoint` command. We can also `disable`, `enable`, or `delete` any breakpoint. Furthermore, GDB also supports setting conditional breaks that stop the execution when a specific condition is met.

## Examine

To manually examine any of the addresses or registers or examine any other, we can use the `x` command in the format of `x/FMT ADDRESS`, as `help x` would tell us. The `ADDRESS` is the address or register we want to examine, while `FMT` is the examine format. The examine format `FMT` can have three parts:

| Argument | Description | Example |
| - | - | - |
| Count | The number of times we want to repeat the examine | 2,3,10 |
| Format | The format we want the result to be represented in | x(hex), s(string), i(instruction) |
| Size | The size of memory we want to examine | b(byte), h(halfword), w(word), g(giant, 8 bytes) |

For example, if we wanted to examine the next four instructions in line, we will have to examine the $rip register (which holds the address of the next instruction), and use 4 for the count, i for the format, and g for the size (for 8-bytes or 64-bits). So, the final examine command would be x/4ig $rip, as follows:

```
gef➤  x/4ig $rip

=> 0x401000 <_start>:	mov    eax,0x1
   0x401005 <_start+5>:	mov    edi,0x1
   0x40100a <_start+10>:	movabs rsi,0x402000
   0x401014 <_start+20>:	mov    edx,0x12
```

### Strings

We can also examine a variable stored at a specific memory address. We know that our message variable is stored at the .data section on address 0x402000 from our previous disassembly. We also see the upcoming command movabs rsi, 0x402000, so we may want to examine what is being moved from 0x402000.

In this case, we will not put anything for the Count, as we only want one address (1 is the default), and will use s as the format to get it in a string format rather than in hex:

```
gef➤  x/s 0x402000

0x402000:	"Hello HTB Academy!"
```

> Note: if we don't specify the Size or Format, it will default to the last one we used.

### Addresses

The most common format of examining is hex x. We often need to examine addresses and registers containing hex data, such as memory addresses, instructions, or binary data. Let us examine the same previous instruction, but in hex format, to see how it looks:

```
gef➤  x/wx 0x401000

0x401000 <_start>:	0x000001b8
```

We see instead of mov eax,0x1, we get 0x000001b8, which is the hex representation of the mov eax,0x1 machine code in little-endian formatting.  
This is read as: b8 01 00 00.

at any point we can use the registers command to print out the current value of all registers:
```
gef➤  registers
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffe310  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x1
...SNIP...
```


## Step

The third step of debugging is stepping through the program one instruction or line of code at a time. As we can see, we are currently at the very first instruction in our helloWorld program:

```
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ffe                  add    BYTE PTR [rax], al
 →   0x401000 <_start+0>       mov    eax, 0x1
     0x401005 <_start+5>       mov    edi, 0x1
```

> Note: the instruction shown with the `->` symbol is where we are at, and it has not yet been processed.

To move through the program, there are three different commands we can use: stepi and step.

### Step Count

Similarly to examine, we can repeat the si command by adding a number after it. For example, if we wanted to move 3 steps to reach the syscall instruction, we can do so as follows:

```
gef➤  si 3
0x0000000000401019 in _start ()
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401004 <_start+4>       add    BYTE PTR [rdi+0x1], bh
     0x40100a <_start+10>      movabs rsi, 0x402000
     0x401014 <_start+20>      mov    edx, 0x12
 →   0x401019 <_start+25>      syscall 
     0x40101b <_start+27>      mov    eax, 0x3c
     0x401020 <_start+32>      mov    edi, 0x0
     0x401025 <_start+37>      syscall 
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "helloWorld", stopped 0x401019 in _start (), reason: SINGLE STEP
```

### Step

The step or s command, on the other hand, will continue until the following line of code is reached or until it exits from the current function. If we run an assembly code, it will break when we exit the current function _start.

> Note: There's also the `next` or `n` command, which will also continue until the next line, but will skip any functions called in the same line of code, instead of breaking at them like step. There's also the `nexti` or `ni`, which is similar to si, but skips functions calls, as we will see later on in the module.

## Modify

As we can see, we have to provide the type/size of the new value, the location to be stored, and the value we want to use. So, let's try changing the string stored in the .data section (at address 0x402000 as we saw earlier) to the string Patched!\n.

We will break at the first syscall at 0x401019, and then do the patch, as follows:

```
gef➤  break *0x401019

Breakpoint 1 at 0x401019
gef➤  r
gef➤  patch string 0x402000 "Patched!\\x0a"
gef➤  c

Continuing.
Patched!
 Academy!
```

We see that we successfully modified the string and got Patched!\n Academy! instead of the old string. Notice how we used \x0a for adding a new line after our string.

using set to modify $rdx

```
gef➤  set $rdx=0x9
```
