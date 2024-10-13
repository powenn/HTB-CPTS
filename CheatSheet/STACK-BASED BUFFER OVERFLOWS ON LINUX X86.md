# External References
https://tech-blog.cymetrics.io/posts/crystal/reverse-01/

# Disable ASLR

Modern operating systems have built-in protections against such vulnerabilities, like Address Space Layout Randomization (ASLR). For the purpose of learning the basics of buffer overflow exploitation, we are going to disable this memory protection features:
```
student@nix-bow:~$ sudo su
root@nix-bow:/home/student# echo 0 > /proc/sys/kernel/randomize_va_space
root@nix-bow:/home/student# cat /proc/sys/kernel/randomize_va_space
```

## Compilation
```
student@nix-bow:~$ sudo apt install gcc-multilib
student@nix-bow:~$ gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
student@nix-bow:~$ file bow32 | tr "," "\n"

bow: ELF 32-bit LSB shared object
 Intel 80386
 version 1 (SYSV)
 dynamically linked
 interpreter /lib/ld-linux.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=93dda6b77131deecaadf9d207fdd2e70f47e1071
 not stripped
```

# GDB - Change the Syntax to Intel

The Intel syntax makes the disassembled representation easier to read, and we can change the syntax by entering the following commands in GDB:
```
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```

## Change GDB Syntax

We don't have to change the display mode manually continually. We can also set this as the default syntax with the following command.

```
student@nix-bow:~$ echo 'set disassembly-flavor intel' > ~/.gdbinit
```


# Disassemble function

```
(gdb) disas bowfunc 
```

# Registers info

```
(gdb) info registers 
```

or `info reg`

for sepecfic register
```
(gdb) info registers eip
```

# Create Pattern

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1200 > pattern.txt
```

# GDB - Offset

```
powen@htb[/htb]$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x69423569

[*] Exact match at offset 1036
```

To overwrite it and check if we have reached it as planned, we can add 4 more bytes with "\x66" and execute it to ensure we control the EIP.

# GDB Breakpoint

```
(gdb) break bowfunc 

Breakpoint 1 at 0x56555551
```

## The Stack
```
(gdb) x/2000xb $esp+500

0xffffd28a:	0xbb	0x69	0x36	0x38	0x36	0x00	0x00	0x00
0xffffd292:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd29a:	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f	0x73
0xffffd2a2:	0x74	0x75	0x64	0x65	0x6e	0x74	0x2f	0x62
0xffffd2aa:	0x6f	0x77	0x2f	0x62	0x6f	0x77	0x33	0x32
0xffffd2b2:	0x00    0x55	0x55	0x55	0x55	0x55	0x55	0x55
				 # |---> "\x55"s begin

0xffffd2ba: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2c2: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
<SNIP>
```

