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

