# /bin/sh -i
This command will execute the shell interpreter specified in the path in interactive mode (-i).
```
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```

# Perl
If the programming language Perl is present on the system, these commands will execute the shell interpreter specified.  
Perl To Shell
```
perl —e 'exec "/bin/sh";'
```
```
perl: exec "/bin/sh";
```
The command directly above should be run from a script.

# Ruby
Ruby To Shell
```
ruby: exec "/bin/sh"
```

# Lua
```
lua: os.execute('/bin/sh')
```

# AWK
AWK is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports. It can also be used to spawn an interactive shell. This is shown in the short awk script below:
```
awk 'BEGIN {system("/bin/sh")}'
```

# Find
```
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
This use of the find command is searching for any file listed after the -name option, then it executes awk (/bin/awk) and runs the same script we discussed in the awk section to execute a shell interpreter.

# Using Exec To Launch A Shell
```
find . -exec /bin/sh \; -quit
```

# VIM
Vim To Shell
```
vim -c ':!/bin/sh'
```

Vim Escape
```
vim
:set shell=/bin/sh
:shell
```

# TTY
https://0xffsec.com/handbook/shells/full-tty/
`export TERM=xterm-256color`