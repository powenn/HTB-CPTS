## WHOIS

| **Command** | **Description** |
|-|-|
| `export TARGET="domain.tld"` | Assign target to an environment variable. |
| `whois $TARGET` | WHOIS lookup for the target. |


---
## DNS Enumeration

| **Command** | **Description** |
|-|-|
| `nslookup $TARGET` | Identify the `A` record for the target domain. |
| `nslookup -query=A $TARGET` | Identify the `A` record for the target domain. |
| `dig $TARGET @<nameserver/IP>` | Identify the `A` record for the target domain.  |
| `dig a $TARGET @<nameserver/IP>` | Identify the `A` record for the target domain.  |
| `nslookup -query=PTR <IP>` | Identify the `PTR` record for the target IP address. |
| `dig -x <IP> @<nameserver/IP>` | Identify the `PTR` record for the target IP address.  |
| `nslookup -query=ANY $TARGET` | Identify `ANY` records for the target domain. |
| `dig any $TARGET @<nameserver/IP>` | Identify `ANY` records for the target domain. |
| `nslookup -query=TXT $TARGET` | Identify the `TXT` records for the target domain. |
| `dig txt $TARGET @<nameserver/IP>` | Identify the `TXT` records for the target domain. |
| `nslookup -query=MX $TARGET` | Identify the `MX` records for the target domain. |
| `dig mx $TARGET @<nameserver/IP>` | Identify the `MX` records for the target domain. |


---
## Passive Subdomain Enumeration

| **Resource/Command** | **Description** |
|-|-|
| `VirusTotal` | [https://www.virustotal.com/gui/home/url](https://www.virustotal.com/gui/home/url) |
| `Censys` | [https://censys.io/](https://censys.io/) |
| `Crt.sh` | [https://crt.sh/](https://crt.sh/) |
| `curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.[]' \| sort -u` | All subdomains for a given domain. |
| `curl -s https://sonar.omnisint.io/tlds/{domain} \| jq -r '.[]' \| sort -u` | All TLDs found for a given domain. |
| `curl -s https://sonar.omnisint.io/all/{domain} \| jq -r '.[]' \| sort -u` | All results across all TLDs for a given domain. |
| `curl -s https://sonar.omnisint.io/reverse/{ip} \| jq -r '.[]' \| sort -u` | Reverse DNS lookup on IP address. |
| `curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} \| jq -r '.[]' \| sort -u` | Reverse DNS lookup of a CIDR range. |
| `curl -s "https://crt.sh/?q=${TARGET}&output=json" \| jq -r '.[] \| "\(.name_value)\n\(.common_name)"' \| sort -u` | Certificate Transparency. |
| `cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done` | Searching for subdomains and other information on the sources provided in the source.txt list. |
| `openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" \| openssl x509 -noout -text -in - \| grep 'DNS' \| sed -e 's\|DNS:\|\n\|g' -e 's\|^\*.*\|\|g' \| tr -d ',' \| sort -u` | Certificate Transparency using OpenSSL |

#### Sources.txt
```txt
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
cat facebook.com_subdomains_passive.txt | wc -l
```

---
## Passive Infrastructure Identification

| **Resource/Command** | **Description** |
|-|-|
| `Netcraft` | [https://www.netcraft.com/](https://www.netcraft.com/) |
| `WayBackMachine` | [http://web.archive.org/](http://web.archive.org/) |
| `WayBackURLs` | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |
| `waybackurls -dates https://$TARGET > waybackurls.txt` | Crawling URLs from a domain with the date it was obtained. |


---
## Active Infrastructure Identification

| **Resource/Command** | **Description** |
|-|-|
| `curl -I "http://${TARGET}"` | Display HTTP headers of the target webserver. |
| `whatweb -a https://www.facebook.com -v` | Technology identification. |
| `Wappalyzer` | [https://www.wappalyzer.com/](https://www.wappalyzer.com/) |
| `wafw00f -v https://$TARGET` | WAF Fingerprinting. |
| `Aquatone` | [https://github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone) |
| `cat subdomain.list \| aquatone -out ./aquatone -screenshot-timeout 1000` | Makes screenshots of all subdomains in the subdomain.list. |

> `wafw00f` We can use options like -a to check all possible WAFs in place instead of stopping scanning at the first match, read targets from an input file via the -i flag, or proxy the requests using the -p option.



---
## Active Subdomain Enumeration

| **Resource/Command** | **Description** |
|-|-|
| `HackerTarget` | [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) |
| `SecLists` | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |
| `nslookup -type=any -query=AXFR $TARGET nameserver.target.domain` | Zone Transfer using Nslookup against the target domain and its nameserver. |
| `gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"` | Bruteforcing subdomains. |


---
## Virtual Hosts

| **Resource/Command** | **Description** |
|-|-|
| `curl -s http://192.168.10.10 -H "Host: randomtarget.com"` | Changing the HOST HTTP header to request a specific domain. |
| `cat ./vhosts.list \| while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://<IP address> -H "HOST: ${vhost}.target.domain" \| grep "Content-Length: ";done` | Bruteforcing for possible virtual hosts on the target domain. |
| `ffuf -w ./vhosts -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs 612` | Bruteforcing for possible virtual hosts on the target domain using `ffuf`. |


---
## Crawling

| **Resource/Command** | **Description** |
|-|-|
| `ZAP` | [https://www.zaproxy.org/](https://www.zaproxy.org/) |
| `ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt` | Discovering files and folders that cannot be spotted by browsing the website.
| `ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS` | Mutated bruteforcing against the target web server. |

> `cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10`

ReconSpider
```
wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://inlanefreight.com
```
