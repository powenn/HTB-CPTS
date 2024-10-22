# Wi-Fi Interfaces

## Interface Strength

```
powen@htb[/htb]$ iwconfig

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
By default, this is set to the country specified in our operating system. We can check on this with the `iw reg get` command in Linux.

```
powen@htb[/htb]$ iw reg get

global
country 00: DFS-UNSET
        (2402 - 2472 @ 40), (6, 20), (N/A)
        (2457 - 2482 @ 20), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
        (2474 - 2494 @ 20), (6, 20), (N/A), NO-OFDM, PASSIVE-SCAN
        (5170 - 5250 @ 80), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
        (5250 - 5330 @ 80), (6, 20), (0 ms), DFS, AUTO-BW, PASSIVE-SCAN
        (5490 - 5730 @ 160), (6, 20), (0 ms), DFS, PASSIVE-SCAN
        (5735 - 5835 @ 80), (6, 20), (N/A), PASSIVE-SCAN
        (57240 - 63720 @ 2160), (N/A, 0), (N/A)
```

## Changing the Region Settings for our Interface
```
powen@htb[/htb]$ sudo iw reg set US
```

Afterwards, we can check the txpower of our interface with the iwconfig utility.
```
powen@htb[/htb]$ iwconfig

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```

```
sudo ifconfig wlan0 down
sudo iwconfig wlan0 txpower 30
sudo ifconfig wlan0 up
```

## Checking Driver Capabilities for our Interface

```
powen@htb[/htb]$ iw list

Wiphy phy5
	wiphy index: 5
	max # scan SSIDs: 4
	max scan IEs length: 2186 bytes
	max # sched scan SSIDs: 0
	max # match sets: 0
	max # scan plans: 1
	max scan plan interval: -1
	max scan plan iterations: 0
	Retry short limit: 7
	Retry long limit: 4
	Coverage class: 0 (up to 0m)
	Device supports RSN-IBSS.
	Device supports AP-side u-APSD.
	Device supports T-DLS.
	Supported Ciphers:
			* WEP40 (00-0f-ac:1)
			* WEP104 (00-0f-ac:5)
			<SNIP>
```

## Scanning Available WiFi Networks

```
powen@htb[/htb]$ iwlist wlan0 scan |  grep 'Cell\|Quality\|ESSID\|IEEE'

          Cell 01 - Address: f0:28:c8:d9:9c:6e
                    Quality=61/70  Signal level=-49 dBm  
                    ESSID:"HTB-Wireless"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: 3a:c4:6e:40:09:76
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"CyberCorp"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 03 - Address: 48:32:c7:a0:aa:6d
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"HackTheBox"
                    IE: IEEE 802.11i/WPA2 Version 1
```

## Changing Channel & Frequency of Interface
```
powen@htb[/htb]$ iwlist wlan0 channel

wlan0     32 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 02 : 2.417 GHz
          Channel 03 : 2.422 GHz
          Channel 04 : 2.427 GHz
          <SNIP>
          Channel 140 : 5.7 GHz
          Channel 149 : 5.745 GHz
          Channel 153 : 5.765 GHz
```

```
powen@htb[/htb]$ sudo ifconfig wlan0 down
powen@htb[/htb]$ sudo iwconfig wlan0 channel 64
powen@htb[/htb]$ sudo ifconfig wlan0 up
powen@htb[/htb]$ iwlist wlan0 channel
```

```
powen@htb[/htb]$ iwlist wlan0 frequency | grep Current

          Current Frequency:5.32 GHz (Channel 64)
```

```
powen@htb[/htb]$ sudo ifconfig wlan0 down
powen@htb[/htb]$ sudo iwconfig wlan0 freq "5.52G"
powen@htb[/htb]$ sudo ifconfig wlan0 up
```

# Airmon-ng

## Checking for interfering processes

```
powen@htb[/htb]$ sudo airmon-ng check

Found 5 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to kill (some of) them!

  PID Name
  718 NetworkManager
  870 dhclient
 1104 avahi-daemon
 1105 avahi-daemon
 1115 wpa_supplicant
```

However, it is important to note that this step should only be taken if we are experiencing challenges during the pentesting process.

```
powen@htb[/htb]$ sudo airmon-ng check kill

Killing these processes:

  PID Name
  870 dhclient
 1115 wpa_supplicant
```

# Airodump-ng

The supported bands are a, b, and g.

- a uses 5 GHz
- b uses 2.4 GHz
- g uses 2.4 GHz

```
powen@htb[/htb]$ sudo airodump-ng wlan0mon --band a
```

```
airodump-ng --band abg wlan0mon
```

# Airdecap-ng

## Using Airdecap-ng
```
airdecap-ng [options] <pcap file>
```
| Option | Description |
| - | - |
| -l |	don't remove the 802.11 header |
| -b |	access point MAC address filter |
| -k |	WPA/WPA2 Pairwise Master Key in hex |
| -e |	target network ascii identifier |
| -p |	target network WPA/WPA2 passphrase |
| -w |	target network WEP key in hexadecimal |

## Removing Wireless Headers from Unencrypted Capture file

Capturing packets on an open network would result in an unencrypted capture file. Even if the capture file is already unencrypted, it may still contain numerous frames that are not relevant to our analysis. To streamline the data, we can utilize airdecap-ng to eliminate the wireless headers from an unencrypted capture file.

To remove the wireless headers from the capture file using Airdecap-ng, we can use the following command
```
airdecap-ng -b <bssid> <capture-file>
```

Replace with the MAC address of the access point and with the name of the capture file.

```
powen@htb[/htb]$ sudo airdecap-ng -b 00:14:6C:7A:41:81 opencapture.cap

Total number of stations seen            0
Total number of packets read           251
Total number of WEP data packets         0
Total number of WPA data packets         0
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets         0
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

This will produce a decrypted file with the suffix `-dec.cap`, such as `opencapture-dec.cap`, containing the streamlined data ready for further analysis.

## Decrypting WEP-encrypted captures

Airdecap-ng is a powerful tool for decrypting WEP-encrypted capture files. Once we have obtained the hexadecimal WEP key, we can use it to decrypt the captured packets. This process will remove the wireless encryption, allowing us to analyze the data.

To decrypt a WEP-encrypted capture file using Airdecap-ng, we can use the following command:

```
airdecap-ng -w <WEP-key> <capture-file>
```

Replace <WEP-key> with the hexadecimal WEP key and with the name of the capture file.

```
powen@htb[/htb]$ sudo airdecap-ng -w 1234567890ABCDEF HTB-01.cap

Total number of stations seen            6
Total number of packets read           356
Total number of WEP data packets       235
Total number of WPA data packets       121
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets       235
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

## Decrypting WPA-encrypted captures

Airdecap-ng can also decrypt WPA-encrypted capture files, provided we have the passphrase. This tool will strip the WPA encryption, making it possible to analyze the captured data.

To decrypt a WPA-encrypted capture file using Airdecap-ng, we can use the following command:

```
airdecap-ng -p <passphrase> <capture-file> -e <essid>
```

```
powen@htb[/htb]$ sudo airdecap-ng -p 'abdefg' HTB-01.cap -e "Wireless Lab"

Total number of stations seen            6
Total number of packets read           356
Total number of WEP data packets       235
Total number of WPA data packets       121
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets       121
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

# Aircrack-ng

## Aircrack-ng Benchmark

```
powen@htb[/htb]$ aircrack-ng -S

1628.101 k/s
```

## Cracking WEP

Aircrack-ng is capable of recovering the WEP key once a sufficient number of encrypted packets have been captured using Airodump-ng. It is possible to save only the captured IVs (Initialization Vectors) using the --ivs option in Airodump-ng. Once enough IVs are captured, we can utilize the -K option in Aircrack-ng, which invokes the Korek WEP cracking method to crack the WEP key.

```
powen@htb[/htb]$ aircrack-ng -K HTB.ivs 
```

## Cracking WPA

```
powen@htb[/htb]$ aircrack-ng HTB.pcap -w /opt/wordlist.txt
```

# Connecting to Wi-Fi Networks

After connecting, we can obtain an IP address by using the dhclient utility. This will assign an IP from the network's DHCP server, completing the connection setup.

```
powen@htb[/htb]$ sudo dhclient wlan0
```

if we have a previously assigned DHCP IP address from a different connection, we'll need to release it first. Run the following command to remove the existing IP address:

```
 powen@htb[/htb]$ sudo dhclient wlan0 -r

Killed old client process
```

## Connecting with Network Manager Utilities

One of the ways that we can easily connect to wireless networks in Linux is through the usage of nmtui. This utility will give us a somewhat graphical perspective while connecting to these wireless networks.

```
powen@htb[/htb]$ sudo nmtui
```


