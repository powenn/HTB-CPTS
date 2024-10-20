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
