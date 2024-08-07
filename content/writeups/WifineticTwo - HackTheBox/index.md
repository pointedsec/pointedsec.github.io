+++
author = "Andrés Del Cerro"
title = "Hack The Box: WifineticTwo Writeup | Medium"
date = "2024-07-27"
description = ""
tags = [
    "HackTheBox",
    "WifineticTwo",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Network Security",
    "Wireless Hacking",
    "WPS",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "OpenPLC",
    "Exploit",
    "Linux"
]

+++

# Hack The Box: WifineticTwo Writeup

Welcome to my detailed writeup of the medium difficulty machine **"WifineticTwo"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

## 🕵️‍♂️ Initial Enumeration

### Port Scanning

First, we perform a TCP port scan to discover open ports and services.
```shell
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZqPPOw.iUxtyBgx_I7ywKWBIJNQZkv6zL4; Expires=Fri, 26-Jul-2024 16:35:51 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 26 Jul 2024 16:30:51 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 302 FOUND
```

### 🌐 Web Enumeration

Upon visiting the web service on port 8080, we identify it as an OpenPLC instance, which is known to have a Remote Code Execution (RCE) vulnerability (CVE-2021-31630).

### 📂 Initial Foothold
Using this [PoC](https://github.com/thewhiteh4t/cve-2021-31630) we can get Remote Command Execution on the target, this exploit just upload a specially designed C code that will execute on PLC start.

After executing the exploit, we gain access to a container.

```shell
hostname -I
10.0.3.2
10.0.3.52
```

### 📶 Wireless Network Exploitation
With `iw dev wlan0 scan` command, we can see that an Access Point exists, this AP BSSID is: `02:00:00:00:01:00`

This network have WPS PIN version 1 activated, so we can probably do some bruteforce to the WPS PIN to obtain the WPA PSK.

With [OneShot](https://github.com/nikita-yfh/OneShot-C)
We can bruteforce the WPS pin. The PIN is: `12345670`, Top-Level Security

With this PIN we can now obtain the WPA PSK: `NoWWEDoKnowWhaTisReal123!`

But we doesn't have a username to use this password.

##### Connecting to the wireless network
Now, we can connect to this Access Point using `wpa_passphrase` and `wpa_supplicant`

```shell
root@attica01:/tmp/oneshot# wpa_passphrase plcrouter "NoWWEDoKnowWhaTisReal123!" | sudo tee /etc/wpa_supplicant.con
network={
	ssid="plcrouter"
	#psk="NoWWEDoKnowWhaTisReal123!"
	psk=2bafe4e17630ef1834eaa9fa5c4d81fa5ef093c4db5aac5c03f1643fef02d156`
}
```
We can now authenticate to the AP

```shell
wpa_supplicant -B -c /etc/wpa_supplicant.conf -i wlan0
```

It seems that this Network doesn't have a DHCP Server on it, so we can assign one IP direction statically guessing the tipical domestic networks (192.168.0.0/24 / 192.168.1.0/24)

```shell
sudo ifconfig wlan0 192.168.1.10 netmask 255.255.255.0 up
```

We can do ping to 192.168.1.1
```shell
root@attica01:/tmp/oneshot# ping 192.168.1.1
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=18.2 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=57.0 ms
```

### 🛡️ Privilege Escalation
Scanning Open Ports on the Router

Using the Pivoting Enum script suite:

```shell
git clone https://github.com/S12cybersecurity/Pivoting_Enum
cd Pivoting_Enum
./enum.sh 192.168.1.1

Open Ports:

    53/tcp: DNS
    22/tcp: SSH
    80/tcp: HTTP
    443/tcp: HTTPS
```
SSH into the Router

Surprisingly, the router's SSH allows login without a password for root.

```shell
ssh root@192.168.1.1

=== WARNING! =====================================
There is no root password defined on this device!
Use the "passwd" command to set up a new password
in order to prevent unauthorized SSH logins.
```

At this point we fully compromised this machine!

### 🎉 Conclusion

Through systematic enumeration and exploitation, we successfully rooted WifineticTwo. This involved leveraging default credentials, exploiting RCE, brute-forcing WPS PIN, and finally gaining root access via SSH.

Happy Hacking! 🚀