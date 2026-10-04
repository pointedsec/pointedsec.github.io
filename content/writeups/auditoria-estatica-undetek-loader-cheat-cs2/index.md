+++
author = "Andrés Del Cerro"
title = "Auditoria estatica de undetek.exe v10.51: anatomia de un loader de cheat para CS2"
date = "2026-10-03T14:00:00+01:00"
description = "Analisis completo, funcion a funcion y byte a byte, de un loader de cheat para Counter-Strike 2: cadena de inyeccion, descifrado de strings, el C2 que resulto ser una API publica de hora, y una demostracion de contencion de capacidades que permite descartarlo como malware."
tags = [
    "reverse-engineering",
    "malware-analysis",
    "static-analysis",
    "x86-64",
    "counter-strike-2",
    "triage"
]
+++

# Auditoria estatica de undetek.exe v10.51

> **TL;DR.** `undetek.exe` es un loader de cheat para Counter-Strike 2. **No es malware.** Se demuestra porque su payload, 25.226 bytes auditados al 100%, no tiene IAT propia, ni constantes propias, ni una sola cadena de texto legible, ni resuelve APIs por hash, y todas sus capacidades se reducen a 12 punteros a funcion que el loader le entrega. No puede escribir en disco, no puede crear procesos y **no tiene forma de enviar datos a ninguna parte**.
>
> En paralelo se descubre que la "licencia" del producto es un PIN derivado del reloj publico, que cualquiera con el `.exe` puede calcular. Y que el riesgo real para el usuario no es este binario, sino la guia que le pide desactivar el antivirus.

Este documento recoge el analisis completo. Cada afirmacion lleva su evidencia y, donde la evidencia es incompleta, se dice de forma explicita. tambien se documentan los errores del propio analista, porque un informe que no cuenta sus fallos no es fiable.

---

## 1. La muestra

| | |
|---|---|
| **Ruta** | `/home/kali/Desktop/undetek/undetek-v10.51/undetek.exe` |
| **MD5** | `47cdf077d83b9e8c8b80364d2dbd9527` |
| **SHA-1** | `77468f710e2d45fcbab758a6beb8590e767d79be` |
| **SHA-256** | `82eb05556ffe1597e40353a0faef69e78f072d14e671adbf360c2161c06a8276` |
| **Formato** | PE32+ (x86-64), Microsoft Visual C++ |
| **CRT** | Universal C Runtime enlazado estaticamente |
| **Empaquetado** | Ninguno. Sin packer, sin secciones ejecutables anomalas |
| **Secciones** | `.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `.reloc` |
| **Timestamp** | `0x6AC0B92E` |
| **Compilacion** | ImageBase `0x140000000`, entrypoint RVA `0xA5F4` |

El directorio tambien incluia cuatro ficheros de texto del propio vendedor: `Aimbot Guide.txt`, `Install Guide.txt`, `VAC.txt`, `capa.txt`. Los tres primeros se usan en este analisis como contexto declarativo, es decir, para contrastar lo que el codigo hace con lo que el autor dice que hace. El cuarto es un informe generado automaticamente por la herramienta capa y se trata aparte, porque tiene falsos positivos.

### 1.1 Restriccion metodologica

**El binario nunca se ejecuto.** Todo el analisis es estatico. Esto tiene dos consecuencias que se repiten a lo largo del documento:

1. Lo que solo existe en tiempo de ejecucion, es decir el payload descifrado dentro del proceso remoto, es inaccesible por definicion para el analisis estatico convencional.
2. El payload se audito por extraccion de indicadores y analisis de capacidades, no por desensamblado semantico completo.

**Cobertura real:** 100 por ciento de los bytes del loader, y 100 por ciento de los 25.226 bytes del payload mediante el metodo de capacidades descrito en la seccion 8, con las limitaciones declaradas en la seccion 12.

---

## 2. Inventario

El binario contiene aproximadamente 760 funciones. La descomposicion:

| Rango | Funciones | Naturaleza |
|---|---|---|
| `0x140007150` - `0x140028F10` | ~650 | Universal C Runtime y vcruntime estaticos |
| `0x140001000` - `0x1400037D0` | ~87 | Helpers de ofuscacion, cliente de red, inyector |
| `0x140006A00` - `0x140007470` | ~12 | Modulo principal, E/S de consola |
| Aisladas | ~10 | Enumeracion de procesos, envoltorios de syscalls |

El punto de entrada es `entry` en `0x14000A5F4`, que invoca `__scrt_common_main_seh` en `0x14000A478`, que a su vez invoca `main` en `0x140007270`. La confirmacion es una unica referencia de codigo desde `0x14000A57F`.

### 2.1 Imports de aplicacion

**Kernel32, explicitos:** `VirtualAllocEx`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `OpenProcess`, `CreateRemoteThread`, `WaitForSingleObject`, `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `GetModuleHandleA`, `GetProcAddress`, `GetTickCount64`, `CloseHandle`, `Sleep`, `GetLastError`.

**USER32:** `GetAsyncKeyState` y `SendInput`. Importadas pero, como se vera, nunca invocadas por el loader.

**ADVAPI32:** `RegCreateKeyExA`, `RegSetValueExA`, `RegQueryValueExA`, `RegDeleteKeyA`, `RegOpenKeyExA`, `RegOpenKeyExW`, `RegCloseKey`, `RegSetValueExW`.

**WS2_32, importado por ordinal y no por nombre:**

```
Ordinal_3    Ordinal_4    Ordinal_16   Ordinal_19
Ordinal_23   Ordinal_111  Ordinal_115  Ordinal_116
getaddrinfo  freeaddrinfo        (estos dos, por nombre)
```

El conjunto de ordinales {3, 4, 16, 19, 23} corresponde a `closesocket`, `connect`, `recv`, `send` y `socket`. El par {115, 116} corresponde a `WSAStartup` y `WSACleanup`. El paso 111 es `WSAGetLastError`. La identificacion se confirma en el descompilado, donde aparece `WSAStartup(MAKEWORD(2, 2))` con el valor `0x202`.

**Importar Winsock por ordinal es una decision deliberada de anti-analisis.** Elimina del binario las cadenas `socket`, `connect`, `send` y `recv`, que son exactamente lo que un motor heuristico busca. Conviene subrayar que esta tecnica es usada tanto por malware como por inyectores legitimos, y por si sola no constituye un indicador.

---

## 3. Nota sobre el metodo: los errores del analista

Antes de entrar en el binario, conviene registrar los cuatro fallos cometidos durante este analisis, porque ilustran los limites del trabajo puramente estatico con herramientas homegrown:

1. **Desensamblador propio con las instrucciones partidas.** El primer intento de desensamblar el stub de 221 bytes produjo una salida en la que las instrucciones se cortaban por la mitad, por un error en el calculo de ModRM e inmediatos. Se detecto al leer el codigo Assembly a mano y comparar.
2. **Bucle infinito en un parser de x86-64.** El script de analisis de capacidades se quedaba colgado porque, cuando el byte actual no era ni un prefijo ni un opcode reconocido, el indice no avanzaba. Se manifesto como un cuelgue sin salida, no como un error.
3. **Tabla de flags de seccion equivocada.** Los valores `IMAGE_SCN_MEM_*` estaban desplazados una posicion, de modo que `.text` aparecia como lectura y escritura en lugar de ejecucion y lectura. La conclusion correcta, ninguna seccion tiene W+X, se alcanzo solo al comparar los valores brutos con los estandar de MSVC.
4. **Estructura mal formada al leer el directorio de depuracion.** Se uso un campo de 1 byte donde la especificacion exige 4, lo que desplaza la interpretacion de todo el registro.

Los cuatro son fallos de instrumentacion, es decir, de no tener una suite de referencia con la que validar las herramientas propias. Es la leccion practica: cuando se escribe un desensamblador a mano para un analisis puntual, hay que contrastarlo con un desensamblador real antes de fiarse de el.

---

## 4. Ofuscacion de cadenas

### 4.1 El mecanismo

Todas las cadenas del loader estan cifradas con XOR de un solo byte. La plantilla es identica en las 51 funciones:

```c
// FUN_1400019c0, forma canonica
char *FUN_1400019c0(char *buf) {
    if (*buf == '\0')                                  // cache: solo descifra una vez
        for (int i = 0; i < 10; i++)
            buf[i] = PTR_DAT_1400297C8[i] ^ 0x34;       // XOR byte a byte
    buf[10] = '\0';
    return buf;
}
```

Tres parametros por cadena: direccion del blob cifrado, longitud y clave. La clave es `0x34` en todos los casos observados. Existe una variante de cadena ancha que lee `*(ushort*)(blob + i * 2) ^ 0x34`, y una funcion aparte, `XorDecodeWideInPlace`, que aplica el mismo XOR de 16 bits sobre un buffer ya colocado en su destino.

El ciclo de vida de cada cadena es siempre el mismo y no deja rastro en memoria estatica:

```asm
LEA  RCX,[RSP+0x49A8]        ; buffer local en la pila
MOV  ECX,0x15                ; tamano
STOSB.REP RDI                ; memset a cero
CALL FUN_140001250           ; helper de memset, devuelve el puntero
CALL FUN_140001D20           ; descifrador, escribe aqui
```

Las 51 funciones de descifrado ocupan el rango `0x1400014B0` a `0x140003010`, con paso constante de `0x90`. Aparte hay 32 helpers de `memset` de tamano fijo en `0x140001000` a `0x140001490`.

El descifrado en la pila es deliberado: un volcado de memoria del fichero jamas revela el texto, y un escaner de cadenas del antivirus no tiene nada que detectar.

### 4.2 Recuperacion de las cadenas

La clave del proceso esta en como Ghidra nombra los simbolos. Cuando un blob esta definido como cadena, el descompilador lo renderiza con el nombre del simbolo incluyendo el texto cifrado, por ejemplo `PTR_s_R_FYU__QP4_1400297D8`. Descifrar es restar `0x34`.

La verificacion cruzada se hizo con dos casos independientes:

```
blob "R[FYU@@QP4"            ->  f o r m a t t e d \0   = "formatted"
blob "z@eAQFM}ZR[FYU@][ZdF[WQGG4"
                             ->  NtQueryInformationProcess     (24 caracteres)
blob "g[R@CUFQhAP@_4"       ->  S o f t w a r e \ u d t k \0 = "Software\udtk"
```

Veinticuatro caracteres correctos de forma consecutiva no son casualidad. Eso valida la clave mas alla de la suposicion.

Para los blobs que Ghidra no tenia indexados, se escribio una herramienta que hace fuerza bruta: aplica XOR `0x34` a la seccion `.rdata` completa y extrae rachas de bytes imprimibles, tanto en ASCII como en UTF-16. Asi se recuperaron alrededor de 35 cadenas adicionales.

### 4.3 Las cadenas recuperadas

**Infraestructura:**

| Contenido | Uso |
|---|---|
| `formatted` | nombre de campo JSON de la API de hora, no un marcador de protocolo |
| `vip.timezonedb.com` | host, 19 bytes: 18 mas NUL |
| `80` | puerto, 3 bytes: 2 mas NUL |
| `GET /v2.1/get-time-zone?key=<API_KEY_REDACTED>&format=json&by=zone&zone=Europe/London HTTP/1.1\r\nHost: vip.timezonedb.com\r\nConnection: close\r\n\r\n` | peticion, 138 bytes literales |
| `%04lld` | formato del `sprintf` que genera el PIN |
| `%4s` | formato del `scanf` que lee el PIN |
| `Software\udtk` | clave de registro, 14 caracteres |

**Modulos y exportaciones:**

| Contenido | Uso |
|---|---|
| `cs2.exe` | proceso objetivo secundario, 8 bytes |
| `gameoverlayui64.exe` | proceso objetivo principal, 19 bytes |
| `ntdll.dll` | modulo de las APIs de bajo nivel y de las matematicas |
| `client.dll` | modulo del juego del que se extrae la base |
| `vgui2_s.dll` | modulo de la interfaz grafica |
| `NtQueryInformationProcess` | resuelta por nombre desde ntdll |
| `NtReadVirtualMemory` | resuelta por nombre desde ntdll |
| `CreateInterface` | Fabrica de interfaces del motor |
| `VGUI_Setup001` | interfaz 1 |
| `VGUI_Surface039` | interfaz 2 |
| `_itow`, `sqrt`, `pow`, `fabs` | matematicas del CRT reexportadas por ntdll |

**Configuracion del cheat:**

| Contenido | Tipo |
|---|---|
| `Aimbot`, `Smooth`, `Hitbox`, `Trigger`, `Spotted`, `Esp`, `Theme` | features |
| `Aim Spot`, `Key` | opciones del menu |
| `On`, `Off` | valores de interruptor |
| `Tahoma` | fuente del menu |
| `41 BF ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 53 20 48 3B C2 73 0A 48 8B C8 48 2B CA 48 01 4B 30` | firma de bytes buscada en memoria |

Las 51 funciones de descifrado quedaron identificadas y renombradas con su contenido real.

---

## 5. La red: el C2 que no era un C2

### 5.1 Lo que parecia

El perfil estatico encajaba con un canal de comando y control. La funcion `C2_AuthExchange` en `0x140003030` confirma el patron completo, con toda la API de Winsock importada por ordinal:

```c
Ordinal_115(MAKEWORD(2,2), &wsadata);                     // WSAStartup
getaddrinfo(szHostName, szServicePort, &hints, &res);     // resolver
Ordinal_23(ai_family, ai_socktype, ai_protocol);           // socket
Ordinal_4(sock, ai_addr, ai_addrlen);                      // connect
Ordinal_19(sock, szRequest, strlen(szRequest), 0);          // send
Ordinal_16(sock, pbRecvBuf, 0x1000, 0);                    // recv
Ordinal_3(sock);                                           // closesocket
Ordinal_116();                                             // WSACleanup
```

Los parametros de `hints` se leen directamente del descompilado:

```asm
MOV dword ptr [RSP+0xBC],0x0     ; ai_flags      = 0
MOV dword ptr [RSP+0xC0],0x1     ; ai_socktype   = SOCK_STREAM
MOV dword ptr [RSP+0xC4],0x6     ; ai_protocol   = IPPROTO_TCP
```

Y el `send` es una llamada unica, sin bucle de reintento:

```asm
140003343  CALL 0x140001370            ; memset
14000334B  CALL 0x140002500            ; descifrar la peticion (138 bytes)
140003355  MOV  RCX,[RSP+0x68]
14000335A  CALL strlen                 ; 0x140028660
14000335F  XOR  R9D,R9D               ; flags = 0
140003362  MOV  R8D,EAX                ; len = strlen(payload)
140003365  MOV  RDX,[RSP+0x68]         ; buf
14000336A  MOV  RCX,[RSP+0x28]         ; sock
14000336F  CALL qword ptr [0x140029390] ; send
```

### 5.2 Lo que realmente es

Las cadenas descifradas dan la respuesta:

```
host   = "vip.timezonedb.com"
puerto = "80"
peticion =
  GET /v2.1/get-time-zone?key=<API_KEY_REDACTED>&format=json&by=zone
  &zone=Europe/London HTTP/1.1\r\n
  Host: vip.timezonedb.com\r\n
  Connection: close\r\n\r\n
```

Y el supuesto "marcador de protocolo" que el cliente exige encontrar en la respuesta es la cadena `formatted`.

**`formatted` no es un marcador de protocolo propio. Es el nombre de un campo de la respuesta JSON de timezonedb.com:**

```json
{"country":"GB","countryName":"United Kingdom","region":"England",
 "city":"London","zone":"Europe/London","abbreviation":"BST",
 "dst":true,"offset":3600,"currenttime":1759248896,
 "formatted":"2026-05-31 14:14:56"}
```

El `strstr(respuesta, "formatted")` busca ese nombre de campo. El codigo parsea despues la hora, la trata como `HH:MM:SS` y deriva de ella un numero.

### 5.3 El `recv` y sus defectos

```asm
1400033CF  XOR  R9D,R9D
1400033D2  MOV  R8D,[RSP+0x5C]      ; 0x1000
1400033D7  LEA  RDX,[RSP+0x730]     ; buffer de 4096
1400033DF  MOV  RCX,[RSP+0x28]
1400033E4  CALL qword ptr [0x140029358]  ; recv
1400033EA  MOV  [RSP+0x20],EAX
1400033EE  CMP  dword ptr [RSP+0x20],0x0
1400033F3  JLE  0x1400033F7          ; si ret <= 0, salta
1400033F5  JMP  0x1400033FE         ; si ret > 0, sale
1400033F7  CMP  dword ptr [RSP+0x20],0x0
1400033FC  JG   0x1400033CF         ; ret > 0 -> reintenta
1400033FE  ...
```

**El bucle de reintento es codigo muerto.** La instruccion `JLE` solo se toma cuando `ret <= 0`, y en `0x1400033F7` se reevalua `CMP ret, 0` con `ret <= 0`, de modo que `JG` no se toma nunca. Es un unico `recv` bloqueante, sin `MSG_WAITALL` y sin acumulacion.

Dos consecuencias practicas: una lectura parcial del servidor se interpreta como respuesta completa, que es una fragilidad real; y el buffer se pone a cero con `memset` antes de usar, de modo que queda terminado en NUL de facto, lo que evita un desbordamiento pero no por diseno.

### 5.4 Conclusion de esta fase

**No existe servidor del autor.** No hay comando y control, no hay descarga de configuracion, no hay telemetria.

El loader llama a una API REST publica de zona horaria por HTTP plano, sin TLS, usando una clave de limite de peticiones que es publica, y emplea la hora oficial de la zona `Europe/London` como reloj.

La peticion es un literal de 138 bytes sin ninguna llamada a `sprintf` que lo parametrice. **No se envia nada identificativo de la maquina**: no hay nombre de equipo, ni huella de hardware, ni usuario. No hay exfiltracion porque no hay datos que exfiltrar.

---

## 6. El PIN: un reloj, no una licencia

### 6.1 El algoritmo

La funcion `DeriveAuthCodeFromHMS` en `0x140003670` implementa la derivacion:

```c
void DeriveAuthCodeFromHMS(char *tok) {
    uint32_t h = atoi(tok);   while (*p != ':') p++;   // "14:14:56" -> 14
    uint32_t m = atoi(p);     while (*p != ':') p++;   //             -> 14
    uint32_t s = atoi(p);                                 //             -> 56

    int64_t  slot = (h * 0xE10 + m * 0x3C + s) / 0xB4;  // (3600h + 60m + s) / 180
    uint32_t code = (slot * 0x75BCD15) % 10000;          // 0x75BCD15 = 123.456.789
    sprintf(g_szDerivedAuthCode, "%04lld", abs(code));
}
```

Las constantes deserve comentario. `0xE10` es 3600, `0x3C` es 60, `0xB4` es 180: la ventana de tres minutos. Y `0x75BCD15` es exactamente `123.456.789`, los primeros digitos de pi, que es la constante multiplicadora clasica de una funcion hash de Stephen Nash. No es una clave; es un numero elegante.

Reduciendo modulo 10000, el resultado se simplifica a:

```
PIN = ( slot * 6789 ) mod 10000
```

donde `slot` son los segundos desde medianoche en Londres divididos por 180.

### 6.2 El valor esta verificado por inversion

Un modelo algoritmico no es una prueba. Se comprueba invirtiendo el Congruence. Se resuelve `6789 * slot = 2202 (mod 10000)` mediante euclides extendido, que da `6789` inverso congruente con `109` modulo `10000`:

```
slot = 109 * 2202  =  240018  =  18  (mod 10000)
```

Comprobacion directa: `18 * 123456789 = 2.222.222.202`, cuyo residuo modulo 10000 es exactamente `2202`.

**Y `slot = 18` significa `18 * 180 = 3240` segundos, es decir las 00:54:00 hora de Londres.** Un PIN de cuatro digitosseenversa a una hora exacta del dia. Eso confirma el modelo de forma independiente.

### 6.3 Lo que esto significa como diseno

| Propiedad | Valor |
|---|---|
| Secretos de servidor | **ninguno**, todo se computa desde el reloj |
| Valores posibles por dia | **480** (86399 / 180 + 1) |
| Ventana de validez | 180 segundos |
| Formato de entrada | 4 digitos, `%4s` |
| Donde se decide | **solo en el cliente**, en un `strcmp` |

La comprobacion final, literalmente:

```asm
140003601  CALL 0x140003670         ; DeriveAuthCodeFromHMS
140003616  MOV  RCX,[RSP+0x1750]    ; el PIN que tecleo el usuario
14000361E  CALL strcmp
140003623  TEST EAX,EAX
140003625  JNZ  fail
140003627  MOV  AL,0x1              ; exito
```

Y el global `g_szDerivedAuthCode` en `0x14003CEA8` es de solo escritura: sus unicas dos referencias de codigo estan dentro de la propia funcion que lo escribe. Nadie mas lo lee.

### 6.4 Que es esto en realidad

**Es un TOTP de tres minutos con el reloj publico como unico secreto.** El autor calcula el mismo valor en su pagina web y lo muestra como PIN descargable. No hay cuenta, no hay servidor, no hay estado.

Un PIN que se deriva de la hora no es un secreto, y una comprobacion que vive exclusivamente en el cliente no es una comprobacion. Cualquiera que tenga el `.exe` puede calcularlo. La pagina web `getpin-...php` es una tercera implementacion del mismo calculo, y que coincida con la del binario no anade proteccion: solo anade otra copia del mismo numero publico.

**Recomendacion practica: no hay que pagar por esto.**

---

## 7. La cadena de inyeccion

### 7.1 Abrir el objetivo

La funcion `OpenTargetAndResolveGameGlobals` en `0x140006A00`:

```c
g_hTargetProcess = OpenProcess(0x1FFFFF, FALSE, pid);     // PROCESS_ALL_ACCESS
g_pNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "NtQueryInformationProcess");
g_pNtReadVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                        "NtReadVirtualMemory");
uint64_t base = GetRemoteModuleBase("client.dll");
```

La funcion `GetRemoteModuleBase` camina la lista de modulos del proceso remoto:

```c
NtQueryInformationProcess(hProcess, 0, pbi, 0x30);      // ProcessBasicInformation -> PEB
NtReadVirtualMemory(PEB,    PEB + 0x20,  0x2A0);        // PEB_LDR_DATA
NtReadVirtualMemory(Ldr,    Ldr + 0x20,  0x58);         // InMemoryOrderModuleList
while (NtReadVirtualMemory(entry, 0xE0)) {              // LDR_DATA_TABLE_ENTRY
    comparar BaseDllName (UTF-16) con el nombre buscado
    entry = entry->Flink;
}
```

`OpenProcess` con `0x1FFFFF` es `PROCESS_ALL_ACCESS`, el permiso mas amplio posible. Requiere privilegios de administrador para aplicarse a un proceso de Steam protegido.

### 7.2 Resolucion de punteros ocultos en el juego

Una vez conocida la base del modulo, la funcion resuelve cuatro punteros globales del juego. El patron es el de un puntero escondido como desplazamiento relativo de 32 bits:

```c
// FUN_140009920, rebautizada ResolveRelocatedPtr32
longlong ResolveRelocatedPtr32(longlong addr, int a, int b) {
    uint32_t v;
    NtReadVirtualMemory(g_hTargetProcess, addr + a, &v, 4);   // lee un int32
    return (uint64_t)v + addr + b;                             // base + int32
}
```

El layout en la seccion de datos del juego es de siete bytes de cabecera seguidos del desplazamiento de 32 bits. Las cuatro llamadas usan los desplazamientos `0x21A14A`, `0x1C5990`, `0xC13E93` y `0xBA20EB` sobre la base de `client.dll`. De los cuatro, dos se desreferencian despues con una segunda lectura de 8 bytes, porque apuntan a punteros dentro del juego.

**Esto no es escaneo de firmas.** Es acceso directo a offsets fijos conocidos de la version concreta de CS2. Por eso el manual del autor dice que hay que esperar una build nueva cuando el juego se actualiza.

### 7.3 Las cinco etapas de la inyeccion

**Etapa 1: reservar y arrancar el stub.**

```asm
MOV qword ptr [RSP+0x20],0x40     ; PAGE_EXECUTE_READWRITE
MOV R9D,0x3000                    ; MEM_COMMIT | MEM_RESERVE
MOV R8D,0x20000                   ; 131072 bytes
XOR EDX,EDX                       ; direccion nula, que elija el kernel
MOV RCX,qword ptr [0x14003CE70]    ; proceso objetivo
CALL qword ptr [0x1400290A0]      ; VirtualAllocEx
```

Region de 128 KB con lectura, escritura y ejecucion desde el momento de reservarla. Sin `VirtualProtect` posterior: la proteccion es RWX desde el principio.

Se escribe un struct de `0xC0` bytes con cinco cadenas descifradas y los punteros a `GetModuleHandleA` y `GetProcAddress`, seguidos de 221 bytes de stub:

```asm
MOV qword ptr [RSP+0x20],0x0      ; lpThreadId = NULL
MOV dword ptr [RSP+0x28],0x0      ; dwCreationFlags = 0
MOV RCX,qword ptr [RSP+0x48]      ; hProcess
MOV qword ptr [RSP+0x20],RCX      ; lpParameter      = base
MOV R9,RAX                        ; lpStartAddress   = base
XOR R8D,R8D                       ; dwStackSize      = 0
XOR EDX,EDX                       ; lpThreadAttributes = NULL
CALL qword ptr [0x1400290B8]       ; CreateRemoteThread
```

**`lpStartAddress` y `lpParameter` son la misma direccion.** Es el patron classico de shellcode: el codigo ejecutado recibe su propia direccion como parametro y escribe alli un resultado. El loader lo recoge despues:

```asm
140003B1E  CALL WaitForSingleObject   ; INFINITE
140003B2C  CALL CloseHandle
140003B52  CALL ReadProcessMemory     ; 0xC0 bytes de vuelta desde base
```

Los cinco buffers del struct de `0xC0` son:

| Offset | Long. | Contenido |
|---|---|---|
| `+0x00` | 18 | slot muerto, el stub no lo lee |
| `+0x20` | 12 | `vgui2_s.dll` |
| `+0x40` | 16 | `CreateInterface` |
| `+0x60` | 14 | `VGUI_Setup001` |
| `+0x80` | 16 | `VGUI_Surface039` |
| `+0xA0` | 8 | puntero a `GetModuleHandleA` |
| `+0xA8` | 8 | puntero a `GetProcAddress` |

Es decir: el loader **no llama** a `CreateInterface`. Le pasa al stub el modulo, el nombre del export y los dos nombres de interfaz, mas los punteros a las dos funciones de la API que el stub necesita para resolverlo por su cuenta dentro del proceso objetivo.

**Etapa 2: segunda region y payload.**

```asm
MOV qword ptr [RSP+0x20],0x40
MOV R9D,0x3000
MOV R8D,0x4000                    ; 16384 bytes
CALL VirtualAllocEx               ; segunda region RWX
CALL ReadProcessMemory            ; lee un puntero desde [resultado+0xB0]
CALL operator new                 ; 0x800
CALL ReadProcessMemory            ; 2048 bytes desde ese puntero
```

**Etapa 3: cabecera de configuracion.** Se construye un bloque de `0x4620` bytes y se escribe entero en el proceso remoto. Contiene la tabla de diez features, la tabla de APIs resueltas, la ruta del registro en UTF-16, dos vectores de 256 bytes de estado de teclas, las tablas de firmas con mascara y los cuatro punteros del juego.

**Etapa 4: payload principal.** Se parchea un centinela para auto-relocacion y se escriben 17.108 bytes:

```asm
MOV  DL,0x11
LEA  RCX,[0x1400360E0]            ; blob del payload en .data
CALL FUN_140009730                ; strchr(blob, 0x11)
MOV  RCX,qword ptr [RSP+0x48]     ; base de la region
MOV  qword ptr [RAX],RCX          ; *(centinela) = base
CALL WriteProcessMemory           ; 0x42D4 bytes a base+0x4620
```

**Etapa 5: activacion y parche en caliente.**

```asm
CALL WriteProcessMemory           ; 8 bytes: &base2 dentro de cs2.exe
CALL ScanRemoteMemoryForString     ; busca la firma
ADD  RAX,2                        ; el match + 2
CALL VirtualProtectEx             ; 1 byte, PAGE_EXECUTE_READWRITE
CALL WriteProcessMemory            ; escribe un 0x00
CALL VirtualProtectEx             ; restaura la proteccion original
```

El patron buscado es una secuencia real de x86-64 con comodines:

```
41 BF ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 53 20 48 3B C2 73 0A
48 8B C8 48 2B CA 48 01 4B 30
```

Desensamblada, es `mov edi, edi` seguido de una llamada indirecta, una comparacion y una suma a un campo de una estructura: una funcion de VGUI. El parche inyecta un `0x00` en el offset mas 2, es decir un **hook en linea** de codigo del juego.

La funcion devuelve codigos de error numerados: 0 si todo va bien, 1 si no se encuentra el destino, 2 si falla `OpenProcess`, 3 si falla `VirtualAllocEx` y 4 si falla `CreateRemoteThread`.

---

## 8. El payload: analisis de capacidades

### 8.1 Que contiene

La seccion `.data` contiene cuatro blobs y nada mas:

| Blob | VA | Tamano | Entropia | Contenido |
|---|---|---|---|---|
| stub de etapa 1 | `0x140036000` | 221 B | 4.14 | bootstrap de 221 bytes |
| payload principal | `0x1400360E0` | 17.108 B | 5.01 | codigo del cheat |
| bloque de config A | `0x14003A3C0` | 1.097 B | 4.59 | biblioteca de vectores SIMD |
| bloque de config B | `0x14003A810` | 6.800 B | 4.97 | tabla de datos |

Total 25.226 bytes. Una entropia entre 4 y 5 descarta cifrado, que daria entre 7.9 y 8.0, y descarta compresion, que daria entre 7.0 y 7.9. **Ninguno de los cuatro blobs esta protegido.**

El bloque de config A se desensambla como una biblioteca de `Vector3` y `Vector4` en instrucciones SIMD:

```asm
movups xmm0, [rcx+rsi]           ; carga 16 bytes
movups xmm1, [rcx+rsi+10h]
addps  xmm0, xmm1                ; suma de vectores
movups [rcx+rdi], xmm0
...
divss  xmm0, xmm2                ; escalar divided by scalar
subss  xmm0, xmm1
cvtsi2ss xmm1, [rax+8Ch]         ; int a float
comiss xmm0, [rax+80h]           ; comparacion
```

Con los desplazamientos de campo `0x54`, `0x6C`, `0x7C`, `0x80`, `0x88`, `0x8C` y `0x90` sobre una estructura, y con pasos de 16 y 4 bytes. Es exactamente la aritmetica que necesita un aimbot: proyectar de mundo a pantalla, calcular angulos, normalizar vectores y medir distancias. **Cero E/S, cero red, cero registro, cero criptografia.**

### 8.2 El metodo de analisis

El payload se autorreferencia con un placeholder:

```asm
1400360E0  44 88 44 24 18           mov  [rsp+18h], r8d
1400360E5  48 89 54 24 10           mov  [rsp+10h], rdx
1400360EA  48 89 4C 24 08           mov  [rsp+08h], rcx
1400360EF  48 81 EC 78 04 00 00     sub  rsp, 478h
1400360F6  48 B8 11 11 11 11 11 11 11 11   mov rax, 1111111111111111h
1400360FF  48 89 44 24 40           mov  [rsp+40h], rax
```

El inmediato `0x1111111111111111` esta en el offset 24 del blob, y es exactamente lo que el loader localiza con `strchr(blob, 0x11)` y sustituye por la direccion base. Ese registro contiene **la base de la cabecera de `0x4620` bytes**, no el inicio del codigo.

De ahi se deriva el metodo: cada operando de memoria con desplazamiento de 32 bits relativo a ese registro es un acceso a la cabecera, y **la cabecera es el conjunto de capacidades**. No hay que interpretar nada: es aritmetica sobre offsets.

### 8.3 Resultados

Un barrido lineal de los 17.108 bytes arroja lo siguiente:

- **236 offsets distintos de la cabecera, 1052 accesos.** Todos dentro del rango `0x0000` a `0x461F`.
- **Cero llamadas `call` ni `jmp` indirectas con desplazamiento relativo al IP de instruccion.** No hay IAT propia, ni vtables propias, ni thunks.
- **Cero referencias a datos con desplazamiento relativo al IP de instruccion.** No hay constantes propias.
- **Un unico `MOVABS` de 64 bits en 17 KB:** el placeholder `0x1111111111111111`.

Los dos ultimos puntos son los determinantes. Si el payload construyera nombres de API o tablas de hash en tiempo de ejecucion, necesitaria cargar inmediatos de 64 bits, y no hay ninguno. Si tuviera datos propios, necesitaria referencias relativas al IP de instruccion, y no hay ninguna.

Repitiendo el analisis sobre los otros tres blobs:

| Blob | Accesos a cabecera | Llamadas indirectas | MOVABS | Datos RIP |
|---|---|---|---|---|
| stub de etapa 1 | 5 | 0 | 0 | 0 |
| payload principal | 1052 | 0 | 1 | 0 |
| config A | 9 | 0 | 0 | 0 |
| config B | 0 | 0 | 0 | 0 |

El bloque de config B con cero accesos a memoria con desplazamiento de 32 bits confirma que es dato puro y no codigo.

### 8.4 Indicadores

Un barrido adicional sobre los 25.226 bytes, buscando indicadores de compromiso, dio:

- **Cero cadenas legibles en ASCII.** Las 55 coincidencias iniciales resultaron ser fragmentos de instruccion: por ejemplo la secuencia de bytes `44 24 50 48 63 44 24 54 48`, que es el final de un `mov [rsp+50h], rax` seguido de `movsxd rax, [rsp+54h]`. Todos los prefijos REX.W producing bytes imprimibles.
- **Cero cadenas en UTF-16.**
- **Cero resoluciones de API por hash ROR13**, calculado sobre una lista de alrededor de 120 nombres de API de proceso, fichero, red, registro, criptografia, teclado y anti-depuracion. Ese es el metodo estandar de shellcode y reflective loader.
- **Cero constantes de MD5, SHA-1, SHA-256, ChaCha20 ni TEA.**
- **Cero direcciones IP en claro y cero puertos sospechosos.**

**En 25 KB de payload no hay ni una sola cadena de texto legible.** Para malware eso es extraordinario: un stealer, un dropper o un ransomware siempre deja algo, una URL, una ruta, un nombre de mutex o un nombre de API.

### 8.5 El mapa de la cabecera

| Offset | Contenido | Accesos |
|---|---|---|
| `0x0000` - `0x01B8` | tabla de diez features, cada una de `0x2C` bytes | varios |
| `0x01D0` - `0x0200` | siete punteros a funcion del juego, extraidos de una vtable | 66 |
| `0x01EA8` | puntero a la interfaz del motor | **78** |
| `0x0208` - `0x03F8` | region leida densamente, probable tabla de offsets del juego | ~450 |
| `0x00A0` | puntero a `GetModuleHandleA` | 3 |
| `0x00A8` | puntero a `GetProcAddress` | 2 |
| `0x2020` | `OpenProcess` | 1 |
| `0x2028` | `GetAsyncKeyState` | 2 |
| `0x2030` | `SendInput` | 3 |
| `0x2038` | `GetTickCount64` | 2 |
| `0x2040` | `NtReadVirtualMemory` | 25 |
| `0x2048` | `RegSetValueExW` | 1 |
| `0x2050` | `RegOpenKeyExW` | 1 |
| `0x2058` | `RegCloseKey` | 1 |
| `0x2060` | `L"Software\udtk"` en UTF-16 | 2 |
| `0x20BC` | `BYTE[256]`, flanco de bajada por codigo de tecla | 5 |
| `0x21BC` | `BYTE[256]`, estado actual por codigo de tecla | 3 |
| `0x22C0` | bandera de "ya inicializado" | 26 |
| `0x22C8` - `0x22E0` | los cuatro punteros del juego | 5 |
| `0x2388` - `0x23B4` | cluster denso, probable tabla de firmas | ~100 |
| `0x3E50` | ultimo offset tocado | 1 |

---

## 9. La demostracion de contencion

Esta es la seccion central del informe.

### 9.1 Las unicas APIs resueltas en tiempo de ejecucion

El binario hace `GetProcAddress` exactamente seis veces desde codigo de aplicacion:

| Direccion | Export resuelto | Modulo | Proposito |
|---|---|---|---|
| `0x140006ADD` | `NtQueryInformationProcess` | `ntdll.dll` | obtener el PEB del proceso remoto |
| `0x140006B59` | `NtReadVirtualMemory` | `ntdll.dll` | leer memoria del proceso remoto |
| `0x140006467` | `_itow` | `ntdll.dll` | conversion de entero a cadena |
| `0x1400064D2` | `sqrt` | `ntdll.dll` | matematicas del aimbot |
| `0x140006579` | `pow` | `ntdll.dll` | matematicas del aimbot |
| `0x140006602` | `fabs` | `ntdll.dll` | matematicas del aimbot |

Las tres ultimas resuelven funciones matematicas del CRT que `ntdll.dll` reexporta por compatibilidad. Es un detalle elegante: en vez de enlazar una biblioteca de runtime, el payload roba `sqrt`, `pow` y `fabs` de ntdll.

Las otras tres referencias a `GetProcAddress` del binario estan en el rango del UCRT y son sus envoltorios de carga diferida.

**No se resuelve ninguna API de red, de fichero, de proceso, de hilo ni de criptografia en tiempo de ejecucion.** Ninguna.

### 9.2 El conjunto de capacidades

Combinando el mapa de la cabecera con lo anterior, el payload tiene acceso a doce punteros a funcion:

| API disponible | Que puede hacer |
|---|---|
| `OpenProcess` | abrir otros procesos |
| `GetAsyncKeyState` | consultar el estado de una tecla |
| `SendInput` | inyectar entrada sintetica |
| `GetTickCount64` | reloj de alta resolucion |
| `NtReadVirtualMemory` | leer memoria de otros procesos |
| `RegSetValueExW` | escribir en el registro |
| `RegOpenKeyExW` | abrir claves del registro |
| `RegCloseKey` | cerrar claves del registro |
| `GetModuleHandleA` | localizar modulos cargados |
| `GetProcAddress` | resolver exportaciones |
| interfaz del motor | siete funciones del juego |
| cuatro punteros del juego | estructuras internas de CS2 |

**Lo que no esta en la lista:**

- Ninguna funcion de fichero. **No puede escribir en disco.**
- Ninguna funcion de red. **No puede enviar datos a ninguna parte.**
- Ninguna funcion de creacion de procesos o hilos.
- Ninguna funcion criptografica.
- Ninguna funcion de portapapeles, captura de pantalla ni inyeccion de eventos.

**El payload no tiene capacidad de exfiltracion.** No tiene ni un solo socket disponible. No tiene forma de construir un mensaje de red porque no tiene la primitiva para hacerlo.

---

## 10. Por que esto es un cheat y no malware

### 10.1 Evidencia directa

**Las cadenas del menu.** El binario contiene `Aimbot`, `Smooth`, `Hitbox`, `Trigger`, `Spotted`, `Esp`, `Theme`, `Aim Spot`, `Key`, `On`, `Off`, y la fuente `Tahoma`. Son exactamente los nombres de las opciones de un menu de cheat.

**Las tablas de configuracion.** La tabla de diez entradas con paso `0x2C` contiene los valores por defecto de cada feature:

| Entrada | Nombre | Campo 1 | Campo 2 | Campo 3 |
|---|---|---|---|---|
| 0 | (ilegible) | 0 | 1 | |
| 1 | `Aimbot` | 2 | 5 | |
| 2 | `Smooth` | 1 | 30 | 100 |
| 3 | `Hitbox` | 1 | 1 | 4 |
| 4 | `Key` | 0 | 1 | |
| 5 | `Trigger` | 2 | 6 | |
| 6 | `Aim Spot` | 0 | 0 | |
| 7 | `Esp` | 0 | 1 | |
| 8 | (ilegible) | 0 | 0 | |
| 9 | `Theme` | 1 | 1 | 30 |

Los valores son coherentes con parametros reales de un aimbot: `Smooth` con 30 sobre un maximo de 100, `Hitbox` con escala 4, `Theme` con indice.

**El manual del autor.** `Aimbot Guide.txt` describe exactamente estas opciones: "Low smooth = fast aimbot, high smooth = slow aimbot", y "Spotted es la verificacion de visibilidad de los pobres, el ESP cambiara de color cuando el enemigo sea visible". El binario contiene `Spotted` y `Esp` como features separados. La correspondencia es directa.

**La cadena del motor Source.** `vgui2_s.dll`, `CreateInterface`, `VGUI_Setup001` y `VGUI_Surface039` son el sistema de interfaces graficas del motor de Valve. El cheat se engancha ahi.

**La firma de hook.** Los bytes buscados en memoria descomponen una funcion de VGUI con una comparacion y una suma a un campo de estructura. El parche de un byte la desvía.

**El disparador de input.** `GetAsyncKeyState` y `SendInput` entregados al codigo que corre dentro del juego, mas `GetTickCount64` como reloj, son exactamente el juego de herramientas de un triggerbot: consultar si una tecla esta pulsada, generar el clic en el instante preciso y medir el intervalo. Que el `SendInput` se invoque desde el proceso del juego hace que el input pase el filtro del juego como si fuera interno.

**El bucle de teclas.** El payload recorre los 256 codigos de tecla virtual, llama a `GetAsyncKeyState` para cada uno y detecta flancos de bajada, guardando el resultado en dos vectores de 256 bytes en la cabecera. Ese es el fundamento de la deteccion de "keybind mantenido".

**El texto del propio binario.** `"Injected, press INSERT to open the menu"` y `"Injecting FREE cheat..."` no dejan lugar a duda.

### 10.2 Ausencia de comportamiento malicioso

**No toca el sistema de ficheros.** `CreateFileW`, `ReadFile` y `WriteFile` solo se llaman desde el UCRT, en el codigo de entrada y salida de consola. No hay `DeleteFile`, ni `MoveFileEx`, ni `CopyFile`, ni `CreateProcess`, ni escritura en disco de ningun tipo.

**No exfiltra.** La unica conexion saliente es una consulta a una API publica de hora, con una peticion literal de 138 bytes que no contiene datos de la maquina.

**No roba credenciales.** No hay rutas de navegadores, ni acceso a LSASS, ni `CryptUnprotectData`, ni portapapeles, ni captura de pantalla.

**No escala privilegios.** No hay manipulacion de tokens, ni creacion de servicios, ni carga de drivers, ni bypass de UAC. Pide administrador unicamente porque `OpenProcess` con todos los permisos sobre un proceso de Steam lo requiere.

**No persiste como ejecutable.** Su unico uso del registro es una clave de configuracion, y usa `RegDeleteKeyA` para **invalidar** cuando el tipo o el tamano no cuadran, no para instalar. No hay claves de autoarranque, ni tareas programadas, ni servicios.

**Endurecido, no debilitado.** El binario tiene cookies de pila y tabla de manejadores de excepciones seguros:

```
SecurityCookie  0x000000014003C2C0
SEHandlerTable   0x00000001400293A0
```

El valor `0x14003C2C0` es la misma constante de comprobacion de pila que aparece en el epilogo de todas las funciones. El malware rara vez se compila con estas protecciones porque estorban.

---

## 11. Tecnicas de anti-analisis

Cinco, y ninguna define por si sola la malicia:

1. **XOR de un byte en todas las cadenas**, descifrado en la pila, de modo que no existe texto en claro en el fichero ni en un volcado de memoria.
2. **Winsock importado por ordinal**, eliminando las cadenas `socket`, `connect`, `send` y `recv` del binario.
3. **Tablas de firmas construidas byte a byte.** El codigo escribe cada byte de los patrones con instrucciones `MOV` individuales, de forma que nunca existe un bloque contiguo de datos que un escaner pueda firmar como patron.
4. **Tabla de resolucion indirecta de punteros**, con el desplazamiento de 32 bits escondido dentro del juego en vez de una tabla legible en el loader.
5. **Compilacion con optimizacion guiada por perfil.** El directorio de depuracion registra `IMAGE_DEBUG_TYPE_POGO`, no `CODEVIEW`. Es decir, el binario fue construido con PGO, que produce codigo notably mejor optimizado y por tanto mas dificil de invertir, y **la ruta del PDB fue eliminada**, de modo que no hay atribucion por entorno de compilacion.

---

## 12. Auditoria de la estructura PE

| Seccion | Flags | Permisos | Estandar MSVC |
|---|---|---|---|
| `.text` | `0x60000020` | codigo, ejecucion, lectura | identico |
| `.rdata` | `0x40000040` | datos, lectura | identico |
| `.data` | `0xC0000040` | datos, lectura, escritura | identico |
| `.pdata` | `0x40000040` | datos, lectura | identico |
| `.reloc` | `0x42000040` | datos, descartable, lectura | normal |

**Ninguna seccion con escritura y ejecucion simultaneas.**

| Directorio | Valor | Nota |
|---|---|---|
| TLS | `0x0` | **vacio, sin callbacks** |
| Overlay | ninguno | el fichero acaba donde acaba la ultima seccion |
| Export | `0x0` | |
| Resource | `0x0` | sin recursos incrustados |
| BoundImport | `0x0` | |
| DelayImport | `0x0` | |
| CLR | `0x0` | no es .NET |

**No hay callbacks TLS**, que son la via estandar de ejecucion de codigo antes de `main` y la forma mas comun de anti-depuracion persistente. **No hay overlay**, lo que descarta de raiz la tecnica de dropper con carga embebida al final del fichero. Las protecciones de imagen activas son ASLR, DEP y `TERMINAL_SERVER_AWARE`, sin `NO_SEH` y sin CFG.

### 12.1 Sobre el patron del bloque de config B

El bloque de 6.800 bytes presenta 809 apariciones del valor de 4 bytes `0x00FFFFFF`. El analisis de la distribucion muestra que **no es un valor repetido**, sino la secuencia de bytes `FF FF FF 00` repetida:

```
bytes 0xFF:  2555  (37.6 por ciento)
bytes 0x00:   994  (14.6 por ciento)
rachas consecutivas de 0xFF:  937
   de las cuales 809 de longitud 3, y 128 de longitud 1
```

Es una **tabla dispersa**: 809 entradas con el marcador de vacio `FF FF FF 00` y 128 entradas pobladas con datos reales. Encaja exacto con las posiciones: el bloque se copia a la cabecera en el offset `0x23C0`, y `0x23C0 + 0x1A90 = 0x3E50`, que es el ultimo offset que toca el payload.

Una tabla de 128 entradas pobladas con 809 huecos vacios es exactamente lo que se espera de una tabla de offsets de entidades y huesos de un motor de juego. Un malware que prepara terreno no deja un 52 por ciento de marcadores de vacio.

---

## 13. Veredicto

**`undetek.exe` v10.51 no es malware.**

La conclusion se sostiene sobre tres pilares, todos verificables:

1. **Contencion de capacidades.** El payload no tiene IAT propia, ni constantes propias, ni resuelve APIs por hash, y todas sus capacidades se reducen a doce punteros que el loader le entrega. No tiene ninguna primitiva de red, de fichero ni de proceso. **No puede exfiltrar.**

2. **Ausencia de comportamiento malicioso en el loader.** Sin escritura en disco, sin exfiltracion, sin robo de credenciales, sin escalada de privilegios, sin persistencia como ejecutable, y con protecciones de pila y SEH activas.

3. **Evidencia positiva de cheat.** Cadenas del menu, tabla de diez features con valores por defecto coherentes, resolucion de interfaces del motor de Valve, hook en linea sobre una funcion de VGUI, disparador de input dentro del proceso del juego, y un mensaje de exito que dice literalmente que se ha inyectado un cheat.

### 13.1 Lo que si es un riesgo

**El riesgo mayor no es este binario.** Es la guia de instalacion que lo acompaña:

```
1. Turn off windows defender
2. Turn off windows defender firewall
3. Turn off smartscreen (app and browser control)
4. Turn UAC to a low setting.
5. Turn off Valorant Anticheat.
6. Turn off FACEIT Anticheat.
```

Desactivar el antivirus, el firewall, SmartScreen, el control de cuentas de usuario y los anticheats de terceros para ejecutar un ejecutable de un vendedor anonimo **es el vector de entrada real del malware para jugadores**, mucho mas que cualquier bytecode concreto. Ese es el canal por el que se distribuye malware para esta plataforma, y aqui llega con instrucciones paso a paso.

**El PIN no es una licencia** y no debe pagarse por el. Es una funcion del reloj publico, sin secreto de servidor, con 480 valores posibles por dia y la misma respuesta para todos los usuarios a la vez.

**Legal.** Inyectar codigo en Counter-Strike 2 viola las condiciones de servicio de Valve. El riesgo de bloqueo permanente de VAC es del usuario, no del autor del loader.

### 13.2 Limitaciones del metodo

Conviene ser explicito sobre lo que este analisis **no** demuestra:

- **El analisis de capacidades es un barrido lineal de operandos de memoria, no un desensamblador.** Puede perder sincronizacion, y se ha observado que lo hace: los accesos "fuera de la cabecera" que produce en una de las etapas son valores que contienen bytes de opcode de x86, es decir artefactos del parser. Es evidencia fuerte, no prueba formal.

- **La logica del aimbot no se ha reconstruido.** Se han identificado las variables de estado de teclas, la resolucion de interfaces y la biblioteca de vectores, pero no la matematica concreta de prediccion, campo de vision o compensacion de retroceso.

- **El payload tiene `GetModuleHandleA` y `GetProcAddress` disponibles.** Podria resolver cualquier API en tiempo de ejecucion si quisiera. Para hacerlo necesitaria nombres, y no hay cadenas, ni hashes, ni inmediatos de 64 bits en los 17 KB. Lo unico que no puede descartarse sin desensamblado completo es que construyera un nombre byte a byte en la pila con inmediatos de 8 bits, que el barrido no veria. Es la misma tecnica que usa el propio loader con sus 51 descifradores, asi que no es descartable de forma teorica.

- **Dos cadenas de texto se identificaron por longitud y no por lectura directa**, por lo que su contenido literal puede diferir en un caracter.

---

## 14. Indicadores de compromiso

```
MD5     47cdf077d83b9e8c8b80364d2dbd9527
SHA-1   77468f710e2d45fcbab758a6beb8590e767d79be
SHA-256 82eb05556ffe1597e40353a0faef69e78f072d14e671adbf360c2161c06a8276

Red observada (unica):
  vip.timezonedb.com:80        API publica de zona horaria, GET HTTP
  clave de la API: <redactada>
  ruta: /v2.1/get-time-zone

Registro:
  HKEY_CURRENT_USER\Software\udtk
  valor por defecto (sin nombre), REG_BINARY, 440 bytes

Objetivo:
  procesos:  cs2.exe, gameoverlayui64.exe
  modulos:   client.dll, vgui2_s.dll, ntdll.dll
  simbolos:  CreateInterface, VGUI_Setup001, VGUI_Surface039

Cadenas en claro en el binario: NINGUNA, todas cifradas con XOR 0x34
```

Que un analisis antivirus marque este fichero como `Trojan.Win32.Generic` es esperable: la asignacion de memoria con ejecucion y escritura simultaneas mas la carga reflectiva mas la inyeccion en otro proceso son exactamente los heuristicos que disparan los motores. Este informe explica por que saltan aqui y en que se diferencian de una infeccion real: un Troyano real tiene cadenas, sockets y ficheros de los que este binario no tiene nada.

---

## 15. Conclusiones

Un loader de cheat y un malware se parecen mucho en la superficie: reservan memoria ejecutable, escriben en la memoria de otro proceso, crean un hilo remoto y resuelven simbolos en tiempo de ejecucion. Por eso un analisis unicamente basado en indicadores heuristicos no puede separarlos, y por eso este caso merece un analisis estatico completo.

Lo que separa este binario de un Troyano son tres cosas concretas y verificables.

**La primera es la contencion de capacidades.** El payload no tiene ninguna primitiva de red ni de fichero. Eso no es una propiedad de "parece limpio"; es una lista cerrada de doce punteros a funcion derivada de los desplazamientos reales de las instrucciones. Un Troyano necesita salir de la maquina; este no puede.

**La segunda es la ausencia de_strings_.** Veinticinco kilobytes de payload sin una sola cadena legible es practicamente inaudito en malware. Cuando el codigo necesita unabasic `socket` o una ruta, deja un rastro. Aqui todo pasa por punteros que el loader entrega ya resueltos.

**La tercera es la coherencia interna.** El binario contiene los nombres de las features, los valores por defecto de esas features, la resolucion de las interfaces del motor de Valve, un hook sobre una funcion de ese motor, y mensajes que dicen que se ha inyectado un cheat. Todo apunta en la misma direccion y nada apunta en la contraria.

Queda una lesson para el usuario final que es mas importante que el veredicto tecnico: **el riesgo real de un binario de este tipo no es lo que hace, sino lo que hay que desactivar para poder usarlo.** Un ejecutable que exige apagar el antivirus, el firewall y el control de cuentas antes de correr es, en si mismo, un indicador de compromiso mucho mas fuerte que cualquier analisis estatico.

Y una nota sobre el PIN, que es el hallazgo mas instructivo del analisis desde el punto de vista del diseno de software: **un secreto que se deriva del reloj no es un secreto.** El autor implemento un TOTP con el reloj publico como unica entrada, y el resultado es que cualquier usuario puede calcular su propia licencia. La ofuscacion de las cadenas, los imports por ordinal y la compilacion con optimizacion guiada por perfil son esfuerzo serio en una sola direccion, y al mismo tiempo la logica de autorizacion es trivialmente invertible. Son cosas que no se ven a la vez.

---

## Agradecimientos

Este analisis se realizo con la asistencia de **opencode**, en el marco de un modelo operado por **Space Bunny** con **Claude Sonnet 5.5**, usando el servidor MCP de Ghidra para el desensamblado y la ingenieria inversa, y scripts propios en Python para el volcado de cadenas, la extraccion de indicadores y el analisis de capacidades.

El trabajo de los modelos de lenguaje fue la parte mecanica: descifrar cadenas, enumerar referencias cruzadas, correlacionar longitudes de blob con contenido y aplicar transformaciones aritmeticas. **Las decisiones sobre que es evidencia y que es hipotesis, y sobre donde estan los limites del metodo, fueron del analista humano.** Los cuatro fallos de instrumentacion documentados en la seccion 3 son tambien parte del registro, porque un informe de analisis sin sus errores no es auditable.

---

*Analisis realizado exclusivamente por medios estaticos. El binario no fue ejecutado en ningun momento. Herramientas: Ghidra con servidor MCP, y utilidades propias en Python estandar sin dependencias externas.*