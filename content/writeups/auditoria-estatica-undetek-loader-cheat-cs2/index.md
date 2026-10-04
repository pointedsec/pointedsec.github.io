+++
author = "Andrés Del Cerro"
title = "Auditoría estática de undetek.exe v10.51: anatomía de un loader de cheat para CS2"
date = "2026-10-03T14:00:00+01:00"
description = "Análisis completo, función a función y byte a byte, de un loader de cheat para Counter-Strike 2: cadena de inyección, descifrado de strings, el C2 que resultó ser una API pública de hora, y una demostración de contención de capacidades que permite descartarlo como malware."
tags = [
    "reverse-engineering",
    "malware-analysis",
    "static-analysis",
    "x86-64",
    "counter-strike-2",
    "triage"
]
+++

# Auditoría estática de undetek.exe v10.51

> **TL;DR.** `undetek.exe` es un loader de cheat para Counter-Strike 2. **No es malware.** Se demuestra porque su payload, 25.226 bytes auditados al 100%, no tiene IAT propia, ni constantes propias, ni una sola cadena de texto legible, ni resuelve APIs por hash, y todas sus capacidades se reducen a 12 punteros a función que el loader le entrega. No puede escribir en disco, no puede crear procesos y **no tiene forma de enviar datos a ninguna parte**.
>
> En paralelo se descubre que la "licencia" del producto es un PIN derivado del reloj público, que cualquiera con el `.exe` puede calcular. Y que el riesgo real para el usuario no es este binario, sino la guía que le pide desactivar el antivirus.

Este documento recoge el análisis completo. Cada afirmación lleva su evidencia y, donde la evidencia es incompleta, se dice de forma explícita. También se documentan los errores del propio analista, porque un informe que no cuenta sus fallos no es fiable.

---

## 1. La muestra

| | |
|---|---|
| **Ruta** | `/home/kali/Desktop/undetek/undetek-v10.51/undetek.exe` |
| **MD5** | `47cdf077d83b9e8c8b80364d2dbd9527` |
| **SHA-1** | `77468f710e2d45fcbab758a6beb8590e767d79be` |
| **SHA-256** | `82eb05556ffe1597e40353a0faef69e78f072d14e671adbf360c2161c06a8276` |
| **Formato** | PE32+ (x86-64), Microsoft Visual C++ |
| **CRT** | Universal C Runtime enlazado estáticamente |
| **Empaquetado** | Ninguno. Sin packer, sin secciones ejecutables anómalas |
| **Secciones** | `.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `.reloc` |
| **Timestamp** | `0x6AC0B92E` |
| **Compilacion** | ImageBase `0x140000000`, entrypoint RVA `0xA5F4` |

El directorio también incluía cuatro ficheros de texto del propio vendedor: `Aimbot Guide.txt`, `Install Guide.txt`, `VAC.txt`, `capa.txt`. Los tres primeros se usan en este análisis como contexto declarativo, es decir, para contrastar lo que el código hace con lo que el autor dice que hace. El cuarto es un informe generado automáticamente por la herramienta capa y se trata aparte, porque tiene falsos positivos.

### 1.1 Restricción metodológica

**El binario nunca se ejecutó.** Todo el análisis es estático. Esto tiene dos consecuencias que se repiten a lo largo del documento:

1. Lo que solo existe en tiempo de ejecución, es decir el payload descifrado dentro del proceso remoto, es inaccesible por definición para el análisis estático convencional.
2. El payload se auditó por extracción de indicadores y análisis de capacidades, no por desensamblado semántico completo.

**Cobertura real:** 100 por ciento de los bytes del loader, y 100 por ciento de los 25.226 bytes del payload mediante el método de capacidades descrito en la sección 8, con las limitaciones declaradas en la sección 12.

---

## 2. Inventario

El binario contiene aproximadamente 760 funciones. La descomposición:

| Rango | Funciones | Naturaleza |
|---|---|---|
| `0x140007150` - `0x140028F10` | ~650 | Universal C Runtime y vcruntime estáticos |
| `0x140001000` - `0x1400037D0` | ~87 | Helpers de ofuscación, cliente de red, inyector |
| `0x140006A00` - `0x140007470` | ~12 | Módulo principal, E/S de consola |
| Aisladas | ~10 | Enumeración de procesos, envoltorios de syscalls |

El punto de entrada es `entry` en `0x14000A5F4`, que invoca `__scrt_common_main_seh` en `0x14000A478`, que a su vez invoca `main` en `0x140007270`. La confirmación es una única referencia de código desde `0x14000A57F`.

### 2.1 Imports de aplicación

**Kernel32, explícitos:** `VirtualAllocEx`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `OpenProcess`, `CreateRemoteThread`, `WaitForSingleObject`, `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `GetModuleHandleA`, `GetProcAddress`, `GetTickCount64`, `CloseHandle`, `Sleep`, `GetLastError`.

**USER32:** `GetAsyncKeyState` y `SendInput`. Importadas pero, como se verá, nunca invocadas por el loader.

**ADVAPI32:** `RegCreateKeyExA`, `RegSetValueExA`, `RegQueryValueExA`, `RegDeleteKeyA`, `RegOpenKeyExA`, `RegOpenKeyExW`, `RegCloseKey`, `RegSetValueExW`.

**WS2_32, importado por ordinal y no por nombre:**

```
Ordinal_3    Ordinal_4    Ordinal_16   Ordinal_19
Ordinal_23   Ordinal_111  Ordinal_115  Ordinal_116
getaddrinfo  freeaddrinfo        (estos dos, por nombre)
```

El conjunto de ordinales {3, 4, 16, 19, 23} corresponde a `closesocket`, `connect`, `recv`, `send` y `socket`. El par {115, 116} corresponde a `WSAStartup` y `WSACleanup`. El paso 111 es `WSAGetLastError`. La identificación se confirma en el descompilado, donde aparece `WSAStartup(MAKEWORD(2, 2))` con el valor `0x202`.

**Importar Winsock por ordinal es una decisión deliberada de anti-análisis.** Elimina del binario las cadenas `socket`, `connect`, `send` y `recv`, que son exactamente lo que un motor heurístico busca. Conviene subrayar que esta técnica es usada tanto por malware como por inyectores legítimos, y por sí sola no constituye un indicador.

---

## 3. Nota sobre el método: los errores del analista

Antes de entrar en el binario, conviene registrar los cuatro fallos cometidos durante este análisis, porque ilustran los límites del trabajo puramente estático con herramientas caseras:

1. **Desensamblador propio con las instrucciones partidas.** El primer intento de desensamblar el stub de 221 bytes produjo una salida en la que las instrucciones se cortaban por la mitad, por un error en el cálculo de ModRM e inmediatos. Se detectó al leer el código Assembly a mano y comparar.
2. **Bucle infinito en un parser de x86-64.** El script de análisis de capacidades se quedaba colgado porque, cuando el byte actual no era ni un prefijo ni un opcode reconocido, el índice no avanzaba. Se manifestó como un cuelgue sin salida, no como un error.
3. **Tabla de flags de sección equivocada.** Los valores `IMAGE_SCN_MEM_*` estaban desplazados una posición, de modo que `.text` aparecía como lectura y escritura en lugar de ejecución y lectura. La conclusión correcta, ninguna sección tiene W+X, se alcanzó solo al comparar los valores brutos con los estándar de MSVC.
4. **Estructura mal formada al leer el directorio de depuración.** Se uso un campo de 1 byte donde la especificación exige 4, lo que desplaza la interpretación de todo el registro.

Los cuatro son fallos de instrumentación, es decir, de no tener una suite de referencia con la que validar las herramientas propias. Es la lección práctica: cuando se escribe un desensamblador a mano para un análisis puntual, hay que contrastarlo con un desensamblador real antes de fiarse de el.

---

## 4. Ofuscación de cadenas

### 4.1 El mecanismo

Todas las cadenas del loader están cifradas con XOR de un solo byte. La plantilla es idéntica en las 51 funciones:

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

Tres parámetros por cadena: dirección del blob cifrado, longitud y clave. La clave es `0x34` en todos los casos observados. Existe una variante de cadena ancha que lee `*(ushort*)(blob + i * 2) ^ 0x34`, y una función aparte, `XorDecodeWideInPlace`, que aplica el mismo XOR de 16 bits sobre un buffer ya colocado en su destino.

El ciclo de vida de cada cadena es siempre el mismo y no deja rastro en memoria estática:

```asm
LEA  RCX,[RSP+0x49A8]        ; buffer local en la pila
MOV  ECX,0x15                ; tamaño
STOSB.REP RDI                ; memset a cero
CALL FUN_140001250           ; helper de memset, devuelve el puntero
CALL FUN_140001D20           ; descifrador, escribe aquí
```

Las 51 funciones de descifrado ocupan el rango `0x1400014B0` a `0x140003010`, con paso constante de `0x90`. Aparte hay 32 helpers de `memset` de tamaño fijo en `0x140001000` a `0x140001490`.

El descifrado en la pila es deliberado: un volcado de memoria del fichero jamás revela el texto, y un escáner de cadenas del antivirus no tiene nada que detectar.

### 4.2 Recuperación de las cadenas

La clave del proceso está en cómo Ghidra nombra los símbolos. Cuando un blob está definido como cadena, el descompilador lo renderiza con el nombre del símbolo incluyendo el texto cifrado, por ejemplo `PTR_s_R_FYU__QP4_1400297D8`. Descifrar es restar `0x34`.

La verificación cruzada se hizo con dos casos independientes:

```
blob "R[FYU@@QP4"            ->  f o r m a t t e d \0   = "formatted"
blob "z@eAQFM}ZR[FYU@][ZdF[WQGG4"
                             ->  NtQueryInformationProcess     (24 caracteres)
blob "g[R@CUFQhAP@_4"       ->  S o f t w a r e \ u d t k \0 = "Software\udtk"
```

Veinticuatro caracteres correctos de forma consecutiva no son casualidad. Eso valida la clave más allá de la suposición.

Para los blobs que Ghidra no tenía indexados, se escribió una herramienta que hace fuerza bruta: aplica XOR `0x34` a la sección `.rdata` completa y extrae rachas de bytes imprimibles, tanto en ASCII como en UTF-16. Así se recuperaron alrededor de 35 cadenas adicionales.

### 4.3 Las cadenas recuperadas

**Infraestructura:**

| Contenido | Uso |
|---|---|
| `formatted` | nombre de campo JSON de la API de hora, no un marcador de protocolo |
| `vip.timezonedb.com` | host, 19 bytes: 18 más NUL |
| `80` | puerto, 3 bytes: 2 más NUL |
| `GET /v2.1/get-time-zone?key=<API_KEY_REDACTED>&format=json&by=zone&zone=Europe/London HTTP/1.1\r\nHost: vip.timezonedb.com\r\nConnection: close\r\n\r\n` | petición, 138 bytes literales |
| `%04lld` | formato del `sprintf` que genera el PIN |
| `%4s` | formato del `scanf` que lee el PIN |
| `Software\udtk` | clave de registro, 14 caracteres |

**Módulos y exportaciones:**

| Contenido | Uso |
|---|---|
| `cs2.exe` | proceso objetivo secundario, 8 bytes |
| `gameoverlayui64.exe` | proceso objetivo principal, 19 bytes |
| `ntdll.dll` | módulo de las APIs de bajo nivel y de las matemáticas |
| `client.dll` | módulo del juego del que se extrae la base |
| `vgui2_s.dll` | módulo de la interfaz gráfica |
| `NtQueryInformationProcess` | resuelta por nombre desde ntdll |
| `NtReadVirtualMemory` | resuelta por nombre desde ntdll |
| `CreateInterface` | Fábrica de interfaces del motor |
| `VGUI_Setup001` | interfaz 1 |
| `VGUI_Surface039` | interfaz 2 |
| `_itow`, `sqrt`, `pow`, `fabs` | matemáticas del CRT reexportadas por ntdll |

**Configuración del cheat:**

| Contenido | Tipo |
|---|---|
| `Aimbot`, `Smooth`, `Hitbox`, `Trigger`, `Spotted`, `Esp`, `Theme` | features |
| `Aim Spot`, `Key` | opciones del menú |
| `On`, `Off` | valores de interruptor |
| `Tahoma` | fuente del menú |
| `41 BF ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 53 20 48 3B C2 73 0A 48 8B C8 48 2B CA 48 01 4B 30` | firma de bytes buscada en memoria |

Las 51 funciones de descifrado quedaron identificadas y renombradas con su contenido real.

---

## 5. La red: el C2 que no era un C2

### 5.1 Lo que parecía

El perfil estático encajaba con un canal de comando y control. La función `C2_AuthExchange` en `0x140003030` confirma el patrón completo, con toda la API de Winsock importada por ordinal:

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

Los parámetros de `hints` se leen directamente del descompilado:

```asm
MOV dword ptr [RSP+0xBC],0x0     ; ai_flags      = 0
MOV dword ptr [RSP+0xC0],0x1     ; ai_socktype   = SOCK_STREAM
MOV dword ptr [RSP+0xC4],0x6     ; ai_protocol   = IPPROTO_TCP
```

Y el `send` es una llamada única, sin bucle de reintento:

```asm
140003343  CALL 0x140001370            ; memset
14000334B  CALL 0x140002500            ; descifrar la petición (138 bytes)
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
petición =
  GET /v2.1/get-time-zone?key=<API_KEY_REDACTED>&format=json&by=zone
  &zone=Europe/London HTTP/1.1\r\n
  Host: vip.timezonedb.com\r\n
  Connection: close\r\n\r\n
```

Y el supuesto "marcador de protocolo" que el cliente exige encontrar en la respuesta es la cadena `formatted`.

**`formatted` no es un marcador de protocolo propio. Es el nombre de un campo de la respuesta JSON de timezonedb.com:**

```json
{"country":"GB","countryName":"United Kingdom","región":"England",
 "city":"London","zone":"Europe/London","abbreviation":"BST",
 "dst":true,"offset":3600,"currenttime":1759248896,
 "formatted":"2026-05-31 14:14:56"}
```

El `strstr(respuesta, "formatted")` busca ese nombre de campo. El código parsea después la hora, la trata como `HH:MM:SS` y deriva de ella un número.

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

**El bucle de reintento es código muerto.** La instrucción `JLE` solo se toma cuando `ret <= 0`, y en `0x1400033F7` se reevalúa `CMP ret, 0` con `ret <= 0`, de modo que `JG` no se toma nunca. Es un único `recv` bloqueante, sin `MSG_WAITALL` y sin acumulación.

Dos consecuencias prácticas: una lectura parcial del servidor se interpreta como respuesta completa, que es una fragilidad real; y el buffer se pone a cero con `memset` antes de usar, de modo que queda terminado en NUL de facto, lo que evita un desbordamiento pero no por diseño.

### 5.4 Conclusión de esta fase

**No existe servidor del autor.** No hay comando y control, no hay descarga de configuración, no hay telemetría.

El loader llama a una API REST pública de zona horaria por HTTP plano, sin TLS, usando una clave de límite de peticiones que es pública, y emplea la hora oficial de la zona `Europe/London` como reloj.

La petición es un literal de 138 bytes sin ninguna llamada a `sprintf` que lo parametrice. **No se envía nada identificativo de la máquina**: no hay nombre de equipo, ni huella de hardware, ni usuario. No hay exfiltración porque no hay datos que exfiltrar.

---

## 6. El PIN: un reloj, no una licencia

### 6.1 El algoritmo

La función `DeriveAuthCodeFromHMS` en `0x140003670` implementa la derivación:

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

Las constantes merecen comentario. `0xE10` es 3600, `0x3C` es 60, `0xB4` es 180: la ventana de tres minutos. Y `0x75BCD15` es exactamente `123.456.789`, los primeros dígitos de pi, que es la constante multiplicadora clásica de una función hash de Stephen Nash. No es una clave; es un número elegante.

Reduciendo módulo 10000, el resultado se simplifica a:

```
PIN = ( slot * 6789 ) mod 10000
```

donde `slot` son los segundos desde medianoche en Londres divididos por 180.

### 6.2 El valor está verificado por inversión

Un modelo algorítmico no es una prueba. Se comprueba invirtiendo la congruencia. Se resuelve `6789 * slot = 2202 (mod 10000)` mediante euclides extendido, que da `6789` inverso congruente con `109` módulo `10000`:

```
slot = 109 * 2202  =  240018  =  18  (mod 10000)
```

Comprobación directa: `18 * 123456789 = 2.222.222.202`, cuyo residuo módulo 10000 es exactamente `2202`.

**Y `slot = 18` significa `18 * 180 = 3240` segundos, es decir las 00:54:00 hora de Londres.** Un PIN de cuatro dígitos se convierte en una hora exacta del día. Eso confirma el modelo de forma independiente.

### 6.3 Lo que esto significa como diseño

| Propiedad | Valor |
|---|---|
| Secretos de servidor | **ninguno**, todo se computa desde el reloj |
| Valores posibles por día | **480** (86399 / 180 + 1) |
| Ventana de validez | 180 segundos |
| Formato de entrada | 4 dígitos, `%4s` |
| Dónde se decide | **solo en el cliente**, en un `strcmp` |

La comprobación final, literalmente:

```asm
140003601  CALL 0x140003670         ; DeriveAuthCodeFromHMS
140003616  MOV  RCX,[RSP+0x1750]    ; el PIN que tecleo el usuario
14000361E  CALL strcmp
140003623  TEST EAX,EAX
140003625  JNZ  fail
140003627  MOV  AL,0x1              ; éxito
```

Y el global `g_szDerivedAuthCode` en `0x14003CEA8` es de solo escritura: sus únicas dos referencias de código están dentro de la propia función que lo escribe. Nadie más lo lee.

### 6.4 Qué es esto en realidad

**Es un TOTP de tres minutos con el reloj público como único secreto.** El autor calcula el mismo valor en su página web y lo muestra como PIN descargable. No hay cuenta, no hay servidor, no hay estado.

Un PIN que se deriva de la hora no es un secreto, y una comprobación que vive exclusivamente en el cliente no es una comprobación. Cualquiera que tenga el `.exe` puede calcularlo. La página web `getpin-...php` es una tercera implementación del mismo cálculo, y que coincida con la del binario no añade protección: solo añade otra copia del mismo número público.

**Recomendacion práctica: no hay que pagar por esto.**

---

## 7. La cadena de inyección

### 7.1 Abrir el objetivo

La función `OpenTargetAndResolveGameGlobals` en `0x140006A00`:

```c
g_hTargetProcess = OpenProcess(0x1FFFFF, FALSE, pid);     // PROCESS_ALL_ACCESS
g_pNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "NtQueryInformationProcess");
g_pNtReadVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                        "NtReadVirtualMemory");
uint64_t base = GetRemoteModuleBase("client.dll");
```

La función `GetRemoteModuleBase` camina la lista de módulos del proceso remoto:

```c
NtQueryInformationProcess(hProcess, 0, pbi, 0x30);      // ProcessBasicInformation -> PEB
NtReadVirtualMemory(PEB,    PEB + 0x20,  0x2A0);        // PEB_LDR_DATA
NtReadVirtualMemory(Ldr,    Ldr + 0x20,  0x58);         // InMemoryOrderModuleList
while (NtReadVirtualMemory(entry, 0xE0)) {              // LDR_DATA_TABLE_ENTRY
    comparar BaseDllName (UTF-16) con el nombre buscado
    entry = entry->Flink;
}
```

`OpenProcess` con `0x1FFFFF` es `PROCESS_ALL_ACCESS`, el permiso más amplio posible. Requiere privilegios de administrador para aplicarse a un proceso de Steam protegido.

### 7.2 Resolución de punteros ocultos en el juego

Una vez conocida la base del módulo, la función resuelve cuatro punteros globales del juego. El patrón es el de un puntero escondido como desplazamiento relativo de 32 bits:

```c
// FUN_140009920, rebautizada ResolveRelocatedPtr32
longlong ResolveRelocatedPtr32(longlong addr, int a, int b) {
    uint32_t v;
    NtReadVirtualMemory(g_hTargetProcess, addr + a, &v, 4);   // lee un int32
    return (uint64_t)v + addr + b;                             // base + int32
}
```

El layout en la sección de datos del juego es de siete bytes de cabecera seguidos del desplazamiento de 32 bits. Las cuatro llamadas usan los desplazamientos `0x21A14A`, `0x1C5990`, `0xC13E93` y `0xBA20EB` sobre la base de `client.dll`. De los cuatro, dos se desreferencian después con una segunda lectura de 8 bytes, porque apuntan a punteros dentro del juego.

**Esto no es escaneo de firmas.** Es acceso directo a offsets fijos conocidos de la versión concreta de CS2. Por eso el manual del autor dice que hay que esperar una build nueva cuando el juego se actualiza.

### 7.3 Las cinco etapas de la inyección

**Etapa 1: reservar y arrancar el stub.**

```asm
MOV qword ptr [RSP+0x20],0x40     ; PAGE_EXECUTE_READWRITE
MOV R9D,0x3000                    ; MEM_COMMIT | MEM_RESERVE
MOV R8D,0x20000                   ; 131072 bytes
XOR EDX,EDX                       ; dirección nula, que elija el kernel
MOV RCX,qword ptr [0x14003CE70]    ; proceso objetivo
CALL qword ptr [0x1400290A0]      ; VirtualAllocEx
```

Región de 128 KB con lectura, escritura y ejecución desde el momento de reservarla. Sin `VirtualProtect` posterior: la protección es RWX desde el principio.

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

**`lpStartAddress` y `lpParameter` son la misma dirección.** Es el patrón clásico de shellcode: el código ejecutado recibe su propia dirección como parámetro y escribe allí un resultado. El loader lo recoge después:

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

Es decir: el loader **no llama** a `CreateInterface`. Le pasa al stub el módulo, el nombre del export y los dos nombres de interfaz, más los punteros a las dos funciones de la API que el stub necesita para resolverlo por su cuenta dentro del proceso objetivo.

**Etapa 2: segunda región y payload.**

```asm
MOV qword ptr [RSP+0x20],0x40
MOV R9D,0x3000
MOV R8D,0x4000                    ; 16384 bytes
CALL VirtualAllocEx               ; segunda región RWX
CALL ReadProcessMemory            ; lee un puntero desde [resultado+0xB0]
CALL operator new                 ; 0x800
CALL ReadProcessMemory            ; 2048 bytes desde ese puntero
```

**Etapa 3: cabecera de configuración.** Se construye un bloque de `0x4620` bytes y se escribe entero en el proceso remoto. Contiene la tabla de diez features, la tabla de APIs resueltas, la ruta del registro en UTF-16, dos vectores de 256 bytes de estado de teclas, las tablas de firmas con máscara y los cuatro punteros del juego.

**Etapa 4: payload principal.** Se parchea un centinela para auto-relocación y se escriben 17.108 bytes:

```asm
MOV  DL,0x11
LEA  RCX,[0x1400360E0]            ; blob del payload en .data
CALL FUN_140009730                ; strchr(blob, 0x11)
MOV  RCX,qword ptr [RSP+0x48]     ; base de la región
MOV  qword ptr [RAX],RCX          ; *(centinela) = base
CALL WriteProcessMemory           ; 0x42D4 bytes a base+0x4620
```

**Etapa 5: activación y parche en caliente.**

```asm
CALL WriteProcessMemory           ; 8 bytes: &base2 dentro de cs2.exe
CALL ScanRemoteMemoryForString     ; busca la firma
ADD  RAX,2                        ; el match + 2
CALL VirtualProtectEx             ; 1 byte, PAGE_EXECUTE_READWRITE
CALL WriteProcessMemory            ; escribe un 0x00
CALL VirtualProtectEx             ; restaura la protección original
```

El patrón buscado es una secuencia real de x86-64 con comodines:

```
41 BF ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 53 20 48 3B C2 73 0A
48 8B C8 48 2B CA 48 01 4B 30
```

Desensamblada, es `mov edi, edi` seguido de una llamada indirecta, una comparación y una suma a un campo de una estructura: una función de VGUI. El parche inyecta un `0x00` en el offset más 2, es decir un **hook en línea** de código del juego.

La función devuelve códigos de error numerados: 0 si todo va bien, 1 si no se encuentra el destino, 2 si falla `OpenProcess`, 3 si falla `VirtualAllocEx` y 4 si falla `CreateRemoteThread`.

---

## 8. El payload: análisis de capacidades

### 8.1 Qué contiene

La sección `.data` contiene cuatro blobs y nada más:

| Blob | VA | Tamaño | Entropía | Contenido |
|---|---|---|---|---|
| stub de etapa 1 | `0x140036000` | 221 B | 4.14 | bootstrap de 221 bytes |
| payload principal | `0x1400360E0` | 17.108 B | 5.01 | código del cheat |
| bloque de config A | `0x14003A3C0` | 1.097 B | 4.59 | biblioteca de vectores SIMD |
| bloque de config B | `0x14003A810` | 6.800 B | 4.97 | tabla de datos |

Total 25.226 bytes. Una entropía entre 4 y 5 descarta cifrado, que daría entre 7.9 y 8.0, y descarta compresion, que daría entre 7.0 y 7.9. **Ninguno de los cuatro blobs está protegido.**

El bloque de config A se desensambla como una biblioteca de `Vector3` y `Vector4` en instrucciones SIMD:

```asm
movups xmm0, [rcx+rsi]           ; carga 16 bytes
movups xmm1, [rcx+rsi+10h]
addps  xmm0, xmm1                ; suma de vectores
movups [rcx+rdi], xmm0
...
divss  xmm0, xmm2                ; escalar dividido por escalar
subss  xmm0, xmm1
cvtsi2ss xmm1, [rax+8Ch]         ; int a float
comiss xmm0, [rax+80h]           ; comparación
```

Con los desplazamientos de campo `0x54`, `0x6C`, `0x7C`, `0x80`, `0x88`, `0x8C` y `0x90` sobre una estructura, y con pasos de 16 y 4 bytes. Es exactamente la aritmética que necesita un aimbot: proyectar de mundo a pantalla, calcular ángulos, normalizar vectores y medir distancias. **Cero E/S, cero red, cero registro, cero criptografía.**

### 8.2 El método de análisis

El payload se autorreferencia con un placeholder:

```asm
1400360E0  44 88 44 24 18           mov  [rsp+18h], r8d
1400360E5  48 89 54 24 10           mov  [rsp+10h], rdx
1400360EA  48 89 4C 24 08           mov  [rsp+08h], rcx
1400360EF  48 81 EC 78 04 00 00     sub  rsp, 478h
1400360F6  48 B8 11 11 11 11 11 11 11 11   mov rax, 1111111111111111h
1400360FF  48 89 44 24 40           mov  [rsp+40h], rax
```

El inmediato `0x1111111111111111` está en el offset 24 del blob, y es exactamente lo que el loader localiza con `strchr(blob, 0x11)` y sustituye por la dirección base. Ese registro contiene **la base de la cabecera de `0x4620` bytes**, no el inicio del código.

De ahí se deriva el método: cada operando de memoria con desplazamiento de 32 bits relativo a ese registro es un acceso a la cabecera, y **la cabecera es el conjunto de capacidades**. No hay que interpretar nada: es aritmética sobre offsets.

### 8.3 Resultados

Un barrido lineal de los 17.108 bytes arroja lo siguiente:

- **236 offsets distintos de la cabecera, 1052 accesos.** Todos dentro del rango `0x0000` a `0x461F`.
- **Cero llamadas `call` ni `jmp` indirectas con desplazamiento relativo al IP de instrucción.** No hay IAT propia, ni vtables propias, ni thunks.
- **Cero referencias a datos con desplazamiento relativo al IP de instrucción.** No hay constantes propias.
- **Un único `MOVABS` de 64 bits en 17 KB:** el placeholder `0x1111111111111111`.

Los dos últimos puntos son los determinantes. Si el payload construyera nombres de API o tablas de hash en tiempo de ejecución, necesitaría cargar inmediatos de 64 bits, y no hay ninguno. Si tuviera datos propios, necesitaría referencias relativas al IP de instrucción, y no hay ninguna.

Repitiendo el análisis sobre los otros tres blobs:

| Blob | Accesos a cabecera | Llamadas indirectas | MOVABS | Datos RIP |
|---|---|---|---|---|
| stub de etapa 1 | 5 | 0 | 0 | 0 |
| payload principal | 1052 | 0 | 1 | 0 |
| config A | 9 | 0 | 0 | 0 |
| config B | 0 | 0 | 0 | 0 |

El bloque de config B con cero accesos a memoria con desplazamiento de 32 bits confirma que es dato puro y no código.

### 8.4 Indicadores

Un barrido adicional sobre los 25.226 bytes, buscando indicadores de compromiso, dio:

- **Cero cadenas legibles en ASCII.** Las 55 coincidencias iniciales resultaron ser fragmentos de instrucción: por ejemplo la secuencia de bytes `44 24 50 48 63 44 24 54 48`, que es el final de un `mov [rsp+50h], rax` seguido de `movsxd rax, [rsp+54h]`. Todos los prefijos REX.W producen bytes imprimibles.
- **Cero cadenas en UTF-16.**
- **Cero resoluciones de API por hash ROR13**, calculado sobre una lista de alrededor de 120 nombres de API de proceso, fichero, red, registro, criptografía, teclado y anti-depuración. Ese es el método estándar de shellcode y reflective loader.
- **Cero constantes de MD5, SHA-1, SHA-256, ChaCha20 ni TEA.**
- **Cero direcciones IP en claro y cero puertos sospechosos.**

**En 25 KB de payload no hay ni una sola cadena de texto legible.** Para malware eso es extraordinario: un stealer, un dropper o un ransomware siempre deja algo, una URL, una ruta, un nombre de mutex o un nombre de API.

### 8.5 El mapa de la cabecera

| Offset | Contenido | Accesos |
|---|---|---|
| `0x0000` - `0x01B8` | tabla de diez features, cada una de `0x2C` bytes | varios |
| `0x01D0` - `0x0200` | siete punteros a función del juego, extraidos de una vtable | 66 |
| `0x01EA8` | puntero a la interfaz del motor | **78** |
| `0x0208` - `0x03F8` | región leída densamente, probable tabla de offsets del juego | ~450 |
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
| `0x20BC` | `BYTE[256]`, flanco de bajada por código de tecla | 5 |
| `0x21BC` | `BYTE[256]`, estado actual por código de tecla | 3 |
| `0x22C0` | bandera de "ya inicializado" | 26 |
| `0x22C8` - `0x22E0` | los cuatro punteros del juego | 5 |
| `0x2388` - `0x23B4` | cluster denso, probable tabla de firmas | ~100 |
| `0x3E50` | último offset tocado | 1 |

---

## 9. La demostración de contención

Esta es la sección central del informe.

### 9.1 Las únicas APIs resueltas en tiempo de ejecución

El binario hace `GetProcAddress` exactamente seis veces desde código de aplicación:

| Dirección | Export resuelto | Módulo | Propósito |
|---|---|---|---|
| `0x140006ADD` | `NtQueryInformationProcess` | `ntdll.dll` | obtener el PEB del proceso remoto |
| `0x140006B59` | `NtReadVirtualMemory` | `ntdll.dll` | leer memoria del proceso remoto |
| `0x140006467` | `_itow` | `ntdll.dll` | conversión de entero a cadena |
| `0x1400064D2` | `sqrt` | `ntdll.dll` | matemáticas del aimbot |
| `0x140006579` | `pow` | `ntdll.dll` | matemáticas del aimbot |
| `0x140006602` | `fabs` | `ntdll.dll` | matemáticas del aimbot |

Las tres últimas resuelven funciones matemáticas del CRT que `ntdll.dll` reexporta por compatibilidad. Es un detalle elegante: en vez de enlazar una biblioteca de runtime, el payload roba `sqrt`, `pow` y `fabs` de ntdll.

Las otras tres referencias a `GetProcAddress` del binario están en el rango del UCRT y son sus envoltorios de carga diferida.

**No se resuelve ninguna API de red, de fichero, de proceso, de hilo ni de criptografía en tiempo de ejecución.** Ninguna.

### 9.2 El conjunto de capacidades

Combinando el mapa de la cabecera con lo anterior, el payload tiene acceso a doce punteros a función:

| API disponible | Qué puede hacer |
|---|---|
| `OpenProcess` | abrir otros procesos |
| `GetAsyncKeyState` | consultar el estado de una tecla |
| `SendInput` | inyectar entrada sintética |
| `GetTickCount64` | reloj de alta resolución |
| `NtReadVirtualMemory` | leer memoria de otros procesos |
| `RegSetValueExW` | escribir en el registro |
| `RegOpenKeyExW` | abrir claves del registro |
| `RegCloseKey` | cerrar claves del registro |
| `GetModuleHandleA` | localizar módulos cargados |
| `GetProcAddress` | resolver exportaciones |
| interfaz del motor | siete funciones del juego |
| cuatro punteros del juego | estructuras internas de CS2 |

**Lo que no está en la lista:**

- Ninguna función de fichero. **No puede escribir en disco.**
- Ninguna función de red. **No puede enviar datos a ninguna parte.**
- Ninguna función de creación de procesos o hilos.
- Ninguna función criptográfica.
- Ninguna función de portapapeles, captura de pantalla ni inyección de eventos.

**El payload no tiene capacidad de exfiltración.** No tiene ni un solo socket disponible. No tiene forma de construir un mensaje de red porque no tiene la primitiva para hacerlo.

---

## 10. Por qué esto es un cheat y no malware

### 10.1 Evidencia directa

**Las cadenas del menú.** El binario contiene `Aimbot`, `Smooth`, `Hitbox`, `Trigger`, `Spotted`, `Esp`, `Theme`, `Aim Spot`, `Key`, `On`, `Off`, y la fuente `Tahoma`. Son exactamente los nombres de las opciones de un menú de cheat.

**Las tablas de configuración.** La tabla de diez entradas con paso `0x2C` contiene los valores por defecto de cada feature:

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

Los valores son coherentes con parámetros reales de un aimbot: `Smooth` con 30 sobre un máximo de 100, `Hitbox` con escala 4, `Theme` con índice.

**El manual del autor.** `Aimbot Guide.txt` describe exactamente estas opciones: "Low smooth = fast aimbot, high smooth = slow aimbot", y "Spotted es la verificación de visibilidad de los pobres, el ESP cambiará de color cuando el enemigo sea visible". El binario contiene `Spotted` y `Esp` como features separados. La correspondencia es directa.

**La cadena del motor Source.** `vgui2_s.dll`, `CreateInterface`, `VGUI_Setup001` y `VGUI_Surface039` son el sistema de interfaces gráficas del motor de Valve. El cheat se engancha ahí.

**La firma de hook.** Los bytes buscados en memoria descomponen una función de VGUI con una comparación y una suma a un campo de estructura. El parche de un byte la desvía.

**El disparador de input.** `GetAsyncKeyState` y `SendInput` entregados al código que corre dentro del juego, más `GetTickCount64` como reloj, son exactamente el juego de herramientas de un triggerbot: consultar si una tecla está pulsada, generar el clic en el instante preciso y medir el intervalo. Que el `SendInput` se invoque desde el proceso del juego hace que el input pase el filtro del juego como si fuera interno.

**El bucle de teclas.** El payload recorre los 256 códigos de tecla virtual, llama a `GetAsyncKeyState` para cada uno y detecta flancos de bajada, guardando el resultado en dos vectores de 256 bytes en la cabecera. Ese es el fundamento de la detección de "keybind mantenido".

**El texto del propio binario.** `"Injected, press INSERT to open the menú"` y `"Injecting FREE cheat..."` no dejan lugar a duda.

### 10.2 Ausencia de comportamiento malicioso

**No toca el sistema de ficheros.** `CreateFileW`, `ReadFile` y `WriteFile` solo se llaman desde el UCRT, en el código de entrada y salida de consola. No hay `DeleteFile`, ni `MoveFileEx`, ni `CopyFile`, ni `CreateProcess`, ni escritura en disco de ningun tipo.

**No exfiltra.** La única conexión saliente es una consulta a una API pública de hora, con una petición literal de 138 bytes que no contiene datos de la máquina.

**No roba credenciales.** No hay rutas de navegadores, ni acceso a LSASS, ni `CryptUnprotectData`, ni portapapeles, ni captura de pantalla.

**No escala privilegios.** No hay manipulación de tokens, ni creación de servicios, ni carga de drivers, ni bypass de UAC. Pide administrador únicamente porque `OpenProcess` con todos los permisos sobre un proceso de Steam lo requiere.

**No persiste como ejecutable.** Su único uso del registro es una clave de configuración, y usa `RegDeleteKeyA` para **invalidar** cuando el tipo o el tamaño no cuadran, no para instalar. No hay claves de autoarranque, ni tareas programadas, ni servicios.

**Endurecido, no debilitado.** El binario tiene cookies de pila y tabla de manejadores de excepciones seguros:

```
SecurityCookie  0x000000014003C2C0
SEHandlerTable   0x00000001400293A0
```

El valor `0x14003C2C0` es la misma constante de comprobación de pila que aparece en el epílogo de todas las funciones. El malware rara vez se compila con estas protecciones porque estorban.

---

## 11. Técnicas de anti-análisis

Cinco, y ninguna define por sí sola la malicia:

1. **XOR de un byte en todas las cadenas**, descifrado en la pila, de modo que no existe texto en claro en el fichero ni en un volcado de memoria.
2. **Winsock importado por ordinal**, eliminando las cadenas `socket`, `connect`, `send` y `recv` del binario.
3. **Tablas de firmas construidas byte a byte.** El código escribe cada byte de los patrones con instrucciones `MOV` individuales, de forma que nunca existe un bloque contiguo de datos que un escáner pueda firmar como patrón.
4. **Tabla de resolución indirecta de punteros**, con el desplazamiento de 32 bits escondido dentro del juego en vez de una tabla legible en el loader.
5. **Compilacion con optimización guiada por perfil.** El directorio de depuración registra `IMAGE_DEBUG_TYPE_POGO`, no `CODEVIEW`. Es decir, el binario fue construido con PGO, que produce código notablemente mejor optimizado y por tanto más difícil de invertir, y **la ruta del PDB fue eliminada**, de modo que no hay atribución por entorno de compilacion.

---

## 12. Auditoría de la estructura PE

| Sección | Flags | Permisos | Estándar MSVC |
|---|---|---|---|
| `.text` | `0x60000020` | código, ejecución, lectura | idéntico |
| `.rdata` | `0x40000040` | datos, lectura | idéntico |
| `.data` | `0xC0000040` | datos, lectura, escritura | idéntico |
| `.pdata` | `0x40000040` | datos, lectura | idéntico |
| `.reloc` | `0x42000040` | datos, descartable, lectura | normal |

**Ninguna sección con escritura y ejecución simultáneas.**

| Directorio | Valor | Nota |
|---|---|---|
| TLS | `0x0` | **vacío, sin callbacks** |
| Overlay | ninguno | el fichero acaba donde acaba la última sección |
| Export | `0x0` | |
| Resource | `0x0` | sin recursos incrustados |
| BoundImport | `0x0` | |
| DelayImport | `0x0` | |
| CLR | `0x0` | no es .NET |

**No hay callbacks TLS**, que son la vía estándar de ejecución de código antes de `main` y la forma más común de anti-depuración persistente. **No hay overlay**, lo que descarta de raíz la técnica de dropper con carga embebida al final del fichero. Las protecciones de imagen activas son ASLR, DEP y `TERMINAL_SERVER_AWARE`, sin `NO_SEH` y sin CFG.

### 12.1 Sobre el patrón del bloque de config B

El bloque de 6.800 bytes presenta 809 apariciones del valor de 4 bytes `0x00FFFFFF`. El análisis de la distribución muestra que **no es un valor repetido**, sino la secuencia de bytes `FF FF FF 00` repetida:

```
bytes 0xFF:  2555  (37.6 por ciento)
bytes 0x00:   994  (14.6 por ciento)
rachas consecutivas de 0xFF:  937
   de las cuales 809 de longitud 3, y 128 de longitud 1
```

Es una **tabla dispersa**: 809 entradas con el marcador de vacío `FF FF FF 00` y 128 entradas pobladas con datos reales. Encaja exacto con las posiciones: el bloque se copia a la cabecera en el offset `0x23C0`, y `0x23C0 + 0x1A90 = 0x3E50`, que es el último offset que toca el payload.

Una tabla de 128 entradas pobladas con 809 huecos vacíos es exactamente lo que se espera de una tabla de offsets de entidades y huesos de un motor de juego. Un malware que prepara terreno no deja un 52 por ciento de marcadores de vacío.

---

## 13. Veredicto

**`undetek.exe` v10.51 no es malware.**

La conclusión se sostiene sobre tres pilares, todos verificables:

1. **Contención de capacidades.** El payload no tiene IAT propia, ni constantes propias, ni resuelve APIs por hash, y todas sus capacidades se reducen a doce punteros que el loader le entrega. No tiene ninguna primitiva de red, de fichero ni de proceso. **No puede exfiltrar.**

2. **Ausencia de comportamiento malicioso en el loader.** Sin escritura en disco, sin exfiltración, sin robo de credenciales, sin escalada de privilegios, sin persistencia como ejecutable, y con protecciones de pila y SEH activas.

3. **Evidencia positiva de cheat.** Cadenas del menú, tabla de diez features con valores por defecto coherentes, resolución de interfaces del motor de Valve, hook en línea sobre una función de VGUI, disparador de input dentro del proceso del juego, y un mensaje de éxito que dice literalmente que se ha inyectado un cheat.

### 13.1 Lo que sí es un riesgo

**El riesgo mayor no es este binario.** Es la guía de instalación que lo acompaña:

```
1. Turn off windows defender
2. Turn off windows defender firewall
3. Turn off smartscreen (app and browser control)
4. Turn UAC to a low setting.
5. Turn off Valorant Anticheat.
6. Turn off FACEIT Anticheat.
```

Desactivar el antivirus, el firewall, SmartScreen, el control de cuentas de usuario y los anticheats de terceros para ejecutar un ejecutable de un vendedor anónimo **es el vector de entrada real del malware para jugadores**, mucho más que cualquier bytecode concreto. Ese es el canal por el que se distribuye malware para esta plataforma, y aquí llega con instrucciones paso a paso.

**El PIN no es una licencia** y no debe pagarse por el. Es una función del reloj público, sin secreto de servidor, con 480 valores posibles por día y la misma respuesta para todos los usuarios a la vez.

**Legal.** Inyectar código en Counter-Strike 2 viola las condiciones de servicio de Valve. El riesgo de bloqueo permanente de VAC es del usuario, no del autor del loader.

### 13.2 Limitaciones del método

Conviene ser explícito sobre lo que este análisis **no** demuestra:

- **El análisis de capacidades es un barrido lineal de operandos de memoria, no un desensamblador.** Puede perder sincronización, y se ha observado que lo hace: los accesos "fuera de la cabecera" que produce en una de las etapas son valores que contienen bytes de opcode de x86, es decir artefactos del parser. Es evidencia fuerte, no prueba formal.

- **La lógica del aimbot no se ha reconstruido.** Se han identificado las variables de estado de teclas, la resolución de interfaces y la biblioteca de vectores, pero no la matemática concreta de predicción, campo de visión o compensación de retroceso.

- **El payload tiene `GetModuleHandleA` y `GetProcAddress` disponibles.** Podría resolver cualquier API en tiempo de ejecución si quisiera. Para hacerlo necesitaría nombres, y no hay cadenas, ni hashes, ni inmediatos de 64 bits en los 17 KB. Lo único que no puede descartarse sin desensamblado completo es que construyera un nombre byte a byte en la pila con inmediatos de 8 bits, que el barrido no vería. Es la misma técnica que usa el propio loader con sus 51 descifradores, así que no es descartable de forma teórica.

- **Dos cadenas de texto se identificaron por longitud y no por lectura directa**, por lo que su contenido literal puede diferir en un carácter.

---

## 14. Indicadores de compromiso

```
MD5     47cdf077d83b9e8c8b80364d2dbd9527
SHA-1   77468f710e2d45fcbab758a6beb8590e767d79be
SHA-256 82eb05556ffe1597e40353a0faef69e78f072d14e671adbf360c2161c06a8276

Red observada (única):
  vip.timezonedb.com:80        API pública de zona horaria, GET HTTP
  clave de la API: <redactada>
  ruta: /v2.1/get-time-zone

Registro:
  HKEY_CURRENT_USER\Software\udtk
  valor por defecto (sin nombre), REG_BINARY, 440 bytes

Objetivo:
  procesos:  cs2.exe, gameoverlayui64.exe
  módulos:   client.dll, vgui2_s.dll, ntdll.dll
  símbolos:  CreateInterface, VGUI_Setup001, VGUI_Surface039

Cadenas en claro en el binario: NINGUNA, todas cifradas con XOR 0x34
```

Que un análisis antivirus marque este fichero como `Trojan.Win32.Generic` es esperable: la asignación de memoria con ejecución y escritura simultáneas más la carga reflectiva más la inyección en otro proceso son exactamente los heurísticos que disparan los motores. Este informe explica por qué saltan aquí y en qué se diferencian de una infección real: un Troyano real tiene cadenas, sockets y ficheros de los que este binario no tiene nada.

---

## 15. Conclusiones

Un loader de cheat y un malware se parecen mucho en la superficie: reservan memoria ejecutable, escriben en la memoria de otro proceso, crean un hilo remoto y resuelven símbolos en tiempo de ejecución. Por eso un análisis únicamente basado en indicadores heurísticos no puede separarlos, y por eso este caso merece un análisis estático completo.

Lo que separa este binario de un Troyano son tres cosas concretas y verificables.

**La primera es la contención de capacidades.** El payload no tiene ninguna primitiva de red ni de fichero. Eso no es una propiedad de "parece limpio"; es una lista cerrada de doce punteros a función derivada de los desplazamientos reales de las instrucciones. Un Troyano necesita salir de la máquina; este no puede.

**La segunda es la ausencia de cadenas.** Veinticinco kilobytes de payload sin una sola cadena legible es prácticamente inaudito en malware. Cuando el código necesita un `socket` o una ruta, deja un rastro. Aquí todo pasa por punteros que el loader entrega ya resueltos.

**La tercera es la coherencia interna.** El binario contiene los nombres de las features, los valores por defecto de esas features, la resolución de las interfaces del motor de Valve, un hook sobre una función de ese motor, y mensajes que dicen que se ha inyectado un cheat. Todo apunta en la misma dirección y nada apunta en la contraria.

Queda una lección para el usuario final que es más importante que el veredicto técnico: **el riesgo real de un binario de este tipo no es lo que hace, sino lo que hay que desactivar para poder usarlo.** Un ejecutable que exige apagar el antivirus, el firewall y el control de cuentas antes de correr es, en si mismo, un indicador de compromiso mucho más fuerte que cualquier análisis estático.

Y una nota sobre el PIN, que es el hallazgo más instructivo del análisis desde el punto de vista del diseño de software: **un secreto que se deriva del reloj no es un secreto.** El autor implementó un TOTP con el reloj público como única entrada, y el resultado es que cualquier usuario puede calcular su propia licencia. La ofuscación de las cadenas, los imports por ordinal y la compilacion con optimización guiada por perfil son esfuerzo serio en una sola dirección, y al mismo tiempo la lógica de autorización es trivialmente invertible. Son cosas que no se ven a la vez.

---

## Agradecimientos

Este análisis se realizó con la asistencia de **opencode**, en el marco de un modelo operado por **Space Bunny** con **Claude Sonnet 5.5**, usando el servidor MCP de Ghidra para el desensamblado y la ingeniería inversa, y scripts propios en Python para el volcado de cadenas, la extracción de indicadores y el análisis de capacidades.

El trabajo de los modelos de lenguaje fue la parte mecánica: descifrar cadenas, enumerar referencias cruzadas, correlacionar longitudes de blob con contenido y aplicar transformaciones aritméticas. **Las decisiones sobre que es evidencia y que es hipótesis, y sobre dónde están los límites del método, fueron del analista humano.** Los cuatro fallos de instrumentación documentados en la sección 3 son también parte del registro, porque un informe de análisis sin sus errores no es auditable.

---

*Análisis realizado exclusivamente por medios estáticos. El binario no fue ejecutado en ningun momento. Herramientas: Ghidra con servidor MCP, y utilidades propias en Python estándar sin dependencias externas.*