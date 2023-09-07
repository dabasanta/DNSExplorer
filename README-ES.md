# Presenting DNSExplorer v2

![Untitled](https://raw.githubusercontent.com/dabasanta/DNSExplorer/main/examples/Banner.gif)

# DNSExplorer

## TL;TR

**DNSExplorer** es un script que automatiza el proceso de enumerar un dominio o servidor DNS y sus subdominios usando 'host' como herramienta principal.

Su objetivo es enumerar dominios y subdominios usando el servidor por defecto en el archivo revolv.conf para dar una visión general del servicio DNS.

DNSExplorer es una herramienta inicial de enumeración y reconocimiento, útil para su uso en pentesting y redteam interno o externo, con DNSExplorer se puede obtener un buen punto de apoyo a través de la huella de una empresa. DNSExplorer es de uso libre, cualquiera puede modificar o añadir características para mejorar el enfoque. El autor no promueve acciones maliciosas o el uso del script para operaciones ilegales. Recuerde obtener siempre el permiso previo de los administradores de sistemas de la empresa objetivo antes de realizar cualquier acción maliciosa. Aunque DNSExplorer no realiza acciones que puedan comprometer la integridad, confidencialidad o disponibilidad de la información, puede generar ruido en la red de la empresa si se monitoriza continuamente, lo que puede disparar alertas de seguridad.

> **Integridad:** DNSExplorer es una herramienta de sólo lectura, no realiza ninguna modificación sobre los activos de la empresa.
> 

> **Disponibilidad:** DNSExplorer no realiza acciones que puedan comprometer la disponibilidad de los activos tecnológicos de los objetivos.
> 

> **Confidencialidad:** DNSExplorer no guarda registros de los datos obtenidos en servidores o servicios externos.
> 

# Modo de uso

 Solo ejecuta el script indicándole el nombre del dominio a verificar, DNSExplorer hará el resto!

```bash
./DNSExplorer.sh <domain.com>
```

## Enumeración extendida

Estableciendo la bandera extendida, el script puede ejecutar pruebas adicionales, tales como enumeración de tecnologías web y enumeración de protección WAF a los sitios descubiertos.

```bash
./DNSExplorer.sh <domain.com> --extended
```

# Dependencias

- host
    
    Comando que comunmente viene con el paquete ‘dns-utils’ o ‘bind-utils’.
    
- curl
    
    Usado para consultas a servicios externos, como [CRT.SH](http://CRT.SH) y para descubrir servidores web en el dominio objetivo.
    
- parallel
    
    Usado para las capacidades que requieren ejecución paralela.
    
- bc
    
    Usado para mostrar algunas estadísticas a lo largo del script.
    
- openssl
    
    Usado para establecer las conexiones a servidores seguros HTTPS y enumerar algunos aspectos de los certificados digitales.
    

## Dependencias opcionales (pruebas extendidas)

- wafw00f
    
    Viene por defecto en Kali, usada para determinar los sitios que están protegidos por un WAF.
    
- whatweb
    
    Usado para enumerar las tecnologías de los servidores web identificados.
    

# Enum phases

Las fases de enumeración se dividen en 3 grupos

- **Enumeración básica:** Conjunto de enumeración estándar de registros DNS.
- **Transferencia de zona DNS:** Una vez identificados los servidores DNS responsables de resolver las peticiones, se intenta un ataque de transferencia de zona, en caso afirmativo, se descarga la información referente al dominio objetivo.
- **Ataque de diccionario (*AKA. Bruteforce*):** Ataque de diccionario contra los registros DNS con el fin de descubrir la mayor cantidad de subdominios disponibles, es muy rapido y permite elegir entre dos opciones: usar un diccionario por defecto de *SECLISTS*, o usar un diccionario local definido por el usuario.
- **Abuso de [CRT.SH](http://CRT.SH):** Abusar de la base de datos de CRT.SH, ver mayores detalles abajo.
- **Descubrimiento de servidores web:** Mapear servidores HTTP y HTTPS en los subdominios identificados.
- **Búsqueda de registros SAN en certificados digitales:** Una vez identificados los servidores HTTPS, se hace un barrido de sus certificados digitales para identificar los registros SAN en busca de nombres alternativas que puedan ser objetivos.
- **Checkeo extendido:** Esta función pretende “correr la milla extra”, al identificar las tecnologías que soportan al servidor web (versión, lenguaje de programación, pais, protección de WAF). Requiere activación manual con la bandera `—extended`.

## Basic enum

La enumeración básica usara el comando ‘host’ para extraer la información publica de la zona DNS del servidor responsable de la resolución, aqui, podemos encontrar registros estándar como los siguientes:

```bash
[+] A records for google.com domain
172.217.173.206

[+] AAA records for google.com domain
2800:3f0:4005:408::200e

[+] MX records for google.com domain
10 smtp.google.com.

[+] CNAME records for google.com domain
 Hosts google.com has not alias records

[+] TXT records for google.com domain
acebook.com descriptive text "google-site-KI-C3_iA"
facebook.com descriptive text "google-sito_RnyMJoDaG0s"
facebook.com descriptive text "zoom-d036f01bb"
facebook.com descriptive text "v=spf1 com"
facebook.com descriptive text "google-RReU6pJlY"

[+] Enumerating DNS Servers...
[4] DNS Servers was found, trying ZoneTransfer on these servers

[!!] NameServer ns2.google.com. does not accept zone transfer
[!!] NameServer ns4.google.com. does not accept zone transfer
[!!] NameServer ns1.google.com. does not accept zone transfer
[!!] NameServer ns3.google.com. does not accept zone transfer

[!!] DNS zone transfer was not possible, DNS servers are not accept it
```

## ZoneTransfer

> Un ataque de transferencia de zona en DNS, también conocido como "zonetransfer", es una táctica utilizada para obtener información sensible sobre la estructura de un dominio, como nombres de dominio, direcciones IP y registros DNS. Este ataque aprovecha una debilidad en la configuración del servidor DNS que permite a un atacante solicitar una copia completa de la zona DNS, que contiene información detallada sobre todos los recursos del dominio. Esto puede dar a los atacantes una visión completa de la infraestructura de red y, en algunos casos, revelar información crítica que podría utilizarse en ataques posteriores, como la identificación de vulnerabilidades o puntos de entrada. Por tanto, es esencial para los administradores de sistemas y profesionales de seguridad configurar adecuadamente sus servidores DNS para evitar la transferencia de zona no autorizada y prevenir posibles ataques de este tipo.
> 

Una vez identificados los servidores DNS, se intenta realizar un ataque de transferencia de zona en estos. 

```bash
[+] TXT records for domain.com domain
 Hosts domain.com has not description records

[+] Enumerating DNS Servers...
[4] DNS Servers was found, trying ZoneTransfer on these servers

NameServer ns4.domain.com. accept ZoneTransfer

[+] 15 'A' records found:
[+] 14 'AAA' records found:
[+] 4 'MX' records found:
[+] 1 'AXFR' records found:
[+] 14 'CNAME' records found:
[+] 4 'NS' records found:
[+] 11 'SRV' records found:
[+] 13 'TXT' records found:
[+] 1 'SOA' records found:

[76] Records found in ns4.domain.com.
Please take note of the other DNS servers, they may do zone transfers as well.

 DNS zone transfer was possible, no bruteforce attacks on the subdomains are required.]
```

## Dictionary attack

Cuando la transferencia de zona falla, podemos tener sesgos en los resultados de la enumeración básica, esto debido a que parte de los registros DNS de una organización no se indexan el internet, o no son expuestos en la zona publica del servidor DNS. Algunos registros están pensados para ser consumidos solo por la red interna o a través de una conexión VPN, en estos casos el ataque de diccionario puede ayudarnos a encontrar mas información relevante, mucha de la cual puede escaparse de la enumeración básica a través de las consultas realizadas a los registros generales del DNS. En conjunto con el abuso de CRT.SH, esta técnica permite tener una visión mas acercada a la realidad, permitiendo incluso tener una visión del dominio casi a la par que los administradores internos de la  infraestructura (dicho por experiencia propia).

```bash
Do you want to brute force subdomains? [Y/n]> y

 
  ██████╗ ██╗ ██████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗ █████╗ ██████╗ ██╗   ██╗
  ██╔══██╗██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
  ██║  ██║██║██║     ██║        ██║   ██║██║   ██║██╔██╗ ██║███████║██████╔╝ ╚████╔╝ 
  ██║  ██║██║██║     ██║        ██║   ██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗  ╚██╔╝  
  ██████╔╝██║╚██████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║██║  ██║██║  ██║   ██║   
  ╚═════╝ ╚═╝ ╚═════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
                                                                                     
                   █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗                 
                  ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝                 
                  ███████║   ██║      ██║   ███████║██║     █████╔╝                  
                  ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗                  
                  ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗                 
                  ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝                 
                                                                                     
  
		Fuzzing subdomains of [evil-corp.com]

  Do yo want to use a custom dictionary? [c=custom/d=default]
  [+] Default: Provides a dictionary with the top 1000 of the most commonly used subdomains.
  [+] Custom: Use your own custom dictionary.

[d/c]> d

		[+] Subdomain found: intranet.evil-corp.com
[+] Reading file...
```

**¿Por qué no es opcional?**

El ataque de diccionario si dispara automáticamente cuando la transferencia de zona ha fallado, si bien [CRT.SH](http://CRT.SH) brindará una visión bastante completa del dominio, por medio del ataque de diccionario podemos cerciorarnos que la información que recolectemos es accesible, aunque sea solo parcialmente. Además, puede brindar información que se le escape a CRT.SH, por ejemplo, subdominios de aplicaciones o endpoints que no cuenten con certificados digitales, y, por lo tanto, no estén mapeados en CRT.SH.

### Custom dicctionary attack

Este método permite establecer el diccionario que el usuario prefiera, no existe un limite en cuanto al tamaño del archivo, pero si existe un limite en cuanto a la cantidad de procesos paralelos que se ejecutarán, siendo 40 el numero máximo de procesos paralelos a ejecutar. Por defecto, el script usara el 15% del tamaño del archivo como numero de hilos, entonces, si el diccionario contiene 100 registros, se usaran 15 hilos para consumir las 100 peticiones. Claro, esto puede sonar desproporcionado para un diccionario tan pequeño, pero, si tenemos uno mas grande, por ejemplo, 80.000 registros, agradeceremos el uso de ejecuciones paralelas para establecer las consultas. Sin embargo, se ha establecido 40 como limite para evitar que la CPU se sobrecargue.

Si deseas establecer un valor fijo al numero de hilos para tu diccionario personalizado, puedes modificar la variable `DNS_BRUTE_THREADS` ubicada en la sección de variables globales al inicio del script:

```bash
# Modify the DNS_BRUTE_THREADS variable to set the number of threads to use in the custom-dictionary attack.
# By default, the script will use 15% of the number of records in the dictionary.
export DNS_BRUTE_THREADS=0
```

Por defecto, el valor de esta variable es cero, pero, si estableces un valor diferente de cero, por ejemplo, 60, este será tomado como el valor por defecto para consumir el diccionario personalizado.

💡 **Cortesía de la casa:** Para los dominios que son en español, puedes usar el diccionario: [https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-spanish.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-spanish.txt)

### Default dicctionary attack

Este modo provee un diccionario de SECLISTS llamado [bitquark-subdomains-top100000.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt) el cual contiene 100.000 registros, para este modo, se usan 40 hilos de forma predeterminada, numero suficiente para consumir el diccionario de forma eficiente y rápida sin sacrificar las CPU antiguas.

## CRT.SH

Es un registro público y transparente de certificados SSL/TLS utilizados en Internet. Este sistema permite la monitorización y búsqueda de certificados digitales, lo que es esencial para detectar certificados fraudulentos o maliciosos, así como para mejorar la seguridad en línea. Sin embargo, la información que esta base de datos puede brindarnos sobre un dominio es tremendamente util para esta labor, pudiendo registrar información incluso de registros DNS internos que solo son accesibles desde dentro de la organización. Sin embargo, CRT.SH no es malo por esto, aqui aplica el dicho “un cuchillo puede ser una herramienta de trabajo en las manos correctas, o un arma mortal en las manos equivocadas”.

DNSExplorer toma la salida de CRT.SH, la cual viene en formato JSON en una estructura como la siguiente:

```json
{
	"issuer_ca_id" : 4,
	"issuer_name" : "C=US, O=Google Inc, CN=Google Internet Authority",
	"common_name" : "onex.wifi.google.com",
	"name_value" : "onex.wifi.google.com",
	"id" : 2380850988,
	"entry_timestamp" : "2020-01-26T22:51:36.008",
	"not_before" : "2012-02-29T09:49:41",
	"not_after" : "2013-02-28T09:59:41",
	"serial_number" : "5518368b000300004b60"
}
```

DNSExplorer convierte los datos crudos JSON en información util para la enumeración del dominio.

## Web Server discovery

En cuanto tenemos una base inicial de subdominios de la organización, es una buena idea comenzar a mapear los diferentes servicios que se ejecutan en estos puntos, esta función permite descubrir servidores HTTPS y HTTP.

**¿Por qué excluir los servidores HTTP-HTTPS, siendo que en algunos casos pueden ser el mismo servidor aplicando una redirección?**

Básicamente el script usará los servidores HTTPS para una enumeración posterior, adicionalmente, algunos componentes de las aplicaciones web pueden ser hospedadas por servidores diferentes.

```bash
The domain intranet.evil-corp.com has a web server. [HTTP:200]
The domain new.evil-corp.com has a web server. [HTTP:301]
The domain news.evil-corp.com has a secure web server. [HTTPS:302]
The domain www2.evil-corp.com has a web server. [HTTP:403]
The domain b2b.evil-corp.com has a secure web server. [HTTPS:301]
The domain www.evil-corp.com has a web server. [HTTP:301]
```

## Búsqueda de registros SAN en certificados digitales

Los SAN son extensiones de certificados SSL/TLS que permiten especificar múltiples nombres de dominio que están protegidos por el mismo certificado. La finalidad de esta prueba es verificar si existen nombres de dominio adicionales a los que ya se hayan encontrado en las pruebas anteriores, en caso afirmativo se agregarán esos subdominios a la lista.

## Extended checks

En resumen, esta opcion nos permitirá tener un CSV con la siguiente estructura:

| URL | HTTPServer | IP | PoweredBy | X-Powered-By | Country | WAF |
| --- | --- | --- | --- | --- | --- | --- |
| https://www2.evil-corp.com/ | Apache | 66.33.99.196 | None | PHP/7.4.3 | RESERVED | Incapsula |

### Web technologies enum

Se usa whatweb para enumerar los siguientes aspectos:

- Servidor HTTP
- IP
- Tecnología o solución (ej. WordPress)
- Lenguaje de programación.
- Pais donde se encuentra el servidor físico

### WAF protection enum

Usa wafw00f para determinar si la pagina o aplicación web esta protegida por un WAF, además, identifica el nombre del fabricante del WAF, util si se quiere arriesgar con tecnicas de Bypass.