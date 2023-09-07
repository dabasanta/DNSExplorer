# Presenting DNSExplorer v2

![](https://raw.githubusercontent.com/dabasanta/DNSExplorer/main/examples/Banner.gif)

# DNSExplorer

## TL;TR

DNSExplorer is a script that automates the process of enumerating a domain or DNS server and its subdomains using 'host' as the main tool.

Its goal is to enumerate domains and subdomains using the default server in the revolv.conf file to give an overview of the DNS service.

DNSExplorer is an initial enumeration and reconnaissance tool, useful for use in pentesting and internal or external redteam, with DNSExplorer you can get a good foothold across a company's footprint. DNSExplorer is free to use, anyone can modify or add features to improve the approach. The author does not promote malicious actions or the use of the script for illegal operations. Remember to always obtain prior permission from the target company's system administrators before performing any malicious actions. Although DNSExplorer does not perform actions that may compromise the integrity, confidentiality or availability of information, it may generate noise in the company network if continuously monitored, which may trigger security alerts.

> **Integrity:** DNSExplorer is a read-only tool, it does not make any modifications to the company's assets.
> 

> **Availability:** DNSExplorer does not perform actions that could compromise the availability of the targets' technology assets.
> 

> Confidentiality:** DNSExplorer does not keep records of data obtained on external servers or services.
>

# How to use

 Just run the script telling it the domain name to verify, DNSExplorer will do the rest!

```bash
./DNSExplorer.sh <domain.com>
```

## Extended enumeration

By setting the extended flag, the script can run additional tests, such as enumeration of web technologies and enumeration of WAF protection to discovered sites.

```bash
./DNSExplorer.sh <domain.com> --extended
```

# Dependencies

- host
    
    Command that commonly comes with the 'dns-utils' or 'bind-utils' package.
    
- curl
    
    Used for querying external services, such as [CRT.SH](http://CRT.SH) and for discovering web servers in the target domain.
    
- parallel
    
    Used for capabilities that require parallel execution.
    
- bc
    
    Used to display some statistics throughout the script.
    
- openssl
    
    Used to establish connections to HTTPS secure servers and list some aspects of digital certificates.
    

## Optional dependencies (extended tests)

- wafw00f
    
    Default in Kali, used to determine which sites are protected by a WAF.
    
- whatweb
    
    Used to list identified web server technologies.


# Enum phases

The enumeration phases are divided into 3 groups

- **Basic enumeration:** Standard enumeration set of DNS records.
- **DNS zone transfer:** Once the DNS servers responsible for resolving requests have been identified, a zone transfer attack is attempted, if successful, information about the target domain is downloaded.
- **Dictionary attack (*AKA. Bruteforce*):** Dictionary attack against DNS records in order to discover as many available subdomains as possible, it is very fast and allows to choose between two options: use a default dictionary of *SECLISTS*, or use a local dictionary defined by the user.
- **Abuse of [CRT.SH](http://CRT.SH):** Abuse of the CRT.SH database, see more details below.
- **Web server discovery:** Mapping HTTP and HTTPS servers on identified subdomains.
- **Search for SAN records in digital certificates:** Once the HTTPS servers have been identified, a sweep of their digital certificates is performed to identify SAN records for alternative names that may be targeted.
- **Extended Checking:** This feature is intended to "go the extra mile" by identifying the technologies supporting the web server (version, programming language, country, WAF protection). It requires manual activation with the `--extended` flag.


## Enumeración básica

La enumeración básica usara el comando 'host' para extraer la información publica de la zona DNS del servidor responsable de la resolución, aqui, podemos encontrar registros estándar como los siguientes:

```bash
[+] A records for google.com domain
172.217.173.206

[+] AAA records for google.com domain
2800:3f0:4005:408::200e

[+] Registros MX para el dominio google.com
10 smtp.google.com.

[+] registros CNAME para el dominio google.com
 Hosts google.com no tiene registros alias

[+] Registros TXT para el dominio google.com
acebook.com texto descriptivo "google-site-KI-C3_iA"
facebook.com texto descriptivo "google-sito_RnyMJoDaG0s"
facebook.com texto descriptivo "zoom-d036f01bb"
facebook.com texto descriptivo "v=spf1 com"
facebook.com texto descriptivo "google-RReU6pJlY"

[+] Enumerando servidores DNS...
[4] DNS Servers was found, trying ZoneTransfer on these servers

[!!] NameServer ns2.google.com. no acepta transferencia de zona
[!!] NameServer ns4.google.com. no acepta transferencia de zona
[!!] NameServer ns1.google.com. no acepta transferencia de zona
[!!] NameServer ns3.google.com. no acepta transferencia de zona

[!!] La transferencia de zona DNS no fue posible, los servidores DNS no la aceptan
```

## ZoneTransfer

> A DNS zone transfer attack, also known as a "zonetransfer", is a tactic used to obtain sensitive information about a domain's structure, such as domain names, IP addresses and DNS records. This attack exploits a weakness in the DNS server configuration that allows an attacker to request a full copy of the DNS zone, which contains detailed information about all the domain's resources. This can give attackers a complete view of the network infrastructure and, in some cases, reveal critical information that could be used in subsequent attacks, such as identifying vulnerabilities or entry points. It is therefore essential for system administrators and security professionals to properly configure their DNS servers to avoid unauthorized zone transfer and prevent potential attacks of this type.
> 

Once the DNS servers are identified, an attempt is made to perform a zone transfer attack on them. 

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

When the zone transfer fails, we can have biases in the basic enumeration results, this is because some of the DNS records of an organization are not indexed on the Internet, or are not exposed in the public zone of the DNS server. Some records are intended to be consumed only by the internal network or through a VPN connection, in these cases the dictionary attack can help us find more relevant information, much of which may escape the basic enumeration through queries made to the general DNS records. In conjunction with the abuse of CRT.SH, this technique allows us to have a closer view to reality, even allowing us to have a view of the domain almost on par with the internal administrators of the infrastructure (said from my own experience).

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

**Why is it not optional?**

The dictionary attack if triggered automatically when the zone transfer has failed, although [CRT.SH](http://CRT.SH) will provide a fairly complete view of the domain, by means of the dictionary attack we can make sure that the information we collect is accessible, even if only partially. In addition, it can provide information that escapes CRT.SH, for example, subdomains of applications or endpoints that do not have digital certificates and, therefore, are not mapped in CRT.SH.

### Custom dictionary attack

This method allows to set the dictionary that the user prefers, there is no limit to the size of the file, but there is a limit to the number of parallel processes that will be executed, being 40 the maximum number of parallel processes to be executed. By default, the script will use 15% of the file size as the number of threads, so if the dictionary contains 100 records, 15 threads will be used to consume the 100 requests. Of course, this may sound disproportionate for such a small dictionary, but, if we have a larger one, for example, 80,000 records, we will appreciate the use of parallel executions to set up the queries. However, 40 has been set as a limit to avoid overloading the CPU.

If you want to set a fixed value to the number of threads for your custom dictionary, you can modify the `DNS_BRUTE_THREADS` variable located in the global variables section at the beginning of the script:

```bash
# Modify the DNS_BRUTE_THREADS variable to set the number of threads to use in the custom-dictionary attack.
# By default, the script will use 15% of the number of records in the dictionary.
export DNS_BRUTE_THREADS=0
```

By default, the value of this variable is zero, but, if you set a non-zero value, for example, 60, this will be taken as the default value to consume the custom dictionary.

💡 For the domains that are in Spanish, you can use the dictionary: [https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-spanish.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-spanish.txt)

### Default dictionary attack

This mode provides a SECLISTS dictionary called [bitquark-subdomains-top100000.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt) which contains 100,000 records, for this mode, 40 threads are used by default, enough to consume the dictionary efficiently and quickly without sacrificing old CPUs.

## CRT.SH

It is a public and transparent registry of SSL/TLS certificates used on the Internet. This system allows monitoring and searching for digital certificates, which is essential for detecting fraudulent or malicious certificates, as well as for improving online security. However, the information that this database can provide about a domain is tremendously useful for this task, being able to record information even from internal DNS records that are only accessible from within the organization. However, CRT.SH is not bad for this, here applies the saying "a knife can be a working tool in the right hands, or a deadly weapon in the wrong hands".

DNSExplorer takes the output of CRT.SH, which comes in JSON format in a structure like the following:

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

DNSExplorer converts raw JSON data into useful information for domain enumeration.

## Web Server discovery

As soon as we have an initial base of subdomains of the organization, it is a good idea to start mapping the different services running on these points, this function allows to discover HTTPS and HTTP servers.

**Why exclude HTTP-HTTPS servers, since in some cases they can be the same server by applying a redirect?**

Basically the script will use the HTTPS servers for later enumeration, additionally, some components of web applications may be hosted by different servers.

```bash
The domain intranet.evil-corp.com has a web server. [HTTP:200]
The domain new.evil-corp.com has a web server. [HTTP:301]
The domain news.evil-corp.com has a secure web server. [HTTPS:302]
The domain www2.evil-corp.com has a web server. [HTTP:403]
The domain b2b.evil-corp.com has a secure web server. [HTTPS:301]
The domain www.evil-corp.com has a web server. [HTTP:301]
```

## Search for SAN records in digital certificates

SANs are SSL/TLS certificate extensions that allow you to specify multiple domain names that are protected by the same certificate. The purpose of this test is to check if there are additional domain names to those already found in the previous tests, if so those subdomains will be added to the list.

## Extended checks

In summary, this option will allow us to have a CSV with the following structure:

| URL | HTTPServer | IP | PoweredBy | X-Powered-By | Country | WAF |
| --- | --- | --- | --- | --- | --- | --- |
| https://www2.evil-corp.com/ | Apache | 66.33.99.196 | None | PHP/7.4.3 | RESERVED | Incapsula |

### Web technologies enum

Whatweb is used to enumerate the following aspects:

- HTTP server
- IP ADDRESS
- Technology or solution (e.g. WordPress)
- Programming language.
- Country where the physical server is located

### WAF protection enum

Use wafw00f to determine if the web page or application is protected by a WAF, it also identifies the name of the WAF manufacturer, useful if you want to take risks with Bypass techniques.

