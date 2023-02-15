#!/usr/bin/env bash
# @author: Danilo Basanta
# @author-linkedin: https://www.linkedin.com/in/danilobasanta/
# @author-github: https://github.com/dabasanta
tmpdir="/tmp/dnsexplorer" 
mkdir -p $tmpdir  
tput civis  
clean(){  
    echo ""
    rm -rf $tmpdir
    echo "Happy hunting."
    tput cnorm
    exit 0
}
function scape() {  
  clean
}
trap scape INT
mkdir -p $1.out
output="$1.out"
dictionaryAttackCustom(){
  dicc_outfile="$tmpdir/dicctionary.results.txt"
  echo "" > $dicc_outfile
  check=0
  while [ $check -eq 0 ];do
    echo ""
    read -rp "Enter the path of the dictionary file> " dfile ; echo ""
    if [ -f "$dfile" ];then
      istext=$(file "$dfile" | awk '{print $2}')
      if [[ $istext = "ASCII" ]];then
        l=$(wc -l "$dfile" | awk '{print $1}')
        co=1
        su=0
        tput civis
        echo "Take it slow and go for coffe.The obtained data will be written to the temporary directory and will be saved to disk when the script execution is completely finished."
        while IFS= read -r sub
        do
          if host "$fqdn"."$1" | head -1 | grep "has address" && echo "$fqdn.$1" >> $dicc_outfile;then
            su=$((su+1))
          fi
          echo -ne " Using entry: $co of $l. \r"
          co=$((co+1))
        done < <(grep -v '^ *#' < "$dfile")
        if [ $su -ge 1 ];then
          
          echo "Found $su subdomains."
        else
          echo " Found $su subdomains."
        fi
        check=1
      else
        echo "the file is not ASCII text. Can't use it."
        break
      fi
    else
      echo "File $dfile does not exists."
      break
    fi
  done
  dnsWebServersEnum "$1"
}
dictionaryAttack(){ 
  tput civis
  bitquark="$tmpdir/bit.txt"
  dicc="$tmpdir/bitq.txt"
  dicc_outfile="$tmpdir/dicctionary.results.txt"
  echo "" > $dicc_outfile
  echo " Using the first 1.000 records of the dictionary: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt Courtesy of seclists ;)Take it slow and go for coffe.The obtained data will be written to the temporary directory and will be saved to disk when the script execution is completely finished."
  curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -o $bitquark
  l_bitq=$(cat $bitquark | wc -l)
  if [ $l_bitq -gt 999 ];then
    cat $bitquark | head -1000  > $dicc
    l=$(wc -l $dicc | awk '{print $1}')
    c=1
    s=0
    while IFS= read -r fqdn;do
      if host "$fqdn"."$1" | head -1 | grep "has address" && echo "$fqdn.$1" >> $dicc_outfile;then
        s=$((s+1))
      fi
      echo -ne " Using entry: $c of$l. \r"
      c=$((c+1))
    done < <(grep -v '^ *#' < $dicc)
    if [ $s -ge 1 ];then
      echo "[+] Found $s subdomains."
    else
      echo "!!] Found $s subdomains."
    fi
  else
    echo "Could not download dictionary from seclists url."
    dictionaryAttackCustom "$1"
  fi
  dnsWebServersEnum "$1"
}
bruteForceDNS(){ 
  echo "Fuzzing subdomains of $1 "
  echo "Do yo want to use a custom dictionary? [C=custom/d=Default]"
  echo "Default: Provides a dictionary with the top 1000 of the most commonly used subdomains.Custom: Use your own custom dictionary."
  while true; do
    echo ""
    read -rp "[D/c]> " dc
    echo ""
    case $dc in
      [Dd]* ) dictionaryAttack "$1"; break;;
      [Cc]* ) dictionaryAttackCustom "$1"; break;;
      * ) echo "Please answer D or C.";;
    esac
  done
}
checkHTTPServers(){ 
  tput civis
  domains=$1
  root_domain=$2
  count_domains=$(cat $domains | wc -l)
  echo "" > $output/$root_domain.webservers && webservers_outfile="$output/$root_domain.webservers"
  echo "Lodaed $count_domains targets...This output will be saved to '$webservers_outfile' file. Keep calm and go for a beer"
  round=0
  servers=0
  while read domain;do
    round=$((round+1))
    response=$(curl -m 3 --head --silent --output /dev/null --write-out '%{http_code}' $domain) 
    if (($response >= 100 && $response <= 599)); then 
      echo "The domain $domain has a web server. [HTTP:$response]"
      echo "$domain" >> $webservers_outfile
      servers=$((servers+1))
    else
      response=$(curl -m 3 --head --silent --output /dev/null --write-out '%{http_code}' https://$domain) 
      if (($response >= 100 && $response <= 599)); then 
        echo "The domain $domain has a web server. [HTTPS:$response]"
        echo "https://$domain" >> $webservers_outfile
        servers=$((servers+1))
      fi
    fi
    percent_print=$(echo "scale=2; ($round / $count_domains) * 100" | bc)
    rest=$(echo "$count_domains - $round" | bc)
    echo -ne "[$percent_print%] $servers found - $rest remaining domains \r"
  done < $domains
  sed -i '/^$/d' $webservers_outfile
  echo ""
  echo " Output files"
  echo "$output/$root_domain.subdomains.txt\t Subdomains obtained from crt.sh."
  echo "$output/$root_domain.wildcard.txt\t Wildcard subdomains obtained from crt.sh."
  echo "$output/$root_domain-all.txt\t The previous files without wildcard mask *."
  echo "$output/$root_domain.webservers.txt\t Public web servers/apps from $root_domain domain."
  clean
}
crtSH(){ 
  dictionary_results="$tmpdir/dicctionary.results.txt"
  domain_search=$1
  crtshoutput="$tmpdir/crtsh-output.txt"
  crtsh_parsed_output="$tmpdir/crt.sh.reg"
  subdomain_file="$output/$domain_search.subdomains.txt"
  subdomain_wildcard_file="$output/$domain_search.wildcard.txt"
  final_outputfile="$output/$domain_search-all.txt"
  echo "" > $subdomain_file && echo "" > $subdomain_wildcard_file
  echo " Finding subdomains - abusing Certificate Transparency Logs using https://crt.sh/"
  curl -sk "https://crt.sh/?q=${domain_search}&output=json" -o $crtshoutput 2>&1
  if [ $? ];then 
    cat $crtshoutput | sed 's/,/\n/g' | grep 'common_name' | cut -d : -f 2 | sed 's/"//g' | sed 's/\\n/\n/g' > $crtsh_parsed_output
    echo ""
    size_crtsh_output=$(cat $crtsh_parsed_output | sort -u | wc -l) 
    cat $crtsh_parsed_output | grep '*.' >/dev/null 2>&1
    if [ $? ];then 
      crtsh_parsed_output_wildard_size=$(cat $crtsh_parsed_output | sort -u | grep '*.' | wc -l) 
      crtsh_parsed_output_no_wildard_size=$(cat $crtsh_parsed_output | sort -u | grep -v '*.' | wc -l) 
      cat $crtsh_parsed_output | sort -u | sed 's/*\.//g'
      echo " The complete record will be saved in the '$subdomain_file' file."
      cat $crtsh_parsed_output | sort -u | sed 's/*\.//g' > $subdomain_file
      echo " $crtsh_parsed_output_wildard_size subdomains with wildcard (*.<subdomain>.$domain_search) masks have been found. It is possible that there are more third or fourth level subdomains behind these masks."
      echo "" && cat $crtsh_parsed_output | grep '*.' | sort -u 
      echo " Complete output will be saved in the '$subdomain_wildcard_file' file."
      cat $crtsh_parsed_output | grep '*.' | sort -u > $subdomain_wildcard_file
      echo " CRTsh results"
      echo "[$crtsh_parsed_output_no_wildard_size] subdomain found"
      echo "[$crtsh_parsed_output_wildard_size] wildcard subdomains found"
      echo "[$size_crtsh_output] total subdomains"
    else 
      cat $crtsh_parsed_output | sort -u 
      echo " The complete record will be saved in the '$subdomain_file' file."
      cat $crtsh_parsed_output | sort -u > $subdomain_file
      echo "CRTsh results[$size_crtsh_output] total subdomains found"
    fi
    cat $subdomain_wildcard_file | sed 's/*\.//g' > $tmpdir/0.txt
    cat $dictionary_results > $tmpdir/1.txt 2>/dev/null
    cat $subdomain_file > $tmpdir/2.txt
    cat $tmpdir/1.txt $tmpdir/2.txt > $tmpdir/merged.txt
    cat $tmpdir/0.txt >> $tmpdir/merged.txt
    sed -i '/^$/d' $tmpdir/merged.txt
    cp $tmpdir/merged.txt $final_outputfile
    echo " Some subdomains may contain applications or web servers. DNSExplorer provides fast and easy functionality to discover web servers on the most common ports (80, 443)."
    checkHTTPServers "$final_outputfile" "$domain_search"
  else
    echo "Unable to connect to CTR.sh "
    checkHTTPServers "$final_outputfile" "$domain_search"
  fi
}
dnsWebServersEnum(){
  connected=$(echo -n | openssl s_client -connect  "$1:443" 2>/dev/null | head -1 | awk -F "(" '{print $1}')
  if [[ "$connected" == "CONNECTED" ]];then
      DNS=$(echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | sed 's/\                //'|grep -i "DNS:" | awk -F ":" '{print $1}')
      if [[ "$DNS" == "DNS" ]];then
          echo " The domain $1 has a secure webserver and your certificate have these alternate domain names:"
          echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:"| tr ',' '\n'| sed 's/\               //' | sed 's/\s//g' | sed 's/DNS://g'
          subjects=$(echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:" | tr ',' '\n' | sed 's/\               //' | wc -l)
          crtSH "$1"
      else
          echo "Domain $1 has secure website at $1:443, but does not have alternate subject names."
          crtSH "$1"
      fi
  else
      echo "No website found on $1:443"
  fi
}
initHostRecon(){
  echo "Finding IP address for A records"
  host "$1" | grep 'has address' | awk '{print $4}'
  echo "Finding IPv6 address for AAA records"
  if host "$1" | grep 'IPv6' >/dev/null 2>&1;then
    host "$1" | grep 'IPv6'| awk '{print $5}'
    echo ""
  else
    echo "Hosts $1 has not IPv6 address"# .*$
  fi
  echo "Finding mail server address for $1 domain"
  if host -t MX "$1" | grep 'mail' >/dev/null 2>&1;then
    host "$1" | grep 'mail' | awk '{print $6,$7}'
    echo ""
  else
    echo "Hosts $1 has not mail server records"
  fi
  echo "Finding CNAME records for $1 domain"
  if host -t CNAME "$1" | grep 'alias' >/dev/null 2>&1;then
    host -t CNAME "$1" | awk '{print $1,$4,$6}'
    echo ""
  else
    echo "Hosts $1 has not alias records"
  fi
  echo "Finding text description for $1 domain"
  if host -t txt "$1" | grep 'descriptive' >/dev/null 2>&1;then
    host -t txt "$1" | grep 'descriptive'
    echo ""
  else
    echo "Hosts $1 has not description records"
  fi
}
doZoneTransfer(){
  if host -t NS "$1" | grep 'name server' >/dev/null 2>&1;then
    host -t NS "$1" | cut -d " " -f 4
    host -t NS "$1" | cut -d " " -f 4 > $tmpdir/NameServers.txt
    ns=$(wc -l $tmpdir/NameServers.txt | awk '{print $1}')
    echo " $ns DNS Servers was found, trying ZoneTransfer on these servers"
    while IFS= read -r nameserver;do
      host -t axfr "$1" "$nameserver" | grep'Received ([0-9]+) bytes from [0-9\.]+#[0-9]+ in ([0-9]+) ms' >/dev/null 2>&1
      if [ $? -eq 0 ];then
        echo "NameServer $nameserver accept ZoneTransfer"
        success=0
      else
        echo "NameServer $nameserver does not accept zone transfer"
      fi
    done < <(grep -v '^ *#' < $tmpdir/NameServers.txt)
    if [ $success -eq 0 ];then
      echo " DNS zone transfer was possible, no bruteforce attacks on the subdomains are required. "
      dnsWebServersEnum "$1"
      clean
    else
      echo " DNS zone transfer was not possible, DNS servers are not accept it"
      while true; do
        echo ""
        tput cnorm
        echo ""
        read -rp "Do you want to brute force subdomains? [Y/n]> " yn
        echo ""
        case $yn in
          [Yy]* ) bruteForceDNS "$1"; clean; break;;
          [Nn]* ) dnsWebServersEnum "$1"; clean;;
          * ) echo "Please answer yes or no.";;
        esac
      done
    fi
  fi
}
basicRecon(){ 
  success=1
  initHostRecon "$1"
  doZoneTransfer "$1"
}
help(){ 
    echo "                              
        \e[92m@@@  @@@  @@@@@@@@  @@@       @@@@@@@   
        @@@  @@@  @@@@@@@@  @@@       @@@@@@@@  
        @@!  @@@  @@!       @@!       @@!  @@@  
        !@!  @!@  !@!       !@!       !@!  @!@  
        @!@!@!@!  @!!!:!    @!!       @!@@!@!   
        !!!@!!!!  !!!!!:    !!!       !!@!!!    
        !!:  !!!  !!:       !!:       !!:       
        :!:  !:!  :!:        :!:      :!:       
        ::   :::   :: ::::   :: ::::   ::       
        :   : :  : :: ::   : :: : :   :        
\e[36mDNSExplorer automates the enumeration of DNS servers and domains using the 'host' tool and the predefined DNS server in /etc/resolv.conf.
\e[36mTo use it run: ./DNSExplorer.sh domain.com"
tput cnorm
}
checkDependencies() { 
    if ! command -v host &> /dev/null
    then
        echo "'host' command is not available, please install the bind-utils/dnsutils package. "
        clean
    fi
    if ! command -v curl &> /dev/null
    then
        echo "'curl' command is not available, please install the curl package. "
        clean
    fi
}
banner(){
    echo "\e[91m
        ▓█████▄  ███▄    █   ██████ ▓█████ ▒██   ██▒ ██▓███   ██▓     ▒█████   ██▀███  ▓█████  ██▀███  
        ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▓██▒    ▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ ▓██ ▒ ██▒
        ░██   █▌▓██  ▀█ ██▒░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░    ▒██░  ██▒▓██ ░▄█ ▒▒███   ▓██ ░▄█ ▒
        ░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██░    ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ ▒██▀▀█▄  
        ░▒████▓ ▒██░   ▓██░▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░██████▒░ ████▓▒░░██▓ ▒██▒░▒████▒░██▓ ▒██▒
        ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
        ░ ░  ░    ░   ░ ░ ░  ░  ░     ░    ░    ░  ░░         ░ ░   ░ ░ ░ ▒    ░░   ░    ░     ░░   ░ 
        ░             ░       ░     ░  ░ ░    ░               ░  ░    ░ ░     ░        ░  ░   ░     
        ░ v:1.0.1     ░ By: Danilo Basanta (https://github.com/dabasanta/) | (https://www.linkedin.com/in/danilobasanta/)"
}
main(){
  banner
  checkDependencies
  
  if ping -c 1 "$1" > /dev/null 2>&1;then
      if host "$1" > /dev/null 2>&1;then
          basicRecon "$1"
      else
          echo "No route to host, please verify your DNS server or internet connection"
          clean
      fi
  else
      echo "PING was not success, does server ignoring ICMP packets?"
      if host "$1" > /dev/null 2>&1;then
          echo "Running checks anyway"
          basicRecon "$1"
      else
          echo "No route to host, please verify your DNS server or internet connection"
          clean
      fi
  fi
}
  if [ "$1" = "-h" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-help" ] || [ "$2" = "-h" ] || [ "$2" = "--help" ] || [ "$2" = "-help" ] || [ "$2" = "help" ];then 
        help
  else
    main "$1"
  fi
else
    echo "Invalid arguments "
    help
    tput cnorm
    exit 1
fi