#!/usr/bin/env bash
# @author: Danilo Basanta
# @author-linkedin: https://www.linkedin.com/in/danilobasanta/
# @author-github: https://github.com/dabasanta

# GLOBAL VARS
export DOMAIN="None"
export EXTENDED_CHECKS=false
export DNS_BRUTE_THREADS=0

function scape() {
  clean
}
trap scape INT

tmpdir="/tmp/dnsexplorer"
mkdir -p $tmpdir
tput civis

end="\e[0m"
info="\e[1m\e[36m[+]"
cyan="\e[1m\e[36m"
output_color="\e[0m\e[36m[++]"
error="\e[1m\e[91m[!!]"
question="\e[1m\e[93m"
yellow="\e[1m\e[93m"
green="\e[92m"
ok="\e[1m\e[92m"
resalted_output="\e[1;37m"

clean(){
    echo -e "\n\n"
    rm -rf $tmpdir
    echo -e "${end}Happy hunting."
    tput cnorm
    exit 0
}

dictionaryAttackCustom() { #5
  dicc_outfile="$tmpdir/dictionary.results.txt"
  : > "$dicc_outfile"

  check=0
  while [ "$check" -eq 0 ]; do
    echo -e "$question"
    read -rp "Ingrese la ruta del archivo de diccionario> " dfile
    echo -e "$end"

    if [ ! -f "$dfile" ] || [[ $(file "$dfile" | awk '{print $2}') != @(ASCII|Unicode) ]]; then
      echo -e "$error El archivo $dfile no existe o no es un archivo de texto ASCII/Unicode."
    else
      check=1
    fi
  done

  lon_dicc=$(wc -l < "$dfile")
  tput civis

  threads=$(echo "scale=0; ($lon_dicc * 0.15 + 0.5)/1" | bc)
  [ "$threads" -lt 1 ] && threads=1
  [ "$threads" -gt 25 ] && threads=25
  [ "$DNS_BRUTE_THREADS" -ne 0 ] && threads="$DNS_BRUTE_THREADS"
  echo -e "$question\tThis file has $lon_dicc records, $threads parallel processes will be used to speed up the attack, press any key to start\n"
  read -n 1 -s -r -p ""

  grep -v '^ *#' < "$dfile" | xargs -P $threads -I {} sh -c '
    sub="$1"
    if host "$sub.$2" | head -1 | grep -q "has address"; then
      echo "$sub.$2" >> "$3"
      printf ".... Subdomain found: %s.%s\n" "$sub" "$2"
    fi
    printf "[~] Reading file... \r"
  ' _ {} "$DOMAIN" "$dicc_outfile"

  total=$(wc -l $dicc_outfile)
  echo -e "$info $total Subdomains found.$end"
  sleep 5s
  dnsWebServersEnum
}

dictionaryAttack(){ #5
  tput civis
  bitquark="$tmpdir/bit.txt"
  dicc="$tmpdir/bitq.txt"
  dicc_outfile="$tmpdir/dicctionary.results.txt"
  echo "" > $dicc_outfile
  echo -e "\n$info Using the first 1.000 records of the dictionary:$green https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt\n\e[1m\e[36mCourtesy of seclists ;)\nTake it slow and go for coffe.$end\nThe obtained data will be written to the temporary directory and will be saved to disk when the script execution is completely finished.\n"
  curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -o $bitquark
  l_bitq=$(cat $bitquark | wc -l)
  
  if [ $l_bitq -gt 999 ];then
    cat $bitquark | head -1000  > $dicc

    grep -v '^ *#' < "$dicc" | xargs -P 10 -I {} sh -c '
    sub="$1"
    if host "$sub.$2" | head -1 | grep -q "has address"; then
      echo "$sub.$2" >> "$3"
      printf ".... Subdomain found: %s.%s\n" "$sub" "$2"
    fi
    printf "[~] Reading file... \r"
  ' _ {} "$DOMAIN" "$dicc_outfile"
  else
    echo -e "$error Could not download dictionary from seclists url.$end"
    dictionaryAttackCustom
  fi
  dnsWebServersEnum
}

bruteForceDNS(){ # Trigger the dictorinary attack
  #dnsWebServersEnum
  echo -e " 
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
                                                                                     
  \n\t\t$output_color Fuzzing subdomains of $1[++]$end\n
  ${question}Do yo want to use a custom dictionary? [c=custom/d=default]$end
  $info Default: Provides a dictionary with the top 1000 of the most commonly used subdomains.
  $info Custom: Use your own custom dictionary.$question\n"

  while true; do
    read -rp "[d/c]> " dc
    case $dc in
      [Dd]* ) dictionaryAttack "$1"; break;;
      [Cc]* ) dictionaryAttackCustom "$1"; break;;
      * ) echo -e "$error Please answer$green D$end \e[1m\e[91mor$end$green\e[1m C$end\e[1m\e[91m.$end\n";;
    esac
  done
}

check_web_server() { #8
  local end="\e[0m"
  local cyan="\e[1m\e[36m"
  local ok="\e[1m\e[92m"
  local resalted_output="\e[1;37m"
  local domain="$1"
  local protocol="$2"
  local webservers_outfile="$3"
  local response=$(curl -m 3 --head --silent --output /dev/null --write-out '%{http_code}' "${protocol}://${domain}")

  if ((response >= 100 && response <= 599)); then
    local secure=""
    local protocol_upper=$(echo "$protocol" | tr '[:lower:]' '[:upper:]')
    [ "$protocol" == "https" ] && secure=" secure"
    echo -e "${end}The domain $resalted_output$domain$end has a$secure web server. [$cyan$protocol_upper$end:$ok$response$end]"
    echo "${protocol}://$domain" >> "$webservers_outfile"
    return 1
  fi
  return 0
}
export -f check_web_server

# Abuse of crt.sh website - Internet connection required.
crtSH(){ #7
  dictionary_results="$tmpdir/dicctionary.results.txt"
  crtshoutput="$tmpdir/crtsh-output.txt"
  crtsh_parsed_output="$tmpdir/crt.sh.reg"
  subdomain_file="$output/$domain_search.subdomains.txt"
  subdomain_wildcard_file="$output/$domain_search.wildcard.txt"
  final_outputfile="$output/$domain_search-all.txt"
  echo "" > $subdomain_file && echo "" > $subdomain_wildcard_file
  echo -e "\n$info Finding subdomains - abusing Certificate Transparency Logs using https://crt.sh/\n$end"

  curl -sk "https://crt.sh/?q=${DOMAIN}&output=json" -o $crtshoutput 2>&1
  if [ $? ];then
    # Getting entire output list
    cat $crtshoutput | sed 's/,/\n/g' | grep 'common_name' | cut -d : -f 2 | sed 's/"//g' | sed 's/\\n/\n/g' > $crtsh_parsed_output
    #echo -e "$ok"
    size_crtsh_output=$(cat $crtsh_parsed_output | sort -u | wc -l) # Size of output list 
    cat $crtsh_parsed_output | grep '*.' >/dev/null 2>&1
    
    if [ $? ];then # If the domain has subdmians, then...
      crtsh_parsed_output_wildard_size=$(cat $crtsh_parsed_output | sort -u | grep '*.' | wc -l) # Size of output list - only wilcard
      crtsh_parsed_output_no_wildard_size=$(cat $crtsh_parsed_output | sort -u | grep -v '*.' | wc -l) # Size of output list - without wilcard
      cat $crtsh_parsed_output | sort -u | sed 's/*\.//g' > $subdomain_file # Save subdomains without wildcard
      cat $crtsh_parsed_output | grep '*.' | sort -u > $subdomain_wildcard_file # save subdomains with wildcard
      echo -e "$ok[$resalted_output$crtsh_parsed_output_no_wildard_size$ok] subdomain found"
      echo -e "$ok[$resalted_output$crtsh_parsed_output_wildard_size$ok] wildcard subdomains found"
      echo -e "$ok[$resalted_output$size_crtsh_output$ok] total subdomains"

    else # if domian don't have wildcard subdomains, then...

      cat $crtsh_parsed_output | sort -u > $subdomain_file
      echo -e "$info CRTsh results\n[$size_crtsh_output] total subdomains found"
    fi

    # Consolidate all data in single file
    cat $subdomain_wildcard_file | sed 's/*\.//g' > $tmpdir/0.txt
    cat $dictionary_results > $tmpdir/1.txt 2>/dev/null
    cat $subdomain_file > $tmpdir/2.txt
    cat $tmpdir/1.txt $tmpdir/2.txt > $tmpdir/merged.txt
    cat $tmpdir/0.txt >> $tmpdir/merged.txt
    sed -i '/^$/d' $tmpdir/merged.txt
    cp $tmpdir/merged.txt $final_outputfile
    
    count_domains=$(wc -l < "$final_outputfile")
    threads=$(echo "scale=0; ($count_domains * 0.15 + 0.5)/1" | bc)
    [ "$threads" -lt 1 ] && threads=1
    echo "" > $output/$DOMAIN.webservers && webservers_outfile="$output/$DOMAIN.webservers"
    echo -e "$info Lodaed $count_domains targets...$end\n\n"
    round=0
    servers=0

    while read -r domain; do
      ((round++))
      parallel -j "$threads" check_web_server ::: "$domain" ::: http https ::: "$webservers_outfile"
      ((servers += $?))

      percent_print=$(printf "%.2f" "$(echo "$round / $count_domains * 100" | bc -l)")
      rest=$((count_domains - round))
      echo -ne "$yellow[$percent_print%] $servers found - $rest remaining domains \r"
    done < "$final_outputfile"

  else
    echo -e "$error Unable to connect to CTR.sh$end"
    # Consolidate all data in single file
    cat $subdomain_wildcard_file | sed 's/*\.//g' > $tmpdir/0.txt
    cat $dictionary_results > $tmpdir/1.txt 2>/dev/null
    cat $subdomain_file > $tmpdir/2.txt
    cat $tmpdir/1.txt $tmpdir/2.txt > $tmpdir/merged.txt
    cat $tmpdir/0.txt >> $tmpdir/merged.txt
    sed -i '/^$/d' $tmpdir/merged.txt
    cp $tmpdir/merged.txt $final_outputfile

    count_domains=$(wc -l < "$final_outputfile")
    threads=$(echo "scale=0; ($count_domains * 0.15 + 0.5)/1" | bc)
    [ "$threads" -lt 1 ] && threads=1
    echo "" > $output/$DOMAIN.webservers && webservers_outfile="$output/$DOMAIN.webservers"
    echo -e "$info Lodaed $count_domains targets...$end\n\n"
    round=0
    servers=0

    while read -r domain; do
      ((round++))
      parallel -j "$threads" check_web_server ::: "$domain" ::: http https ::: "$webservers_outfile"
      ((servers += $?))

      percent_print=$(printf "%.2f" "$(echo "$round / $count_domains * 100" | bc -l)")
      rest=$((count_domains - round))
      echo -ne "$yellow[$percent_print%] $servers found - $rest remaining domains$end\r"
    done < "$final_outputfile"
  fi

  ### AQUI CONTINUA LA EJECUCION DEL SCRIPT, SI EL --EXTENDED FUE APLICADO, SE DEBE VERIFICAR AQUI PARA SABER SI SE TOMA LA LISTA DE LOS SERVIDORES WEB Y SE ENUMERAN
  #####
  #####
  #####

}

dnsWebServersEnum(){ #6
  connected=$(echo -n | openssl s_client -connect  "$DOMAIN:443" 2>/dev/null | head -1 | awk -F "(" '{print $1}')

  if [[ "$connected" == "CONNECTED" ]];then
      DNS=$(echo -n | openssl s_client -connect "$DOMAIN:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | sed 's/\                //'|grep -i "DNS:" | awk -F ":" '{print $1}')

      if [[ "$DNS" == "DNS" ]];then
          echo -e "\n$info The domain $resalted_output$DOMAIN$cyan has a secure webserver and your certificate have these alternate domain names:\e[92m"
          echo -n | openssl s_client -connect "$DOMAIN:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:"| tr ',' '\n' | sed 's/\               //' | sed 's/\s//g' | sed 's/DNS://g'
          subjects=$(echo -n | openssl s_client -connect "$DOMAIN:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:" | tr ',' '\n' | sed 's/\               //' | wc -l)
          crtSH
      else
          echo -e "$question Domain $DOMAIN has secure website at $DOMAIN:443, but does not have alternate subject names.\n"
          crtSH
      fi
  else
      echo -e "$error No website found on $DOMAIN:443\n"
  fi

  ## LLAMA A CRTSH, INCLUSO SI NO HAY WEBSERVER QUE CHEKEAR CON OPENSSL.
  ## 
}

initHostRecon(){ #3
  echo -e "$info Finding IP address for A records \e[92m"
  # A Records
  host "$DOMAIN" | grep 'has address' | awk '{print $4}'

  echo -e "$info Finding IPv6 address for AAA records \e[92m"
  # AAA Records
  if host "$DOMAIN" | grep 'IPv6' >/dev/null 2>&1;then
    host "$DOMAIN" | grep 'IPv6'| awk '{print $5}'
    echo -e ""
  else
    echo -e "$question Hosts $DOMAIN has not IPv6 address\n"
  fi

  echo -e "$info Finding mail server address for $resalted_output$DOMAIN$cyan domain \e[92m"
  # MAIL Records
  if host -t MX "$DOMAIN" | grep 'mail' >/dev/null 2>&1;then
    host "$DOMAIN" | grep 'mail' | awk '{print $6,$7}'
    echo -e ""
  else
    echo -e "$question Hosts $DOMAIN has not mail server records\n"
  fi
  
  echo -e "$info Finding CNAME records for $resalted_output$DOMAIN$cyan domain \e[92m"
  # CNAME Records
  if host -t CNAME "$DOMAIN" | grep 'alias' >/dev/null 2>&1;then
    host -t CNAME "$DOMAIN" | awk '{print $1,$4,$6}'
    echo -e ""
  else
    echo -e "$question Hosts $DOMAIN has not alias records\n"
  fi

  echo -e "$info Finding text description for $resalted_output$DOMAIN$cyan domain \e[92m"
` # TXT Records`
  if host -t txt "$DOMAIN" | grep 'descriptive' >/dev/null 2>&1;then
    host -t txt "$DOMAIN" | grep 'descriptive'
    echo -e ""
  else
    echo -e "$question Hosts $DOMAIN has not description records\n"
  fi
}

doZoneTransfer(){ #4
  success=1
  if host -t NS "$DOMAIN" | grep 'name server' >/dev/null 2>&1;then
    host -t NS "$DOMAIN" | cut -d " " -f 4
    host -t NS "$DOMAIN" | cut -d " " -f 4 > $tmpdir/NameServers.txt
    ns=$(wc -l $tmpdir/NameServers.txt | awk '{print $1}')
    echo -e "\n$info $ns DNS Servers was found, trying ZoneTransfer on these servers$end"

    while IFS= read -r nameserver;do
      host -t axfr "$DOMAIN" "$nameserver" | grep -E 'Received ([0-9]+) bytes from [0-9\.]+#[0-9]+ in ([0-9]+) ms' >/dev/null 2>&1
      if [ $? -eq 0 ];then
        echo -e "$green NameServer $nameserver accept ZoneTransfer$end\n"
        success=0
      else
        echo -e "$error NameServer $nameserver does not accept zone transfer$end"
      fi
    done < <(grep -v '^ *#' < $tmpdir/NameServers.txt)

    if [ $success -eq 0 ];then
      echo -e "\n$ok DNS zone transfer was possible, no bruteforce attacks on the subdomains are required. $end\n"
      dnsWebServersEnum
      clean
    else
      echo -e "\n$error DNS zone transfer was not possible, DNS servers are not accept it"

      while true; do
        echo ""
        tput cnorm
        echo -e "$question"
        read -rp "Do you want to brute force subdomains? [Y/n]> " yn
        echo -e "$end"

        case $yn in
          [Yy]* ) bruteForceDNS; clean; break;;
          [Nn]* ) dnsWebServersEnum; clean;;
          * ) echo -e "$error Please answer yes or no.$end\n";;
        esac
      done
    fi
  fi
}

# Init recon with 'host' command
basicRecon(){  #2
  initHostRecon
  doZoneTransfer
}

help(){ # Simply help function
    echo -e "                               
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


\e[36mDNSExplorer$ok automates the enumeration of DNS servers and domains using the 'host' tool and the predefined DNS server in /etc/resolv.conf.

\e[36mTo use it run: $ok./DNSExplorer.sh domain.com$end\n"
tput cnorm
}

checkDependencies() { # Check dependencies: curl, host, parallel.

  declare -A dependencies=(
    ["host"]="bind-utils/dnsutils"
    ["curl"]="curl"
    ["parallel"]="Parallel"
    ["bc"]="BC"
  )

  for cmd in "${!dependencies[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
      echo -e "$error '$cmd' command is not available, please install the ${dependencies[$1]} package. $end"
        clean
    fi
  done
}

banner(){
    echo -e "\e[91m
        ▓█████▄  ███▄    █   ██████ ▓█████ ▒██   ██▒ ██▓███   ██▓     ▒█████   ██▀███  ▓█████  ██▀███  
        ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▓██▒    ▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ ▓██ ▒ ██▒
        ░██   █▌▓██  ▀█ ██▒░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░    ▒██░  ██▒▓██ ░▄█ ▒▒███   ▓██ ░▄█ ▒
        ░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██░    ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ ▒██▀▀█▄  
        ░▒████▓ ▒██░   ▓██░▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░██████▒░ ████▓▒░░██▓ ▒██▒░▒████▒░██▓ ▒██▒
        ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
        ░ ░  ░    ░   ░ ░ ░  ░  ░     ░    ░    ░  ░░         ░ ░   ░ ░ ░ ▒    ░░   ░    ░     ░░   ░ 
        ░             ░       ░     ░  ░ ░    ░               ░  ░    ░ ░     ░        ░  ░   ░     
        ░ v:1.0.1     ░$end By: Danilo Basanta (https://github.com/dabasanta/) | (https://www.linkedin.com/in/danilobasanta/)\n\n


\033[3mThe author does not promote malicious actions or the use of the script for illegal operations. Remember to always obtain prior permission from the target company's system administrators before performing any malicious actions.\033[0m\n\n"
}

main(){ #1
  mkdir -p $DOMAIN.out
  output="$DOMAIN.out"
  banner
  checkDependencies
  if ping -c 1 "$DOMAIN" > /dev/null 2>&1;then
      if host "$DOMAIN" > /dev/null 2>&1;then
          basicRecon "$DOMAIN"
      else
          echo -e "$error No route to host, please verify your DNS server or internet connection$end"
          clean
      fi
  else
      echo -e "${question}PING was not success, does server ignoring ICMP packets?$end"
      if host "$DOMAIN" > /dev/null 2>&1;then
          echo -e "${info}Running checks anyway$end\n"
          basicRecon "$DOMAIN"
      else
          echo -e "$error No route to host, please verify your DNS server or internet connection$end"
          clean
      fi
  fi
}

# Init  flow
if [ "$1" = "-h" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$2" = "-h" ] || [ "$2" = "--help" ] || [ "$2" = "help" ]; then
  help
elif [ $# -eq 2 ]; then
  if [ "$2" = "--extended" ]; then
    DOMAIN=$1
    EXTENDED_CHECKS=true
    main "$DOMAIN"
  else
    echo -e "$error Parameter '$2' is not recognized $end"
    help
    tput cnorm
    exit 1
  fi
elif [ $# -eq 0 ]; then
  help
  tput cnorm
  exit 1
else
  DOMAIN=$1
  main "$DOMAIN"
fi