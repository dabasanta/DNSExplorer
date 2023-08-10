#!/usr/bin/env bash
# @author: Danilo Basanta
# @author-linkedin: https://www.linkedin.com/in/danilobasanta/
# @author-github: https://github.com/dabasanta

# Changing between bash colors in outputs
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

tmpdir="/tmp/dnsexplorer" # Setting tmp path
mkdir -p $tmpdir  # Creating temporally directory
tput civis  # Making beep off

clean(){  # Cleaning the system after execution
    echo -e "\n\n"
    rm -rf $tmpdir
    echo -e "${end}Happy hunting."
    tput cnorm
    exit 0
}

function scape() {  # Catch the ctrl_c INT key
  clean
}

trap scape INT

# Creating output directory
mkdir -p $1.out
output="$1.out"

dictionaryAttackCustom() {
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

  echo -e "$info Using the dictionary '$dfile'. The process may take some time depending on the number of records.\n"
  echo -e "$question\tThis file has $lon_dicc records, 20 parallel processes will be used to speed up the attack, press any key to start\n"
  read -n 1 -s -r -p ""

  grep -v '^ *#' < "$dfile" | xargs -P 20 -I {} sh -c '
    sub="$1"
    if host "$sub.$2" | head -1 | grep -q "has address"; then
      echo "$sub.$2" >> "$3"
      printf ".... Subdomain found: %s.%s\n" "$sub" "$2"
    fi
    printf "[~] Reading file... \r"
  ' _ {} "$1" "$dicc_outfile"

  total=$(wc -l $dicc_outfile)
  echo -e "$info $total Subdomains found.$end"
  sleep 5s
  dnsWebServersEnum "$1"
}

dictionaryAttack(){ # Performs a dictionary attack agains the target
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
  ' _ {} "$1" "$dicc_outfile"
  else
    echo -e "$error Could not download dictionary from seclists url.$end"
    dictionaryAttackCustom "$1"
  fi
  dnsWebServersEnum "$1"
}

bruteForceDNS(){ # Trigger the dictorinary attack

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

check_web_server() {
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

crtSH(){ # Abuse of crt.sh website - Internet connection required.
  dictionary_results="$tmpdir/dicctionary.results.txt"
  domain_search=$1
  crtshoutput="$tmpdir/crtsh-output.txt"
  crtsh_parsed_output="$tmpdir/crt.sh.reg"
  subdomain_file="$output/$domain_search.subdomains.txt"
  subdomain_wildcard_file="$output/$domain_search.wildcard.txt"
  final_outputfile="$output/$domain_search-all.txt"
  echo "" > $subdomain_file && echo "" > $subdomain_wildcard_file
  echo -e "\n$info Finding subdomains - abusing Certificate Transparency Logs using https://crt.sh/\n$end"

  # Starting crt.sh connection
  curl -sk "https://crt.sh/?q=${domain_search}&output=json" -o $crtshoutput 2>&1
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
    echo "" > $output/$domain_search.webservers && webservers_outfile="$output/$domain_search.webservers"
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
    echo "" > $output/$domain_search.webservers && webservers_outfile="$output/$domain_search.webservers"
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
}

dnsWebServersEnum(){
  # Check if the provider domain has a TLS site for enum the alternative DNS names by using OpenSSL
  connected=$(echo -n | openssl s_client -connect  "$1:443" 2>/dev/null | head -1 | awk -F "(" '{print $1}')

  if [[ "$connected" == "CONNECTED" ]];then
      DNS=$(echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | sed 's/\                //'|grep -i "DNS:" | awk -F ":" '{print $1}')

      if [[ "$DNS" == "DNS" ]];then
          echo -e "\n$info The domain $resalted_output$1$cyan has a secure webserver and your certificate have these alternate domain names:\e[92m"
          echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:"| tr ',' '\n' | sed 's/\               //' | sed 's/\s//g' | sed 's/DNS://g'
          subjects=$(echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:" | tr ',' '\n' | sed 's/\               //' | wc -l)
          crtSH "$1"
      else
          echo -e "$question Domain $1 has secure website at $1:443, but does not have alternate subject names.\n"
          crtSH "$1"
      fi
  else
      echo -e "$error No website found on $1:443\n"
  fi
}

initHostRecon(){
  echo -e "$info Finding IP address for A records \e[92m"
  # A Records
  host "$1" | grep 'has address' | awk '{print $4}'

  echo -e "$info Finding IPv6 address for AAA records \e[92m"
  # AAA Records
  if host "$1" | grep 'IPv6' >/dev/null 2>&1;then
    host "$1" | grep 'IPv6'| awk '{print $5}'
    echo -e ""
  else
    echo -e "$question Hosts $1 has not IPv6 address\n"
  fi

  echo -e "$info Finding mail server address for $resalted_output$1$cyan domain \e[92m"
  # MAIL Records
  if host -t MX "$1" | grep 'mail' >/dev/null 2>&1;then
    host "$1" | grep 'mail' | awk '{print $6,$7}'
    echo -e ""
  else
    echo -e "$question Hosts $1 has not mail server records\n"
  fi
  
  echo -e "$info Finding CNAME records for $resalted_output$1$cyan domain \e[92m"
  # CNAME Records
  if host -t CNAME "$1" | grep 'alias' >/dev/null 2>&1;then
    host -t CNAME "$1" | awk '{print $1,$4,$6}'
    echo -e ""
  else
    echo -e "$question Hosts $1 has not alias records\n"
  fi

  echo -e "$info Finding text description for $resalted_output$1$cyan domain \e[92m"
` # TXT Records`
  if host -t txt "$1" | grep 'descriptive' >/dev/null 2>&1;then
    host -t txt "$1" | grep 'descriptive'
    echo -e ""
  else
    echo -e "$question Hosts $1 has not description records\n"
  fi
}

doZoneTransfer(){
  if host -t NS "$1" | grep 'name server' >/dev/null 2>&1;then
    host -t NS "$1" | cut -d " " -f 4
    host -t NS "$1" | cut -d " " -f 4 > $tmpdir/NameServers.txt
    ns=$(wc -l $tmpdir/NameServers.txt | awk '{print $1}')
    echo -e "\n$info $ns DNS Servers was found, trying ZoneTransfer on these servers$end"

    while IFS= read -r nameserver;do
      host -t axfr "$1" "$nameserver" | grep -E 'Received ([0-9]+) bytes from [0-9\.]+#[0-9]+ in ([0-9]+) ms' >/dev/null 2>&1
      if [ $? -eq 0 ];then
        echo -e "$green NameServer $nameserver accept ZoneTransfer$end\n"
        success=0
      else
        echo -e "$error NameServer $nameserver does not accept zone transfer$end"
      fi
    done < <(grep -v '^ *#' < $tmpdir/NameServers.txt)

    if [ $success -eq 0 ];then
      echo -e "\n$ok DNS zone transfer was possible, no bruteforce attacks on the subdomains are required. $end\n"
      dnsWebServersEnum "$1"
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
          [Yy]* ) bruteForceDNS "$1"; clean; break;;
          [Nn]* ) dnsWebServersEnum "$1"; clean;;
          * ) echo -e "$error Please answer yes or no.$end\n";;
        esac
      done
    fi
  fi
}

basicRecon(){ # Init recon with 'host' command
  success=1
  initHostRecon "$1"
  doZoneTransfer "$1"
  
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
        ░ v:1.0.1     ░$end By: Danilo Basanta (https://github.com/dabasanta/) | (https://www.linkedin.com/in/danilobasanta/)\n\n"

}

main(){
  banner
  checkDependencies
  # Check very basic ping
  if ping -c 1 "$1" > /dev/null 2>&1;then
      if host "$1" > /dev/null 2>&1;then
          basicRecon "$1"
      else
          echo -e "$error No route to host, please verify your DNS server or internet connection$end"
          clean
      fi
  else
      echo -e "$question PING was not success, does server ignoring ICMP packets?$end"
      if host "$1" > /dev/null 2>&1;then
          echo -e "$info Running checks anyway$end\n"
          basicRecon "$1"
      else
          echo -e "$error No route to host, please verify your DNS server or internet connection$end"
          clean
      fi
  fi
}

# Init flow
if [ $# == 1 ];then # Validate params

  if [ "$1" = "-h" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-help" ] || [ "$2" = "-h" ] || [ "$2" = "--help" ] || [ "$2" = "-help" ] || [ "$2" = "help" ];then # Need help?
    help
  elif [ $# == 1 ];then # pass
    main "$1"
  fi
elif [ $# == 2 ];then
  if [ "$1" = "-h" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-help" ] || [ "$2" = "-h" ] || [ "$2" = "--help" ] || [ "$2" = "-help" ] || [ "$2" = "help" ];then # Doble Check
        help
  else
    main "$1"
  fi
else
    echo -e "$error Invalid arguments $end"
    help
    tput cnorm
    exit 1
fi

