#!/usr/bin/env bash
# @author: Danilo Basanta
# @author-linkedin: https://www.linkedin.com/in/danilobasanta/
# @author-github: https://github.com/dabasanta

# GLOBAL VARS - DO NOT MODIFY
export DOMAIN="None"
export EXTENDED_CHECKS=false
export zone_transfer="No"
export dns_servers_count=0
export subdomains_count=0
export webservers_count=0
# Modify the DNS_BRUTE_THREADS variable to set the number of threads to use in the custom-dictionary attack.
# By default, the script will use 15% of the number of records in the dictionary.
export DNS_BRUTE_THREADS=0

# CRTL+C handler
function scape() {
  clean
}
trap scape INT

# Creating the tmp directory
tmpdir="/tmp/dnsexplorer"
mkdir -p $tmpdir
mkdir -p $tmpdir/whatweb
mkdir -p $tmpdir/wafw00f
tput civis

end="\e[0m"
info="\e[36m[+]"
cyan="\e[36m"
output_color="\e[0m\e[36m"
error="\e[1m\e[91m[!]"
question="\e[93m"
yellow="\e[1m\e[93m"
green="\e[92m"
ok="\e[1m\e[92m"
resalted_output="\e[1;37m"

# Clean -exit- function
clean(){
    echo -e "\n\n"
    rm -rf $tmpdir
    echo -e "${end}Happy hunting."
    tput cnorm
    exit 0
}

# Custom dicctionary attack function
dictionaryAttackCustom() { #5
  dicc_outfile="$tmpdir/dicctionary.results.txt"
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
  [ "$threads" -gt 40 ] && threads=40
  [ "$DNS_BRUTE_THREADS" -ne 0 ] && threads="$DNS_BRUTE_THREADS"
  echo -e "    ${question}This file has $lon_dicc records, $threads parallel processes will be used to speed up the attack, press any key to start\n"
  read -n 1 -s -r -p ""

  grep -Eva '[^a-zA-Z0-9\-_]' < "$dfile" | xargs -P $threads -I {} sh -c '
    GREEN="\033[32m"
    resalted_output="\e[1;37m"
    RESET="\033[0m"
    lon_dicc="$4"
    if host "$1.$2" 2>/dev/null | head -1 | grep -q "has address"; then
      echo "$1.$2" >> "$3"
      printf "    [+] Found: ${resalted_output}%s.%s${RESET}\n" "$1" "$2"
    fi
    
    echo "." >> /tmp/dnsexplorer/tracker.txt
    len=$(wc -l < /tmp/dnsexplorer/tracker.txt)
    dicc=$()
    percent=$(echo "scale=2; ($len / $lon_dicc) * 100" | bc)
    printf "${GREEN}[%.0f%%] Reading file...${RESET}\r" $percent
  ' _ {} "$DOMAIN" "$dicc_outfile" "$lon_dicc"

  total=$(wc -l < $dicc_outfile)
  echo ""
  echo -e "${info} $total Subdomains found.${end}"
  echo ""
  crtSH "dicattack"
}

# Dictionary attack function
dictionaryAttack(){ #5
  tput civis
  bitquark="$tmpdir/bit.txt"
  dicc_outfile="$tmpdir/dicctionary.results.txt"
  echo "" > $dicc_outfile
  echo -e "\n${info}Using SECLISTS: bitquark-subdomains-top100000.txt${end}\n"
  curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -o $bitquark
  l_bitq=$(cat $bitquark | wc -l)
  touch $tmpdir/tracker.txt
  if [ $l_bitq -gt 999 ];then
    grep -v '^ *#' < "$bitquark" | xargs -P 40 -I {} sh -c '
    GREEN="\033[32m"
    resalted_output="\e[1;37m"
    RESET="\033[0m"

    if host "$1.$2" | head -1 | grep -q "has address"; then
      echo "$1.$2" >> "$3"
      printf "    [+] Found: ${resalted_output}%s.%s${RESET}\n" "$1" "$2"
    fi
    
    echo "." >> /tmp/dnsexplorer/tracker.txt
    len=$(wc -l < /tmp/dnsexplorer/tracker.txt)
    percent=$(echo "scale=2; ($len / 100000) * 100" | bc)
    printf "${GREEN}[%.0f%%] Reading file...${RESET}\r" $percent
  ' _ {} "$DOMAIN" "$dicc_outfile"
  total=$(wc -l < $dicc_outfile)
  echo ""
  echo -e "${info} $total Subdomains found.${end}"
  echo ""
  crtSH "dicattack"
  else
    echo -e "$error Could not download dictionary from seclists url.$end"
    dictionaryAttackCustom
  fi
}

# DNS Brute Force handler function - Trigger the dictorinary attack
bruteForceDNS(){
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
      [Dd]* ) dictionaryAttack; break;;
      [Cc]* ) dictionaryAttackCustom; break;;
      * ) echo -e "$error Please answer$green D$end \e[1m\e[91mor$end$green\e[1m C$end\e[1m\e[91m.$end\n";;
    esac
  done
}

# Check if the subdomain has webserver
check_web_server() { #8
  local end="\e[0m"
  local cyan="\e[1m\e[36m"
  local ok="\e[1m\e[92m"
  local resalted_output="\e[1;37m"
  local -r webservers_outfile=$(mktemp /tmp/dnsexplorer/XXXX.webservers.txt)

  local response=$(curl -m 3 --head --silent --output /dev/null --write-out '%{http_code}' "http://${1}")
  if ((response >= 100 && response <= 599)); then
    [ "$protocol" == "https" ] && secure=" secure"
    echo -e "${end}The domain ${resalted_output}$1${end} has a web server. [${cyan}HTTP${end}:$ok$response$end]"
    echo "http://$1" >> "$webservers_outfile"
  fi

  local response=$(curl -m 3 --head --silent --output /dev/null --write-out '%{http_code}' "https://${1}")
  if ((response >= 100 && response <= 599)); then
    [ "$protocol" == "https" ] && secure=" secure"
    echo -e "${end}The domain $resalted_output$1$end has a secure web server. [${cyan}HTTPS${end}:$ok$response$end]"
    echo "https://$1" >> "$webservers_outfile"
  fi
}
export -f check_web_server

# Abuse of crt.sh website - Internet connection required.
crtSH(){ #7
  declare -r call_source="$1"
  
  # Make sure the function is called from another function
  if [ -z "$call_source" ]; then
    echo -e "$error The function 'crtSH' must be called from another function.$end"
    return 1
  fi

  crtshoutput="$tmpdir/crtsh-output.txt" # crt.sh RAW output
  crtsh_parsed_output="$tmpdir/crt.sh.reg" # crt.sh parsed output
  subdomain_file="$output/$DOMAIN.subdomains.txt" # Subdomains results without wildcard
  subdomain_wildcard_file="$output/$DOMAIN.wildcard.txt" # Subdomains results with wildcard
  final_outputfile="$output/$DOMAIN-all.txt" # Final output subdomain file
  webservers_outfile="$output/$DOMAIN.webservers" # Final output subdomain file
  SANs_tmp_file=$(mktemp $tmpdir/XXX.SAN.tmp) # Final output SAN certificates file
  new_SANs="$tmpdir/found_new_SAN.tmp"

  if [ "$call_source" == "dicattack" ];then
    previus_result="$tmpdir/dicctionary.results.txt" # Dictionary attack results
  fi
  if [ "$call_source" == "zonetransfer" ];then
    previus_result="$output/$DOMAIN.zoneTransfer.txt" # Dictionary attack results
    #zonetransfer_tmp_data=$(cat "$previus_result"|  grep -E "([a-zA-Z0-9.-]+)\.$DOMAIN.*" | awk '{print $1}' | sort -u | grep -v '_' | sed 's/\.$//')
    cat "$previus_result" | grep -E "([a-zA-Z0-9.-]+)\.$DOMAIN.*" | awk '{print $1}' | sort -u | grep -v '_' | sed 's/\.$//' > $tmpdir/zonetransfer.results.txt
    zonetransfer_tmp_data="$tmpdir/zonetransfer.results.txt"
  fi
  if [ "$call_source" == "None" ];then
    previus_result="None" # Dictionary attack results
  fi
  
  echo "" > $subdomain_file && echo "" > $subdomain_wildcard_file && echo "" > $SANs_tmp_file && echo "" > $new_SANs
  echo -e "\n$info Finding subdomains - abusing Certificate Transparency Logs using https://crt.sh/\n$end"

  max_retries=3
  retry_count=0
  crtsh_susscess=1

  while [ $retry_count -lt $max_retries ]; do
    # Make sure we have a valid response
    crtsh_response=$(curl -s -w "%{size_download} %{http_code}" "https://crt.sh/?q=${DOMAIN}&output=json" -o $crtshoutput)
    crtsh_response_size=$(echo $crtsh_response | awk '{print $1}')
    crtsh_response_code=$(echo $crtsh_response | awk '{print $2}')

    if [ "$crtsh_response_size" -gt 2 ] && [ "$crtsh_response_code" -eq 200 ]; then
      real_response_size=$(wc -c < $crtshoutput)

      if [ "$real_response_size" -gt 2 ]; then

      ### INTEGRAR VALIDACION DE SI EL ATAQUE DE DICCIONARIO SE LLEVO A CABO

      
        grep -o '"common_name":"[^"]*' $crtshoutput | awk -F ':"' '{ print $2 }' | sort -u > $crtsh_parsed_output
        size_crtsh_output=$(wc -l < $crtsh_parsed_output)
        
        # Filter and sort subdomains only once
        sorted_subdomains=$(sort -u $crtsh_parsed_output)

        # Check if there are wildcard subdomains
        if echo "$sorted_subdomains" | grep -q '^\*\.'; then
          # Calculate the size of the output list - with wildcard
          crtsh_parsed_output_wildcard_size=$(echo "$sorted_subdomains" | grep '^\*\.' | wc -l)

          # Calculate the size of the output list - without wildcard
          crtsh_parsed_output_no_wildcard_size=$(echo "$sorted_subdomains" | grep -v '^\*\.' | wc -l)

          # Save subdomains without wildcard
          echo "$sorted_subdomains" | sed 's/^\*\.//g' > $subdomain_file

          # Save subdomains with wildcard
          echo "$sorted_subdomains" | grep '^\*\.' > $subdomain_wildcard_file

          # Print results
          echo -e "$ok[$resalted_output$crtsh_parsed_output_no_wildcard_size$ok] subdomains found"
          echo -e "$ok[$resalted_output$crtsh_parsed_output_wildcard_size$ok] wildcard subdomains found"
          echo -e "$ok[$resalted_output$size_crtsh_output$ok] total subdomains"
          crtsh_susscess=0
        else
          # Save subdomains without wildcard
          echo "$sorted_subdomains" > $subdomain_file

          # Print results
          echo -e "$info CRTsh results\n[$size_crtsh_output] total subdomains found"
          crtsh_susscess=0
        fi

        if [ "$call_source" == "zonetransfer" ]; then
          cat "$zonetransfer_tmp_data" "$subdomain_wildcard_file" "$subdomain_file" | sed '/^$/d' | sed 's/*\.//g' | sort -u > "$final_outputfile"
        elif [ "$call_source" == "dicattack" ]; then
          cat "$previus_result" "$subdomain_wildcard_file" "$subdomain_file" | sed '/^$/d' | sed 's/*\.//g' | sort -u > "$final_outputfile"
        else
          cat "$subdomain_wildcard_file" "$subdomain_file" | sed '/^$/d' | sed 's/*\.//g' | sort -u > "$final_outputfile"
        fi

        # Calculate the number of threads to use
        count_domains=$(wc -l < "$final_outputfile")
        threads=$(echo "scale=0; ($count_domains * 0.15 + 0.5)/1" | bc)
        [ "$threads" -lt 1 ] && threads=1
        [ "$threads" -gt 25 ] && threads=25

        # Print info
        echo -e "$info Loaded $count_domains targets...$end\n\n"

        # Execute the check_web_server function in parallel
        sort -u "$final_outputfile" | parallel -j "$threads" check_web_server

        break
      else
        echo -e "$error Unable to connect to CTR.sh$end"
        retry_count=$((retry_count + 1))
      fi
    else
      echo -e "$error Unable to connect to CTR.sh$end"
      retry_count=$((retry_count + 1))
    fi
  done

  # if we have reached the max number of retries
  if [ "$max_retries" -eq "$retry_count" ]; then
    
    # if the previus_result variable is empty and the crtsh was not success
    if [[ "$call_source" == "None" && "$crtsh_susscess" -eq 1 ]]; then

      # No previus result and crtsh was not success, try to enumerate the main domain
      echo -e "$error It was not possible to find subdomains using any conventional enumeration method. Running the extra mile......$end"
      check_web_server "$DOMAIN"
      cat /tmp/dnsexplorer/*.webservers.txt > "$webservers_outfile"
      webservers_count=$(wc -l < $webservers_outfile)
      
      # Check if there are webservers
      if [ "$webservers_count" -gt 0 ]; then
        echo -e "$ok[$resalted_output$webservers_count$ok] webservers found"
        protocol=$(grep "https://" "$webservers_outfile" | head -1 | awk -F'://' '{print $1}')
        
        # Check if there are https webservers
        if [ "$protocol" == "https" ]; then
          echo -e "$info Checking for SANs in the certificate$end"
          echo "" > "$SANs_tmp_file"
          grep "https://" "$webservers_outfile" | xargs -I {} -P 1 -n 1 bash -c 'checkCertificateSubjectsAlternativeNames "$1" "$2" "$3"' _ {} 443 "$SANs_tmp_file"
        
        # Check if there are http webservers
        elif [ "$protocol" == "http" ]; then
          if $EXTENDED_CHECKS;then
            local -r webEnumOutputCSV="$output/$DOMAIN.webenum.csv"
            echo "URL,HTTPServer,IP,PoweredBy,X-Powered-By,Country,WAF" > "$webEnumOutputCSV"

            count_webservers=$(wc -l < "$webservers_outfile")
            threads_webenum=$(echo "scale=0; ($count_webservers * 0.15 + 0.5)/1" | bc)
            [ "$threads_webenum" -lt 1 ] && threads=1
            [ "$threads_webenum" -gt 25 ] && threads=25

            sort -u "$webservers_outfile" | parallel -j "$threads_webenum" webEnum
            cat $tmpdir/whatweb/*.csv >> "$webEnumOutputCSV"
            
            printResults 0.05
            # FIN
          fi
        fi
      else
        echo -e "$error No webservers found$end"
        printResults 0.05
        clean
        # FIN
      fi
    else

      # Check if the previus result is not empty
      if [ "$call_source" == "zonetransfer" ];then
        echo "$zonetransfer_tmp_data" > "$final_outputfile"
        count_domains=$(wc -l < "$final_outputfile")
        threads=$(echo "scale=0; ($count_domains * 0.15 + 0.5)/1" | bc)
        [ "$threads" -lt 1 ] && threads=1
        [ "$threads" -gt 25 ] && threads=25
        echo -e "$info Loaded $count_domains targets...$end\n\n"
        sort -u "$final_outputfile" | parallel -j "$threads" check_web_server
      
      # Check if the previus result is not empty
      elif [ "$call_source" == "dicattack" ];then
        cp "$previus_result" "$final_outputfile"
        count_domains=$(wc -l < "$final_outputfile")
        threads=$(echo "scale=0; ($count_domains * 0.15 + 0.5)/1" | bc)
        [ "$threads" -lt 1 ] && threads=1
        [ "$threads" -gt 25 ] && threads=25
        echo -e "$info Loaded $count_domains targets...$end\n\n"
        sort -u "$final_outputfile" | parallel -j "$threads" check_web_server
      fi
    fi
  fi

  # Even if crt.sh has no results, the script takes the data from the source and performs the web server check, even if dicct attacks was not successful.

  # Merge all the webservers files
  cat /tmp/dnsexplorer/*.webservers.txt | sort -u > "$webservers_outfile"
  https_count=$(grep "https://" "$webservers_outfile" | wc -l)
  threads_enumSANs=$(echo "scale=0; ($https_count * 0.15 + 0.5)/1" | bc)
  [ "$threads_enumSANs" -lt 1 ] && threads=1
  [ "$threads_enumSANs" -gt 25 ] && threads=25

  # Check if there are SANs
  grep "https://" "$webservers_outfile" | xargs -I {} -P "$threads_enumSANs" -n 1 bash -c 'checkCertificateSubjectsAlternativeNames "$1" "$2" "$3"' _ {} 443 "$SANs_tmp_file"

  # Discover new SANs
  sort -u $SANs_tmp_file | sed 's/^\*\.//g' | grep -E '.*\.'$domain'\\b' > $new_SANs
  new_subdomains=$(mktemp $tmpdir/XXX.new_subdomains.tmp)
  curated_previus_webservers=$(mktemp $tmpdir/XXX.curated_previus_webservers.tmp)
  cat "$webservers_outfile" | sed 's/http\:\/\///g' | sed 's/https\:\/\///g' | sort -u > $curated_previus_webservers
  grep -Fxv -f $curated_previus_webservers $new_SANs > $new_subdomains
  count_newsubdomains=$(wc -l < $new_subdomains)

  # Print results
  if [ "$count_newsubdomains" -gt 0 ]; then
    echo -e "\n${info}${count_newsubdomains} New subdomains was found${end}"
    cat $new_subdomains
    cat $new_subdomains >> $final_outputfile
  else
    echo -e "\n${cyan}No new subdomains found"
  fi

  webservers_count=$(wc -l < $webservers_outfile)
  subdomains_count=$(wc -l < $final_outputfile)
  
  # ExtendedChecks
  if $EXTENDED_CHECKS;then
    local -r webEnumOutputCSV="$output/$DOMAIN.webenum.csv"
    echo "URL,HTTPServer,IP,PoweredBy,X-Powered-By,Country,WAF" > "$webEnumOutputCSV"

    # Calculate the number of threads to use and launch the webEnum function in parallel
    count_webservers=$(wc -l < "$webservers_outfile")
    threads_webenum=$(echo "scale=0; ($count_webservers * 0.15 + 0.5)/1" | bc)
    [ "$threads_webenum" -lt 1 ] && threads=1
    [ "$threads_webenum" -gt 25 ] && threads=25
    echo "" # Just a blank line :)
    sort -u "$webservers_outfile" | parallel -j "$threads_webenum" webEnum

    # Merge all the CSV files
    cat $tmpdir/whatweb/*.csv >> "$webEnumOutputCSV"
  fi

  printResults 0.05
}

# Print results function
printResults() {
  delay=$1

  DNSExplorerResults="Domain:${DOMAIN}
      DNS Servers: ${dns_servers_count}
      Zone Transfer: ${zone_transfer}
      Subdomains: ${subdomains_count}
      Webservers: ${webservers_count}"
  echo -e "\e[92;1m"
  for i in $(seq 0 $((${#DNSExplorerResults} - 1))); do
    echo -ne "${DNSExplorerResults:$i:1}"
    sleep "$delay"
  done
  echo -e "\e[0m"  # New line
}

# Extended checks capabilities
webEnum() { #9
  info="\e[36m[+]"
  end="\e[0m"
  if [ -z "$1" ]; then
    return 1
  fi

  if [[ $1 != http://* && $1 != https://* ]]; then
    return 1
  fi
  
  local -r wafwoof_txt_tmp_output=$(mktemp /tmp/dnsexplorer/wafw00f/XXX.wafw00f)
  local -r output_txt_webenum_file=$(mktemp /tmp/dnsexplorer/whatweb/XXX.csv)

  # Check if the site has a WAF
  wafw00f "$1" -f json -o "$wafwoof_txt_tmp_output" > /dev/null 2>&1
  firewall_detected=$(cat "$wafwoof_txt_tmp_output" | grep -oE '"firewall": "[^"]+"' | awk -F': ' '{gsub(/[",]/, "", $2); print $2}')
  [ -z "$firewall_detected" ] && firewall_detected="None"

  # Check webserver technologies
  local -r ww_result=$(whatweb --no-errors --open-timeout=7 --read-timeout=15 --colour=never "$1" 2>/dev/null)

  echo -e "${info} Testing webserver ${end}$1"

  # Get the webserver technologies
  httpserver=$(echo "$ww_result" | grep -o 'HTTPServer\[[^]]*\]' | cut -d'[' -f2 | cut -d']' -f1)
  [ -z "$httpserver" ] && httpserver="None"
  ip=$(echo "$ww_result" | grep -o 'IP\[[^]]*\]' | cut -d'[' -f2 | cut -d']' -f1 | head -1)
  [ -z "$ip" ] && ip="None"
  poweredby=$(echo "$ww_result" | grep -o 'PoweredBy\[[^]]*\]' | cut -d'[' -f2 | cut -d']' -f1)
  [ -z "$country" ] && country="None"
  xpoweredby=$(echo "$ww_result" | grep -o 'X-Powered-By\[[^]]*\]' | cut -d'[' -f2 | cut -d']' -f1)
  [ -z "$poweredby" ] && poweredby="None"
  country=$(echo "$ww_result" | grep -o 'Country\[[^]]*\]' | cut -d'[' -f2 | cut -d']' -f1)
  [ -z "$xpoweredby" ] && xpoweredby="None"

  # Save results
  echo "\"$1\",\"$httpserver\",\"$ip\",\"$poweredby\",\"$xpoweredby\",\"$country\",\"$firewall_detected\"" > "$output_txt_webenum_file"
}
export -f webEnum

# Funcion for checking if the site has Subject Alternative Names
checkCertificateSubjectsAlternativeNames() { #6
  port=$2
  declare output_file="$3"

  if [ -z "$1" ]; then
    return 1
  fi

  if [ -z "$port" ]; then
    port=443
  fi

  if [ -z "$output_file" ]; then
    return 1
  fi

  server=$(echo "$1" | sed 's/http:\/\///' | sed 's/https:\/\///' | sed 's/\/$//')

  # Make sure opnessl can connect to the site
  connected=$(echo -n | openssl s_client -connect  "$server:$port" 2>/dev/null | head -1 | awk -F "(" '{print $1}')

  # Check if the site has a webserver
  if [[ "$connected" == "CONNECTED" ]];then

    # Check if the site has DNS names
    DNS=$(echo -n | openssl s_client -connect "$server:$port" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text 2> /dev/null | sed 's/\                //'|grep -i "DNS:" | awk -F ":" '{print $1}')
    
    # Make sure the site has DNS names
    if [[ "$DNS" == "DNS" ]];then

      # Get the number of Subject Alternative Names
      len_subjects=$(echo -n | openssl s_client -connect "$server:$port" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text 2>/dev/null | grep "DNS:" 2>/dev/null | tr ',' '\n' | sed 's/\               //' | wc -l)
      
      # Check if the site has almost one Subject Alternative Names
      if [ $len_subjects -ge 1 ];then
       
        # Get the Subject Alternative Names
        SANs=$(echo -n | openssl s_client -connect "$server:$port" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:"| tr ',' '\n' | sed 's/\               //' | sed 's/\s//g' | sed 's/DNS://g')
        
        # return the Subject Alternative Names
        echo "$SANs" >> "$output_file"
      else
        return 1
      fi
    else
      return 1
    fi
  else
    return 1
  fi
}
export -f checkCertificateSubjectsAlternativeNames

# Initial recon
initHostRecon(){ #3
  echo -e "\n${info} A records for ${resalted_output}${DOMAIN}${end}${cyan} domain${end}"
  # A Records
  host "$DOMAIN" | grep 'has address' | awk '{print $4}'

  echo -e "\n${info} AAA records for ${resalted_output}${DOMAIN}${end}${cyan} domain${end}"
  # AAA Records
  if host "$DOMAIN" | grep 'IPv6' >/dev/null 2>&1;then
    host "$DOMAIN" | grep 'IPv6'| awk '{print $5}'
  else
    echo -e "$question Hosts $DOMAIN has not IPv6 address"
  fi

  echo -e "\n${info} MX records for ${resalted_output}${DOMAIN}${end}${cyan} domain${end}"
  # MAIL Records
  if host -t MX "$DOMAIN" | grep 'mail' >/dev/null 2>&1;then
    host "$DOMAIN" | grep 'mail' | awk '{print $6,$7}'
  else
    echo -e "$question Hosts $DOMAIN has not mail server records\n"
  fi
  
  echo -e "\n${info} CNAME records for ${resalted_output}${DOMAIN}${end}${cyan} domain${end}"
  # CNAME Records
  if host -t CNAME "$DOMAIN" | grep 'alias' >/dev/null 2>&1;then
    host -t CNAME "$DOMAIN" | awk '{print $1,$4,$6}'
  else
    echo -e "$question Hosts $DOMAIN has not alias records"
  fi

  echo -e "\n${info} TXT records for ${resalted_output}${DOMAIN}${end}${cyan} domain${end}"
` # TXT Records`
  if host -t txt "$DOMAIN" | grep 'descriptive' >/dev/null 2>&1;then
    host -t txt "$DOMAIN" | grep 'descriptive'
  else
    echo -e "$question Hosts $DOMAIN has not description records\n"
  fi
}

# Zone transfer attack function
doZoneTransfer(){ #4
  success=1
  if host -t NS "$DOMAIN" | grep 'name server' >/dev/null 2>&1;then
    echo -e "\n${info} Enumerating DNS Servers..."
    host -t NS "$DOMAIN" | cut -d " " -f 4 > $tmpdir/NameServers.txt

    ns=$(wc -l $tmpdir/NameServers.txt | awk '{print $1}')

    if [ $ns -ge 1 ];then
      echo -e "    ${green}[${ns}] DNS Servers was found, trying ZoneTransfer on these servers${end}"
      dns_servers_count=$ns

      # Verify if the DNS servers accept zone transfer
      while IFS= read -r nameserver;do
        host -t axfr "$DOMAIN" "$nameserver" | grep -E 'Received ([0-9]+) bytes from [0-9\.]+#[0-9]+ in ([0-9]+) ms' >/dev/null 2>&1

        if [ $? -eq 0 ];then
          axfr_tmp_file="$tmpdir/axfr.tmp" && echo "" > "$axfr_tmp_file"
          axfr_parsed_file="$tmpdir/parsed_axfr.tmp" && echo "" > "$axfr_tmp_file"
          host -t axfr "$DOMAIN" "$nameserver" > "$axfr_tmp_file"
          declare -a record_types=("A" "AAA" "AXFR" "CNAME" "MX" "NS" "SOA" "SRV" "TXT")
          total_records=0
          success=0

          # SHow blinking message
          for i in {1..3}; do
            echo -ne "${ok}\e[5;7mNameServer ${nameserver} accept ZoneTransfer\e[0m"
            sleep 0.5
            echo -ne "\r\e[K"
            sleep 0.5
          done

          for record_type in "${record_types[@]}"; do
            # Extract the current records of the current type
            current_records=$(cat "$axfr_tmp_file" | grep "IN[[:space:]]\+$record_type" | sort -u | awk '{print $1 "\t" $NF}' | column -t -s $'\t')

            # Verify if there are records of the current type
            if [ -n "$current_records" ]; then
              count_current_records=$(cat "$axfr_tmp_file" | grep "IN[[:space:]]\+$record_type" | sort -u | wc -l)
              echo -e "${info} ${count_current_records} '$record_type' records found:${end}\n$current_records\n"
              echo -e "$current_records" >> "$axfr_parsed_file"
              total_records=$((total_records + count_current_records))
            fi
          done
          echo -e "${ok}[${total_records}] Records found in $nameserver$end\nPlease take note of the other DNS servers, they may do zone transfers as well.${end}"
          break
        else
          echo -e "    $error NameServer $nameserver does not accept zone transfer$end"
        fi
      done < <(grep -v '^ *#' < $tmpdir/NameServers.txt)
    else
      echo -e "$error No DNS servers found for $DOMAIN$end"
    fi

    # Check if the zone transfer was successful
    if [ $success -eq 0 ];then
      echo -e "\n$ok DNS zone transfer was possible, no bruteforce attacks on the subdomains are required. $end\n"

      cp "$axfr_parsed_file" $output/$DOMAIN.zoneTransfer.txt
      zone_transfer="Yes"
      crtSH "zonetransfer"
      clean

    # If the zonetransfer was not successful, then call to bruteforce
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
          [Nn]* ) crtSH "None"; clean;;
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

# Check dependencies: curl, host, parallel.
checkDependencies() {
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

# Check opt dependencies: wafw00f, whatweb.
optDependencies() { 
  declare -A dependencies=(
    ["whatweb"]="whatweb"
    ["wafw00f"]="wafw00f"
  )
  for cmd in "${!dependencies[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
      echo -e "$error '$cmd' command is not available, please install the ${dependencies[$1]} package for extended checks. $end"
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
      v:2.0 ░ $end By: Danilo Basanta (https://github.com/dabasanta/) ░ (https://www.linkedin.com/in/danilobasanta/)\n\n


\033[3mThe author does not promote malicious actions or the use of the script for illegal operations. Remember to always obtain prior permission from the target company's system administrators before performing any malicious actions.\033[0m\n\n"
}

help(){ # Simply help function
    echo -e "\e[91m                               
        @@@  @@@  @@@@@@@@  @@@       @@@@@@@   
        @@@  @@@  @@@@@@@@  @@@       @@@@@@@@  
        @@!  @@@  @@!       @@!       @@!  @@@  
        !@!  @!@  !@!       !@!       !@!  @!@  
        @!@!@!@!  @!!!:!    @!!       @!@@!@!   
        !!!@!!!!  !!!!!:    !!!       !!@!!!    
        !!:  !!!  !!:       !!:       !!:       
        :!:  !:!  :!:        :!:      :!:       
        ::   :::   :: ::::   :: ::::   ::       
        :   : :  : :: ::   : :: : :   :        
v:2.0   ░ By: Danilo Basanta (https://github.com/dabasanta/) ░ (https://www.linkedin.com/in/danilobasanta/)\n\n${end}
"

    options=$(cat <<- EOM
${resalted_output}Usage:${end}        ${green}\e[3m./DNSExplorer.sh <domain>${end}

${resalted_output}Extended:${end}     ${green}\e[3m./DNSExplorer.sh <domain> --extended${end}

${resalted_output}Help:${end}         ${green}\e[3m-h, --help Display this help and exit${end}

EOM
    )
echo -e "$options"
tput cnorm
}

main(){ #1
  export output="$DOMAIN.out"
  mkdir -p $output
  
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

  # Check if the second parameter is --extended
  if [ "$2" = "--extended" ]; then
    DOMAIN=$1
    EXTENDED_CHECKS=true
    optDependencies
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