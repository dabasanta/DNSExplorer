#!/usr/bin/bash
# @author: Danilo Basanta
# @author-linkedin: https://www.linkedin.com/in/danilobasanta/
# @author-github: https://github.com/dabasanta
mkdir -p /tmp/dnsexplorer
clean(){
    rm -rf /tmp/dnsecrecon;exit 0
}

doZoneTransfer(){
    success=1;for nsi in $(cat /tmp/dnsexplorer/NameServers.txt);do host -l $1 $nsi | grep -i "has address" > /dev/null;if [[ $? -eq 0 ]];then echo -e "[+] NameServer $nsi accept ZoneTransfer\n";host -l $1 $nsi | grep -i "has address";success=0;else echo -e "[-] NameServer $nsi does not accept zone transfer";fi;done;return $success
}

dictionaryAttack(){
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -o /tmp/dnsexplorer/bit.txt
    if [ -f /tmp/dnsexplorer/bit.txt ];then cat /tmp/dnsexplorer/bit.txt|head -1000>/tmp/dnsexplorer/bitquark.txt;l=$(wc -l /tmp/dnsexplorer/bitquark.txt|awk '{print $1}');c=1;s=0;for fqdn in $(cat /tmp/dnsexplorer/bitquark.txt);do host $fqdn.$1 | head -1 | grep "has address";if [ $? -eq 0 ];then s=$(($s+1));fi;echo -ne "[++] Using entry:$c of $l.\r";c=$(($c+1));done;if [ $s -ge 1 ];then echo -e "\n[+] Found $s subdomains.";else echo -e "\n[!!] Found $s subdomains.";fi;else echo -e "[!!] Could not download dictionary from seclists url.";clean;fi
}

dictionaryAttackCustom(){
    check=0;while [ $check -eq 0 ];do read -p "Enter the path of the dictionary file> " dfile;if [ -f "$dfile" ];then istext=$(file $dfile|awk '{print $2}');if [[ $istext = "ASCII" ]];then lenn=$(wc -l $dfile|awk '{print $1}');co=1;su=0;for sub in $(cat $dfile);do host $sub.$1|head -1|grep "has address";if [ $? -eq 0 ];then su=$(($su+1));fi;c=$(($co+1));done;if [ $su -ge 1 ];then echo -e "\n[+] Found $su subdomains.";else echo -e "\n[!!] Found $su subdomains.";fi;check=1;clean;else echo -e "[!!] the file is not ASCII text. Can't use it.";fi;else echo -e "[!!] File $dfile does not exists.";fi;done
}

bruteForceDNS(){
    echo -e "[++] Fuzzing subdomains of $1\n[?] Do yo want to use a custom dictionary? [C=custom/d=Default]\n[?] Default: Provides a dictionary with the top 1000 of the most commonly used subdomains.\nCustom: Use your own custom dictionary.";while true; do read -p "[D/c]> " dc;case $dc in
            [Dd]* ) dictionaryAttack $1; break;;
            [Cc]* ) dictionaryAttackCustom $1; break;;
            * ) echo -e "[!!] Please answer D or C\n";;esac;done
}

basicRecon(){
    echo -e "[+] Finding IP address for A records";host $1 | grep 'has address'|awk '{print $4}';echo -e ""
    echo -e "[+] Finding IPv6 address for AAA records";if host $1 | grep 'IPv6' >/dev/null 2>&1;then host $1 | grep 'IPv6'| awk '{print $5}';echo -e "";else echo -e "[?] Hosts $1 has not IPv6 address\n";fi
    echo -e "[+] Finding mail server address for $1 domain";if host -t MX $1 | grep 'mail' >/dev/null 2>&1;then host $1 | grep 'mail'|awk '{print $6,$7}';echo -e "";else echo -e "[?] Hosts $1 has not mail server records\n";fi;echo -e "[+] Finding CNAME records for $1 domain";if host -t CNAME $1 | grep 'alias' >/dev/null 2>&1;then host -t CNAME $1|awk '{print $1,$4,$6}';echo -e "";else echo -e "[?] Hosts $1 has not alias records\n";fi;echo -e "[+] Finding text description for $1 domain";if host -t txt $1 | grep 'descriptive' >/dev/null 2>&1;then host -t txt $1 | grep 'descriptive';echo -e "";else echo -e "[?] Hosts $1 has not description records\n";fi;echo -e "[+] Finding nameserver address for $1 domain"
    if host -t NS $1 | grep 'name server' >/dev/null 2>&1;then
        host -t NS $1 | cut -d " " -f 4
        host -t NS $1 | cut -d " " -f 4 > /tmp/dnsexplorer/NameServers.txt
        ns=$(wc -l /tmp/dnsexplorer/NameServers.txt | awk '{print $1}')
        echo -e "\n $ns DNS Servers was found, trying ZoneTransfer on these servers"
        if doZoneTransfer $1;then
            echo -e "\nDNS zone transfer was possible, no bruteforce attacks on the subdomains are required.\n";clean
        else
            echo -e "\n[!!] DNS zone transfer was not possible, DNS servers are not accept it"
            while true; do
                echo "";read -p "Do you want to brute force subdomains? [Y/n]> " yn
                case $yn in
                    [Yy]* ) bruteForceDNS $1; break;;
                    [Nn]* ) clean;;
                    * ) echo -e "[!!] Please answer yes or no.\n";;
                esac
            done
        fi
    fi
}

help(){
    echo -e "\nDNSExplorer automates the enumeration of DNS servers and domains using the 'host' tool and the predefined DNS server in /etc/resolv.conf. To use it run: ./DNSExplorer.sh domain.com\n"
}

checkDependencies() {
    if ! command -v host &> /dev/null;then echo -e "[!!] 'host' command is not avaliable, please install the bind-utils/dnsutils package.";exit 1;fi;if ! command -v curl &> /dev/null;then echo -e "[!!] 'curl' command is not avaliable, please install the curl package.";exit 1;fi
}

if [ $# == 1 ];then
    if [ $1 = "-h" ] || [ $1 = "help" ] || [ $1 = "--help" ] || [ $1 = "-help" ];then
        help
    elif [ $# == 1 ];then
        checkDependencies
        if ping -c 1 $1 >/dev/null 2>&1;then
            if host $1 >/dev/null 2>&1;then
                basicRecon $1
            else
                echo -e "[!!] No route to host, please verify your DNS server or internet connection";exit 1
            fi    
        else
            echo -e "[?] PING was not success, does server ignoring ICMP packets?"
            if host $1 >/dev/null 2>&1;then
                echo -e "[++] Running checks anyway\n"
                basicRecon $1
            else
                echo -e "[!!] No route to host, please verify your DNS server or internet connection";exit 1
            fi
        fi
    fi
else
    echo -e "[!!] Invalid arguments";help;exit 1
fi

