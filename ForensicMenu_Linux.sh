#!/bin/bash

#This is a non closing select loop script

HORI="============================================"
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'
CMDS=(
'ifconfig -a 2>/dev/null'
'who -a 2>/dev/null'
'last 2>/dev/null'
'lastlog 2>/dev/null'
'arp -an 2>/dev/null'
'route 2>/dev/null'
'netstat -tulanop 2>/dev/null'
'netstat -pan 2>/dev/null'
'netstat -rn 2>/dev/null'
'iptables -L -n 2>/dev/null'
'lsof -i 2>/dev/null'
'uname -a 2>/dev/null'
'rpm -qi basesystem 2>/dev/null'
'uptime 2>/dev/null'
'chkconfig 2>/dev/null'
'systemctl --no-pager 2>/dev/null'
'systemctl list-units --type=target 2>/dev/null'
'ps -aux 2>/dev/null'
'ps -alef 2>/dev/null'
'lsof +L1 2>/dev/null'
)
UGCMDS=(
'id 2>/dev/null'
'lastlog 2>/dev/null |grep -v "Never" 2>/dev/null'
'w 2>/dev/null'
'`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null); do id $i; done` 2>/dev/null'
)
STARTUPCMDS=(
'ls -lisaR /etc/systemd/system/ 2>/dev/null'
'ls -lisaR /run/systemd/system/ 2>/dev/null'
'cat /etc/crontab 2>/dev/null'
'cat /etc/hosts 2>/dev/null'
)
clear
echo -e "\n$HORI"
echo "          Forensic Menu - Linux"
echo "$HORI"
KEY="Create SSH Key Pair"
ENUM="Run Remote Machine Enumeration"
NMAP="NMAP Sweep for Host Discovery"
USRGRP="Display Remote Machine Users and Groups Info"
STUP="Display Remote Machine Startup / Crontab / Hosts File"
select choice in "$KEY" "$ENUM" "$NMAP" "$USRGRP" "$STUP"
do
	case $choice in
		$KEY)
			echo -e "${CYAN}This option creates an SSH Key Pair that will allow password-less connections to the selected remote machine${NC}\n"
			read -p "Please Enter Remote IP Address: " IP
			read -p "Please Eneter Remote Username: " USER
			echo -e "\n${CYAN}Accept the default by pressing 'Enter' for the next 3 options${NC}\n"
			ssh-keygen
			echo -e "\n${CYAN}Enter Remote users password when promted${NC}\n"
			ssh-copy-id -i ~/.ssh/id_rsa.pub $USER@$IP
			;;
		$ENUM)
			echo -e "${RED}It is recomended you create a Key Pair prior to running this command${NC}\n"
			read -p "Please Enter Remote IP Address: " IP
			read -p "Please Eneter Remote Username: " USER
			read -p "Please Specify a Filename to save results (eg. enumresults.txt): " SAVERESULT
			for commandname in "${CMDS[@]}"
				do
				echo "# $commandname" >> $SAVERESULT
				eval "ssh $USER@$IP $commandname" >> $SAVERESULT
				echo "."
				done
			;;
		$NMAP)
			read -p "Please Enter Remote IP Address Range (eg 192.168.0.1/24): " IP
			echo -e "\nDetected Hosts: `nmap $IP -sn`\n"
			;;
		$USRGRP)
			echo -e "${RED}It is recomended you create a Key Pair prior to running this command${NC}\n"
			read -p "Please Enter Remote IP Address: " IP
			read -p "Please Eneter Remote Username: " USER
			for ugcommandname in "${UGCMDS[@]}"
				do
				echo "# $ugcommandname"
				eval "ssh $USER@$IP $ugcommandname"
				echo ""
				done
			;;
		$STUP)
			echo -e "${RED}It is recomended you create a Key Pair prior to running this command${NC}\n"
			read -p "Please Enter Remote IP Address: " IP
			read -p "Please Eneter Remote Username: " USER
			read -p "Please Specify a Filename to save results (eg. enumresults.txt): " SAVERESULT
			for stcommandname in "${STARTUPCMDS[@]}"
				do
				echo "# $stcommandname" >> $SAVERESULT
				eval "ssh $USER@$IP $stcommandname" >> $SAVERESULT
				echo "."
				done
			;;
		*)
			echo -e "\n==> Enter a Number Between 1 and 5"
			;;
		esac
done
