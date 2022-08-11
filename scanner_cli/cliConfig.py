"""Class for holding different CLI configuration values"""
"""City Unviersity Project"""

#different cli variable settings
OKBLUE = '\033[94m'
ENDC = '\033[0m'
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'

#banner created from https://patorjk.com/software/taag/#p=display&f=Graffiti&t=Type%20Something%20
banner = """ 

 ██▓███ ▓██   ██▓ ██▒   █▓ ███▄ ▄███▓  ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███  
▓██░  ██▒▒██  ██▒▓██░   █▒▓██▒▀█▀ ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▓██░ ██▓▒ ▒██ ██░ ▓██  █▒░▓██    ▓██░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
▒██▄█▓▒ ▒ ░ ▐██▓░  ▒██ █░░▒██    ▒██   ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
▒██▒ ░  ░ ░ ██▒▓░   ▒▀█░  ▒██▒   ░██▒▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
▒▓▒░ ░  ░  ██▒▒▒    ░ ▐░  ░ ▒░   ░  ░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
░▒ ░     ▓██ ░▒░    ░ ░░  ░  ░      ░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
░░       ▒ ▒ ░░       ░░  ░      ░   ░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░ 
         ░ ░           ░         ░         ░  ░ ░            ░  ░         ░          ░    ░  ░   ░     
         ░ ░          ░                       ░                                                        

"""
options = ['1.Lookup URL(Hostname) IP Address. ',
           '2.Lookup IP Address URL(Hostname).',
           '3.Scan single or multiple URL\'s for open and vulnerable ports.',
           '4.Test',
           '10.Exit']

lookup_address_option = 'To lookup an URL(Hostaname) you need to enter a single URL or and .txt files with URLS. For single URL enter in the format www.example.com\n'

lookup_ip_option = 'To lookup and IP address for the URL(Hostname) you need to enter the IP below in the format 192.168.1.1\n'

scan_end = ['1.Please choose this option if you wish to go back to the main menu',
            '2.Please use this option if you want to stay on same page']

portscan_info = ['\nWelcome to the port scanning page of the tools. Here you are able to enter single or multiple URL\'s from a file and scan their ports.\nThe scanner will return any open ports they names and protocols.\nYou can specify the ports ranges, threads for the scan(speed), timeout and if you wish to check for known vulnerabilities on these ports.\n\nCheck the manual or help menu for details on options.\nExample scan: www.example.com -th 25 -st 9 -ports 0-1026\n']