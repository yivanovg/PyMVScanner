"""Controler for the CLI interface of the Scanner"""
"""City Unviersity Project"""
"""Definitions of options and arguments"""
#imports
from email.policy import default
import rich_click as click
from scanner_cli import cliConfig
from scanner_core import adminPanel, crawlerURLs, headers_check, sqlScan, utilities, dnsLookups, logger, hostInfoLookup, dirBuster, portScan

click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True

#main method for creating the cli commands and help menu
@click.group()
@click.version_option('1.1', prog_name="PyVMScanner")

def cli():
     """
PyMVScanner is a multi-purpose web application Scanning Tool.The software offers a number of ways for a person to execute a number of different vulnerability scans and some payloads for testing these vulnerabilities.\n



\n\b 
        THE SOFTWARE IS ONLY TO BE USED BY AUTHORISED PEOPLE.
      YOU CAN ONLY SCAN TARGETS WHICH YOU ARE AUTHORISED TO DO SO.
THE INDIVUDAL USING THE SOFTWARE IS RESPONSIBLE ANYTHING MALICIOUS USAGE.
    """
    
#command which is used to specify the target scan settings
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL')

@click.option('--ip',
              help='When using this option plese input an ip address in the format specified: [127.162.221.242]',
              metavar='IP',default=None)

@click.option('--lookup', default='ipwhois', help='Choose the ports that you need to scan. USAGE: pyvs --url http://google.com --ports 80 or multiple ports --ports 443, 22, 21', 
              show_default=True, metavar='SERVICE NAME')

@click.option('--ftype', default='txt', help='Choose the file extension for the results which you want to save. Supported: TXT and JSON', 
              show_default=True, metavar='FILETYPE')

#function logic for choosing the scan with the specified parameters
def targetScan(url, ip, lookup,ftype):

    """
    Use this command to carry out whois ipwhois scan
    """
    #check if host is online if not exit and try again
    if utilities.checkHostOnline(url) == False:
        exit()
    if ip is not None and lookup is not None and ftype is not None:
            hostInfoLookup.chooseScan(lookup,ftype, ip, '')

    if url is not None and lookup is not None and ftype is not None:
            hostInfoLookup.chooseScan(lookup,ftype,'',url)
            
    

#command which is used to specify the target scan settings
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL')

@click.option('--fsave',
              help='Use this option when you are using URL\'s from a file and want to save the IP addresses to an .txt file',metavar='BOOL', default='false', show_default=True)

@click.option('--ip',
              help='When using this option plese input an ip address in the format specified: [127.162.221.242]',
              metavar='IP',default=None)  

#function logic for choosing the scan with the specified parameters
def lookups(url, fsave, ip):
    
    """
    Use this command to lookups URL's and IP addresses
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    if url is not None and fsave != 'false':
        dnsLookups.urlLookup(url, fsave)
    elif url is not None:
        dnsLookups.urlLookup(url)
    
    if ip is not None:
        dnsLookups.ipLookup(ip)


#command which is used to check directories and files on the webpage
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com , google.com, www.google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)

@click.option('--redirect',
              help='When using this option plese input if you want the request to accept redirects.',
              metavar='BOOL', default=True, show_default=True)  

@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)

@click.option('--wordlist',
              help='When using this option plese input a file input in the format specified(.txt format): example.txt',
              metavar='WORDLIST',default='dirBuster.txt', show_default=True)  

#function logic for choosing the scan with the specified parameters
def dirbuster(url, wordlist, fsave, redirect):
    
    """
    Use this command to scan a website for directories and files
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    if url is not None and wordlist is not None:
        dirBuster.main(wordlist, url, fsave, redirect)
        

#command which is used to check for amdin pages on the website
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com , google.com, www.google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)

@click.option('--redirect',
              help='When using this option plese input if you want the request to accept redirects.',
              metavar='BOOL', default=True, show_default=True)  

@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)

@click.option('--wordlist',
              help='When using this option plese input a file input in the format specified(.txt format): example.txt',
              metavar='WORDLIST',default='mediumAdmin.txt', show_default=True)  


#function logic for choosing the scan with the specified parameters
def adminChecker(url, wordlist, fsave, redirect):
    
    """
    Use this command to scan a website for admin pages on the website
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    if url is not None and wordlist is not None:
        adminPanel.startAdminScan(url, wordlist, redirect, fsave)      
         

#command which is used to check the security headers, ssl and cookies
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com , google.com, www.google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)
@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)

#function logic for choosing the scan with the specified parameters
def headercheck(url,fsave):
    
    """
    Use this command to scan a website and check it security headers, cookies, ssl and redirect option
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    if url is not None:
        headers_check.startHeaderCheck(url,fsave)  
        
    
#command which is used to scan for sql vulnerabilities
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com , google.com, www.google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)

@click.option('--onlylink',
              help='When using this option specify if you wish to scan only the target URL for SQL and not the forms as well.',
              metavar='BOOL', default=False, show_default=True)  

@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)

#function logic for choosing the scan with the specified parameters
def sqlscanner(url, fsave, onlylink):
    
    """
    Use this command to scan a website for sql vulnerabilities
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    if url is not None:
        sqlScan.startSQL(url,fsave,onlylink)  
        
     
#command which is used to crawl the website and extract links and forms
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com , google.com, www.google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)

@click.option('--urlimit',
              help='When using this option plese the number of url pages that you wish to scan for links.',
              metavar='INT', default=5, show_default=True)  

@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)
 

#function logic for choosing the scan with the specified parameters
def crawler(url, urlimit, fsave):
    
    """
    Use this command to extract links and form from a specific website
    """
    if utilities.checkHostOnline(url) == False:
        exit()
        
    if url is not None:
        crawlerURLs.start_crawl(url,urlimit, fsave)  
        
        
#command which is used to specify the target scan settings
@cli.command()
#arguments for the commands
@click.option('--url', '--u',
              help='When using this option please input the URL you would wish to scan in the format specified:\b [http://google.com] (DO NOT USE THE EXAMPLE URL SHOWN, FOR IP SCAN USE THE --IP OPTION. For multiple URLS scan please add you URL .txt file to the \\data folder. The URLS should be separated with comma and start on new line or same line comma separated.', 
              metavar='URL', required=True)
@click.option('--fsave',
              help='Use this option when you want to save the output to a .txt file',metavar='BOOl', default=False, show_default=True)

@click.option('--st', '--timeout',
              help='When using this option please specify the time in seconds for the timeout. USAGE: --st 5',
              metavar='SECONDS', default=0.5)

@click.option('--th', '--threads',
              help='When using this option please specify the amount of CPU threads you want to use for the scans. USAGE: --threads 25',
              metavar='THREADS', default=100, show_default = True)

@click.option('--ports', default='80-500', type=str, help='Choose the ports that you need to scan. USAGE: pyvs --url http://google.com --ports 80 or multiple ports --ports 80-500 80-82', 
              show_default=True, metavar='PORT NUMB', required=True)

@click.option('--scan', default='TCP', help='Choose the ports that you need to scan. USAGE: pyvs --url http://google.com --ports 80 or multiple ports --ports 443, 22, 21', 
              show_default=True, metavar='SERVICE NAME')

#function logic for choosing the scan with the specified parameters
def portscan(url, ports, fsave, st, th, scan):

    """
    Use this command to carry a specific type of port scan [TCP,UDP,TCP STEALTH,FIN]
    """
    if utilities.checkHostOnline(url) == False:
        exit()
    
    if url is not None and ports is not None:
        portScan.portSettings(url,ports,fsave,st,th,scan)       