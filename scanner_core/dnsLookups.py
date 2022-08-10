"""Class for controlling the IP and URL lookup functions"""
"""City Unviersity Project"""

#imports
import logging
from scanner_core import utilities, logger
from scanner_cli import cliCore
import click

#Load custom formatted logger class
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)


#Main fucntion for checking and looking up an URL for an IP address
def urlLookup(url, filesave='false'):

    #logic for mutliple urls
    if '.txt' in url:
        
        while True:
            
            try:
                #open file read urls and perform the lookup 
                url_file = open(f'data/{url}')
                myLogger.info('File Accepted!\n')

                file_content = url_file.read()
                urls_split = file_content.split(',')

                #separate urls
                if '\n' in file_content:

                    myLogger.warning('File Contains New Lines\n')
                    urls_split = file_content.replace('\n','').split(',')
                
                if filesave == 'true':
                    myLogger.info('Saving File\n')

                #lookup the url
                for entry in urls_split:
                    reverse_ip = utilities.reverseIpLookup(entry)
                    
                    #file saving
                    if filesave == 'true':
                        try:
                            with open('scanner_core\\data\\urlsToIP.txt', 'a') as file:

                                file.write(f'The IP address of the {entry} is: {reverse_ip}\n')

                        except OSError:
                            myLogger.critical('Aborting File not read !')

                    print(f'The IP address of the {entry} is: {reverse_ip}\n')

                    
                break
            #error handling
            except OSError:
                myLogger.info('Could not open/read file!!!')
                url = click.prompt('Please enter a valid URL filename')

    #error validations
    if 'txt' not in url:    

            while utilities.checkURL(url) == False:
                url = click.prompt('Please enter a valid URL')  

    if 'txt' not in url and utilities.checkURL(url) == True:

            myLogger.info('Signle URL Detected\n')
            reverse_ip = utilities.reverseIpLookup(url)

            print(f'The IP address of the {url} is: {reverse_ip}\n')
            
    
    
#Main fucntion for checking and looking up an IP address for the DNS name
def ipLookup(ip):

 #check ip
 while utilities.checkIP(ip) == False:

        ip = click.prompt('Please enter a valid IP address')
 
 #perform ip lookup
 if utilities.checkIP(ip) ==  True:
    
    myLogger.info('IP accepted')
    reverse_dns = utilities.reverseDnsLookup(ip)

    print(f'\nThe URL(Hostname) address of the {ip} address is: {reverse_dns}\n')
    
 
    