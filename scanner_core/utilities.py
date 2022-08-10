"""Class for additional utility functions needed by the main scanner functions"""
"""City Unviersity Project"""
#imports
import csv
import socket
import logging
import re
from urllib.parse import urlparse
from scanner_core import logger

#initialise logger
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)


#Check if an URL is valid
def checkURL(url):

    #regex expression source is https://www.geeksforgeeks.org/python-check-url-string/
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    
    valid_url = re.findall(regex, url)

   
    #check url if its valid
    if valid_url and valid_url[0][0].count('.') > 1:
        
        return True

    elif not valid_url or valid_url[0][0].count('.') <=1:

        myLogger.warning('URL FORMAT IS NOT VALID !\n')
        
        return False
    
def checkUrlNoScheme(url):
    try:
        
        result = urlparse(url)
        all([result.scheme, result.netloc])
        return True
    
    except ValueError:
        
        myLogger.warning('URL FORMAT IS NOT VALID !\n')
        return False
    
#Check if an IP is valid
def checkIP(ip):

    #using sockets function to check the IP address
    try:

        socket.inet_aton(ip)
        
        if '.' not in ip:
            
            raise Exception('IP FORMAT IS NOT VALID\n')
        
        return True

    except (socket.error, Exception) as e:

        myLogger.warning('IP FORMAT IS NOT VALID\n', extra={'foo':'PyVMScanner'})
        return False

#function for reverse lookup of URL
def reverseIpLookup(ipint):
    
    #using socket to look the host name
    try:
        
        return socket.gethostbyname(ipint)

    except socket.error:

        myLogger.warning("IP Address Unavailable\n")

#fucntion for reverse lookup of an IP address
def reverseDnsLookup(address):

    #using socket to get the host address
    try:

        return socket.gethostbyaddr(address)

    except socket.error:

        myLogger.warning("Hostname Unavailable\n")
        
def reverseDnsLookupPort(address):

    #using socket to get the host address
    try:

        return socket.gethostbyaddr(address)

    except socket.error:
        
        return 'N/A'       
    
#function for reading a wordlist from a .txt file
def readWordlist(wordlist):
    
    #reading a wordlist in a specified format to be used by other functions
    try:
        with open(f'scanner_core/data/scanData/{wordlist}', 'r') as content:
            
            readerFile = csv.reader(content)
            
            readerFile = list(readerFile)
    
            return readerFile
            
    except OSError as e:
        
                myLogger.info('Could not open/read file!!!') 
                exit(e)
    