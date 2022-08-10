"""Class for looking up IP address and Hostname(url) whois details"""
"""City Unviersity Project"""
#imports
from warnings import filterwarnings as fwarning
from ipwhois import IPWhois 
from scanner_core import logger, utilities
import ipwhois
import whois
import json
import logging


#Load custom formatted logger class
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

#choose type of scan whois or ipwhois
def chooseScan(scanService, saveChoice , ip='', url = ''):
    
    if scanService != 'ipwhois' and scanService != 'whois':
        logging.warning('Syntax error. Please check command !')
        exit()

    elif saveChoice != 'txt' and saveChoice != 'json':
        logging.warning('Syntax error. Please check command !')
        exit()

    #ipwhois scan
    if scanService == 'ipwhois' and ip != '' :

        result = ipwhoisLookup(ip)
        
        myLogger.info('Displaying Scan Results')
        
        #format output result
        for key, value in result.items():

            if key == 'nets':
                try:
                    print('Result: ',result['nets'][0])
                    print('Result: ',result['nets'][1])
                    
                except IndexError:
                    continue
            else:
                print('Result: ', key, ':', value)

        myLogger.info('IP Details Scan Finished')

        #save file in specified format
        if saveChoice == 'txt':
            try:
                with open('scanner_core\\data\\ipwhois.txt', 'a+') as file:

                    myLogger.info('Saving File !')
                    json.dump(result, file, indent=4)
                    file.write('\\n')
                 

            except OSError:
                myLogger.info('Could not open/read file!!!')
                exit()

        elif saveChoice == 'json':
            try:
                with open('scanner_core\\data\\ipwhois.json', 'a+') as file:
                    
                    myLogger.info('Saving File !')
                    json.dump(result, file, indent=4)
                    file.write('\\n')

            except OSError:
                myLogger.info('Could not open/read file!!!')
                exit()
                
    elif scanService == 'ipwhois':
        
        myLogger.warning('Invalid lookup option')
    
    #whois scan
    if scanService == 'whois' and url != '':
        myLogger.info('Starting WHOIS host scan!')

        #scan target   
        try:
            result =  whois.whois(url)

        except:

             myLogger.warning('Scan failed please try again !')
             
             myLogger.critical('Aborting please try again or check your URL format !')
             
             exit()

        print('Result: ', result, '\n')
        
        #save file in the chosen format
        if saveChoice == 'txt' and utilities.checkURL(url) == True:

            myLogger.info('Scan Finished !\n')
            myLogger.info('Saving File !\n')

            try:
                with open('scanner_core\\data\\whois.txt', 'a') as file:

                    strInfo = str(result)
                    
                    file.writelines('\n' + strInfo)
                    file.write('\n')

            except OSError:
                myLogger.info('Could not open/read file!!!')
                exit()

        elif saveChoice == 'json' and utilities.checkURL(url) == True:

            myLogger.info('Scan Finished !\n')
            myLogger.info('Saving File !\n')

            try:
                with open('scanner_core\\data\\whois.json', 'a') as file:

                    strInfo = str(result)

                    file.writelines('\n' + strInfo)
                    file.write('\n')

            except OSError:
                myLogger.info('Could not open/read file!!!')
                exit()
        else:
            myLogger.warning('Scan Aborted !')
            
    elif scanService == 'whois':
        
         myLogger.warning('Invalid lookup option')

#ipwhois helper func
def ipwhoisLookup(ip):

    fwarning(action='ignore')

    myLogger.info('Starting IP Details Lookup')
    
    #check ip  
    if utilities.checkIP(ip) == False:
            exit()
    
    #perform ipwhois lookup
    try:

        host = IPWhois(ip)

        details = host.lookup_whois()

    except ipwhois.exceptions.BaseIpwhoisException:

        myLogger.warning('Scan failed please try again !')
        
    return details


