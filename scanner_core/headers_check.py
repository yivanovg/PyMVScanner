"""Class for checking the security headers of a website"""
"""City Unviersity Project"""
#imports
from datetime import datetime
from ssl import CertificateError
from urllib import response
import requests
from requests import *
from requests.utils import dict_from_cookiejar
import pandas as pd
import logging
from scanner_core import DVWALogin, logger
from http.cookiejar import Cookie

#initialise logger
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

fliesave_list = list()

#source of header settings https://www.thesmartscanner.com/blog/complete-guide-to-http-headers-for-securing-websites-cheat-sheet
security_headers = {
            'X-Frame-Options': {'contents': 'DENY' },
            'Srict-Transport-Security': {'contents': ''},
            'Access-control-Allow-Origin': {'contents': '*'},
            'Content-Seurity-Policy': {'contents': ''},
            'X-XSS-Protection': {'contents': '0'}, 
            'X-Content-Type-Options': {'contents': 'nosniff'},
            'X-Powered-By': {'contents': ''},
            'Server': {'contents': ''}, 
            'Referrer-Policy' : {'contents': 'strict-origin-when-cross-origin'},
            'Expect-CT': {'contents': ''}, 
            'HTTP Cross-Origin-Opener-Policy': {'contents': 'same-origin'},
            'Public-Key-Pins': {'contents': ''}
            
        }
 
#main function for checking the SSL status of the website
def check_ssl(url):
    
    global fliesave_list
    
    myLogger.info('Starting SSL Check!\n')
    
    retry_without = True
    
    #try to connect to the website and check for ssl error
    try:      
        get(url)
        print('SSL Supported: Cerificate Valid\n')
        fliesave_list.append('SSL Supported: Cerificate Valid\n')
        
    #if error return outcome
    except requests.exceptions.SSLError as e :
        retry_without = False
        print('SSL Supported : Certificate Invalid\n')
        fliesave_list.append('SSL Supported : Certificate Invalid\n')
        
        #print('Try again\n')
        #exit()
    except Exception as e:
        retry_without = False
        print(e)
    
    #if any other exception happens try connecting without verifying certificate and return outcome
    if not retry_without:
        try:
            
            get(url, verify=False)
            print('SSL Supported : Certificate Invalid\n')
            fliesave_list.append('SSL Supported : Certificate Invalid\n')
            
        except:
            
            print('SLL Not Supported: Certificate Invalid\n')
            fliesave_list.append('SLL Not Supported: Certificate Invalid\n')
            
        return retry_without
    myLogger.info('SSL Check Finished!\n')

    
#main function for checking the SSL redirect
def check_redirect(url, retry_check):

    
    myLogger.info('Starting Redirect Check!\n')
    #var init
    https_redirect_try =  get(url, verify=retry_check)
    temp_redirect_info = {}
    outcome = True
    
    #add the header data to the dictionary
    if https_redirect_try.history:
        
        for destURL in https_redirect_try.history:
            
            temp_redirect_info['start_url_http'] = destURL.url
            
            temp_redirect_info['start_code_http'] = destURL.status_code
            
        temp_redirect_info['end_url_https'] = https_redirect_try.url
        
        temp_redirect_info['end_code_https'] = https_redirect_try.status_code        
        
    else:
        
        temp_redirect_info['start_url_http'] = https_redirect_try.url
        
        temp_redirect_info['start_code_http'] = https_redirect_try.status_code 
        
        temp_redirect_info['end_url_https'] = ''
        
        temp_redirect_info['end_code_https'] = ''   
        
        
    print('Redirect Info: ', temp_redirect_info)
    temp = 'Redirect Info: ', temp_redirect_info, '\n'
    
    fliesave_list.append(temp)
    
    print('\n') 
    
    #verify is https is present at the redirection url and return the result
    if 'https' in temp_redirect_info['end_url']:
        outcome = True
        
    else:
        outcome = False
    
    myLogger.info('Finished Redirect Check!\n')
    
    return outcome

#main function for checking the security headers
def check_headers(url, httpsOn):
    
    global fliesave_list
    myLogger.info('Starting Secure Headers Check!\n')
    
    #verify set to False if connection to a website with no HTTPS example: localhost:3030
    try:
        target = get(url, verify=False)
        
    except RequestException as e:
        exit(e)
        
    clean = {}
    vulnerable = {}
    
    #check the security headers and return the resposne
    for header in security_headers:
        
        if header in target.headers:
            
            clean[header] = 'Not Vulnerable'
            print('Not Vulnerable Security-Header:', header,' Option Set: ', target.headers[header], '\n')
            
            tempstr = 'Not Vulnerable Security-Header:', header,' Option Set: ', target.headers[header], '\n'
            fliesave_list.append(tempstr)
            
        else:
            
            vulnerable[header] = 'Vulnerable'
            
            tempstr1 = 'Vulnerable Security-Header: ', header,'\n'
            
            fliesave_list.append(tempstr1)
            
            print('Vulnerable Security-Header: ', header,'\n')
            
    myLogger.info('Finished Secure Headers Check!')
    
#some code is based on https://subscription.packtpub.com/book/networking-and-servers/9781784392932/5/ch05lvl1sec49/testing-for-insecure-cookie-flags
#function for checking the cookies for HttpOnly and secure flag setting
def cookie_check(url,retry_check):
    
    global fliesave_list
    myLogger.info('Starting Cookie Secure Flags Check!\n')
    
    #var init
    print(retry_check)
    conn = DVWALogin.loginDVWA()
    respone  = conn.get(url, verify=retry_check)
    cookie = respone.cookies
   
    secureC = True
    secureH = True
    secureD = True
   
    try:
    #check each cookie if it has the secure and httponly flag enabled
        for cook in cookie:
       
            if not cook.secure:
                secureC = False
    
            if not cook.has_nonstandard_attr('HttpOnly') or not cook.has_nonstandard_attr('httponly'):
                secureH = False
                  
            if cook.domain_initial_dot:
                secureD = False
            
    except Exception as e:
        
        myLogger.warning('Could not get cookie ABORTING!')
        exit()
           
    #print scan results
    if secureC == True:
        
        print('Cookie Secure Enabled\n')
        fliesave_list.append('Cookie Secure Enabled\n')
        
    else:
        
        print('Cookie Secure Disabled\n')
        fliesave_list.append('Cookie Secure Disabled\n')
        
    if secureH == True:
        
        print('Cookie Httponly Enbaled\n')
        fliesave_list.append('Cookie Httponly Enbaled\n')
        
    else:
        
        print('Cookie Httponly Disabled\n')
        fliesave_list.append('Cookie Httponly Disabled\n')
        
    if secureD == True:
        
        print('Loosly defined Domain: False\n')
        fliesave_list.append('Loosly defined Domain: False\n')
        
    else:
        
        print('Loosly Defined Domain: True\n')
        fliesave_list.append('Loosly Defined Domain: True\n')
    
    myLogger.info('Completed Cookie Secure Flags Check!')
    
def saveFile(filesave):
    try:   
        
        #open and save to the txt file the formatted output
        with open('scanner_core\\data\\headercheckScan.txt', 'a') as file:
                    dateTimeObj = datetime.now()
                    formatted = str(filesave).replace('\\n', '\n')
                    file.write('\n'+str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
                    
                    file.writelines('\n' + formatted)
                    file.write('\n')
    
    except OSError:
                myLogger.info('Could not open/read file!!!')
    return

#entry function for cli
def startHeaderCheck(url, fsave=False):
    
    if 'http' not in url:
        myLogger.info('Please add HTTP OR HTTPS to URL')
        exit()
         
    retry_check = check_ssl(url)
    
    cookie_check(url, retry_check)
    
    check_headers(url,check_redirect(url, retry_check))
    
    if fsave == True:
        saveFile(fliesave_list)
    