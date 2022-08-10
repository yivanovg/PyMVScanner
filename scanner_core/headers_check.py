"""Class for checking the security headers of a website"""
"""City Unviersity Project"""
#imports
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
    
    retry_without = False
    
    #try to connect to the website and check for ssl error
    try:      
        get(url)
        print('SSL Supported: Cerificate Valid\n')
        
    #if error return outcome
    except requests.exceptions.SSLError as e :
        
        print('SSL Supported : Certificate Invalid\n')
        
    except Exception as e:
        retry_without = True
        print(e)
    
    #if any other exception happens try connecting without verifying certificate and return outcome
    if retry_without:
        try:
            
            get(url, verify=False)
            print('SSL Supported : Certificate Invalid\n')
            
        except:
            
            print('SLL Not Supported: Certificate Invalid\n')
        
        return
    myLogger.info('SSL Check Finished!\n')

    
#main function for checking the SSL redirect
def check_redirect(url):

    myLogger.info('Starting Redirect Check!\n')
    #var init
    https_redirect =  get(url)
    redirect_info = {}
    outcome = True
    
    #add the header data to the dictionary
    if https_redirect.history:
        
        for dest in https_redirect.history:
            redirect_info['start_url'] = dest.url
            redirect_info['start_code'] = dest.status_code
            
        redirect_info['end_url'] = https_redirect.url
        redirect_info['end_code'] = https_redirect.status_code        
        
    else:
        
        redirect_info['start_url'] = https_redirect.url
        redirect_info['start_code'] = https_redirect.status_code 
        
        redirect_info['end_url'] = ''
        redirect_info['end_code'] = ''    
        
    #verify is https is present at the redirection url and return the result
    if 'https' in redirect_info['end_url']:
        outcome = True
        
    else:
        outcome = False
    
    myLogger.info('Finished Redirect Check!\n')
    
    return outcome

#main function for checking the security headers
def check_headers(url, httpsOn):
    
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
            
        else:
            
            vulnerable[header] = 'Vulnerable'
            print('Vulnerable Security-Header: ', header,'\n')
            
    myLogger.info('Finished Secure Headers Check!')
    
#function for checking the cookies for HttpOnly and secure flag setting
def cookie_check(url):

    myLogger.info('Starting Cookie Secure Flags Check!\n')
    
    #var init
    conn = DVWALogin.loginDVWA()
    respone  = conn.get(url)
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
    else:
        print('Cookie Secure Disabled\n')
    if secureH == True:
        print('Cookie Httponly enbaled\n')
    else:
        print('Cookie Httponly Disabled\n')
    if secureD == True:
        print('Loosly defined Domain: false\n')
    else:
        print('Loosly Defined Domain: true\n')
    
    myLogger.info('Completed Cookie Secure Flags Check!')

#entry function for cli
def startHeaderCheck(url, fsave):
    
    if 'http' not in url:
        myLogger.info('Please add HTTP OR HTTPS to URL')
        exit()
        
    cookie_check(url)
    
    check_ssl(url)
    
    check_headers(url,check_redirect(url))
    