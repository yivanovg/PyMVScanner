"""Class for scanning an website for an admin panel"""
"""City Unviersity Project"""
#imports
from datetime import datetime
from gettext import find
import re
from scanner_core import logger, utilities, DVWALogin
import logging
from requests import RequestException, Session, get, request
import random

#initialise logger
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

#random user-agents so out connection does not get blocked
USER_AGENTS_OPTIONS = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36',
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0',
    'User-Agent' : 'Mozilla/5.0 (X11; CrOS x86_64 6783.1.0) AppleWebKit/537.36 (KHTML, like Gecko) Edge/12.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.4; WOW64)AppleWebKit/537.36 (KHTML, like Gecko)Chrome/36.0.1985.143 Safari/537.36 Edge/12.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10158',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'User-Agent' : 'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0',
    'User-Agent' : 'Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0',
    'User-Agent' : 'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
    'User-Agent' : 'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14',
    'User-Agent' : 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14',
    'User-Agent' : 'Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02',
    'User-Agent' : 'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
    'User-Agent' : 'Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00',
    'User-Agent' : 'Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00',
    'User-Agent' : 'Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'User-Agent' : 'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10',
    'User-Agent' : 'Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; de-at) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; da-dk) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1',
    'User-Agent' : 'Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
    'User-Agent' : 'Mozilla/5.0 (Windows; U; Windows NT 6.1; ko-KR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27 '}

#user agent choice
user_agent_choices = random.choice(list(USER_AGENTS_OPTIONS))

user_agent_choices = {'User-Agent' : USER_AGENTS_OPTIONS[user_agent_choices]}

robots_final = list()

#function for saving result to a txt file
def saveFile(fileString):
    
    try:   
        
        #open and save to the txt file the formatted output
        with open('scanner_core\\data\\adminURLS.txt', 'a') as file:
                    dateTimeObj = datetime.now()
                    formatted = str(fileString).replace('\\n', '\n')
                    file.write('\n'+str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
                    
                    file.writelines('\n' + formatted)
                    file.write('\n')
    
    except OSError:
                myLogger.info('Could not open/read file!!!')

#main function for checking the admin panels
def checkAdmin(url, redirect, fsave, wordlist):
    
    #var init
    valid_urls = []
    no_redirect = redirect
    url = url
    
    error403 = 0
    error401 = 0
    
    wordlist = utilities.readWordlist(wordlist)
    
    if robots_final is not None:
       wordlist =  wordlist + robots_final
    
    #looping thourg the wordlist creating new url and scanning response we get from them
    myLogger.info(f'Scan Starting on host: {url}')
    for i in range(len(wordlist)):
        try:
            
            site_url_formatted = 'http://' + url + '/' + wordlist[i][0] 
           
            try:
                
                url_request_info = get(site_url_formatted, headers=user_agent_choices)
                
                if no_redirect is False:
                    
                    url_request_info = get(site_url_formatted, headers=user_agent_choices, allow_redirects=False)
                
                #responses deciding the if url is valid
                if url_request_info.status_code == 200:
                    
                    valid_urls.append(f'Possible Vulnerable Admin URL: {site_url_formatted} : Code {url_request_info.status_code} Request OK!\n')
                    print(f'Possible Vulnerable Admin URL: {site_url_formatted}\nCode {url_request_info.status_code} Request OK!\n')
                    
                if url_request_info.status_code == 403:
                    
                    print(f'Possible Vulnerable Admin URL: {site_url_formatted}\nCode {site_url_formatted.status_code} Request Forbidden!\n')
                    error403 += 1
                    
                if url_request_info.status_code == 401:
                    print(f'Possible Vulnerable Admin URL: {site_url_formatted}\nCode {site_url_formatted.status_code} Authenticaiton Required!\n')
                    error401 +=1
                else:
                    continue
                    
                        
        #raising exception
            except RequestException as e:
                myLogger.warning('Aborting Scan!')
                exit(e)
                
        except KeyboardInterrupt:
            break 
        
    if fsave == True:
        saveFile(valid_urls)
        
    myLogger.info(f'Scan Fnished on host: {url}\n')    

#function for checking the robots file of an website for disallowed directories 
def checkRobots(url):
    
    sess = DVWALogin.loginDVWA()
    
    #var init and creation of robots url
    url = url
    myLogger.info('Checking for access to robots.txt file!')
    
    urlRobot = 'http://' + url + '/robots.txt'
    
    global robots_final
    
    #try get the robots txt if not raise warning
    try:
        
        respone = sess.get(urlRobot, allow_redirects=True)
        
        urls_robot = respone.text.split('\n')

        for url in urls_robot:
           
            if 'Disallow: ' in url:
                
                url.replace('Disallow: ', '')
                print(url)
                list_url = url.replace('Disallow: /', '')
                robots_final.append([list_url])
            
        respone.close()
        
        myLogger.info('Finished extracting urls from robots.txt\n')
        return 
    
    except Exception as e:
        myLogger.warning('Could not find robots.txt file!')
        exit(e)
        
def startAdminScan(url, wordlist='mediumAdmin.txt', redirect=True, fsave=False):
    
    checkRobots(url)
    checkAdmin(url, redirect, fsave, wordlist)
