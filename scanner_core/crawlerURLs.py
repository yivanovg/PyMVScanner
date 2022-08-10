"""Class for crawling urls on a target webpage and extrating data from it"""
"""City Unviersity Project"""
#imports
from datetime import datetime
import re
from requests_html import HTMLSession
from requests import get
from scanner_core import DVWALogin, adminPanel, utilities, logger
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup as bs
import warnings

warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')

#initialise logger
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

#global variables
site_links = set()
external_links = set()
crawl_tracker = 0
filesave_data = list()
addDetails = ''
#main function for getting the links from a specific url
def get_web_links(url):
    
    #var init
    global filesave_data
    all = set()
    conn = HTMLSession()
    
    try:
        links_result = conn.get(url, timeout=9)
        
    except Exception as e:
        exit(e)
        
    #try to render the page via javascript first
    try:
        links_result.html.render()
        
    except Exception as e:
        
        print(e)
        pass
    
    #get the url html content and go through it to find all links tag and extract the link
    links_result = bs(get(url).content, 'html.parser')

    try:
        #for loop below contains main logic for extracting the links from a certain url
        for link_tag in links_result.find_all('a'):
            
            href_tag = link_tag.attrs.get('href')

            
            if href_tag == "" or href_tag is None:
                
                print('HREF Tag Empty!')
                continue
            
            #checking if link tag text is relative or absolute and then fixing the url to be in normal format
            if 'http' not in href_tag or 'www' not in href_tag:
                
                href_tag = urljoin(url, href_tag)
                
                parsed = urlparse(href_tag)
                
                href_tag = parsed.scheme + "://" + parsed.netloc + parsed.path
            
            #check if url is already scanned and if not add to the correct dictionary
            if href_tag in site_links:
                
                continue
            
            check =  urlparse(url)
            
            if check.netloc not in href_tag:
                
                if href_tag not in external_links:
                    
                    external_links.add(href_tag)
                    filesave_data.append(f'External link: {href_tag}\n')
                    print(f'External link: {href_tag}')
                    
            elif check.netloc in href_tag:
                
                print(f'Internal Link: {href_tag}')
                filesave_data.append(f'Internal Link: {href_tag}\n')
                all.add(href_tag)
                site_links.add(href_tag)  
            
    except Exception as e:
        
        myLogger.info('Aborting Scan!')
        exit(e)     
    
    return all

def saveFile(data):
    
    try:   
        with open('scanner_core\\data\\crawlerURLS.txt', 'a', encoding='utf-8') as file:

                    #create file formatting
                    dateTimeObj = datetime.now()
                    
                    formatted = str(data).replace('\\n\',', '\n')
                        
                    file.write('\n'+str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
                    
                    file.writelines('\n' + formatted)
                    file.write('\n')
                    file.write(addDetails)
                    file.write('\n')

    except OSError:
        
                myLogger.info('Could not open/read file!!!')
                
                
#main funciton which is called multiple times based on the url limit variable to check for links withing a page
def crawl_website(url, url_limit=5):
    
    #var inti
    global crawl_tracker
    
    crawl_tracker += 1

    #get links list
    links_to_crawl = get_web_links(url)
    
    #crawl each link in the list and save the result
    try:
        for link in links_to_crawl:
            
            if crawl_tracker > url_limit:
                  
                myLogger.info('Max URLS Reached Aborting!\n')
                
                break
            
            crawl_website(link)
                
    except KeyboardInterrupt:
        
        exit()
    

#function for finding all the form in a certain webpage
def find_forms(url):
    global addDetails
    #var init
    result = DVWALogin.loginDVWA().get(url, verify=False)
 
    form_data = bs(result.content, 'html.parser')
    form = form_data.find('form')
    if form is not None:
        """Returns the HTML details of a form,
        including action, method and list of form controls (inputs, etc)  """
        details = {}
        # get the form action (requested URL)
        action = form.attrs.get("action").lower()
        # get the form method (POST, GET, DELETE, etc)
        # if not specified, GET is the default in HTML
        method = form.attrs.get("method", "get").lower()
        # get all form inputs
        
        inputs = []
        
        #create dictionaries with the forms attributes and input field parameters
        for input_tag in form.find_all("input"):
            # get type of input form control
            input_type = input_tag.attrs.get("type", "text")
            # get name attribute
            input_name = input_tag.attrs.get("name")
            # get the default value of that input tag
            input_value =input_tag.attrs.get("value", "")
            # add everything to that list
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        
        if details is not None:
            addDetails = str(details)

        result.close()

        return details

#main fucntion starting the colleciton of urls
def start_crawl(url, url_limit=5, fsave=False):
    
    if 'http' not in url:
        myLogger.info('Please add HTTP OR HTTPS to URL')
        exit()
        
    crawl_website(url, url_limit)
    find_forms(url)
    
    #add to file when saving 
    totalIS = "Total Internal URLS on page:" + str(len(site_links)) + '\n'
    totalES = "Total External URLS on page:" + str(len(external_links)) + '\n'
    totalF =  "Total Forms on WebPage:" + str(len(external_links)) + '\n'
    totalU =  "Total URLs on page:" + str(len(site_links)) + str(len(external_links)) + '\n'
    totalC =  "Total crawled URLS on pages:" + str(url_limit) 
    
    #append to filesave list and send to save
    filesave_data.append(totalIS)
    filesave_data.append(totalES)
    filesave_data.append(totalF)
    filesave_data.append(totalU)
    filesave_data.append(totalC)
    
    if fsave == True:
        saveFile(filesave_data)
    
    #print scan information
    print("Total Internal URLS on page:", len(site_links))
    print("Total External URLS on page:", len(external_links))
    print("Total Forms on WebPage:", len(external_links))
    print("Total URLs on page:", len(site_links) + len(external_links))
    print("Total crawled URLS on pages:", url_limit)
    
   
    return 