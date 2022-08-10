"""Class for loggin to DVWA for testing and returning an active connection so test can be executed as logged in person"""
"""City Unviersity Project"""
#imports
from requests import Session, get
import re

#funtction for testint the DVWA exploitable website
def loginDVWA():
    
    sess = Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

    login_payload = { 
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }
        
    # change URL to the login page of your DVWA login URL
    login_url = "http://127.0.0.1/DVWA-Master/login.php"

    # # login
    r = sess.get(login_url)
    token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
    login_payload['user_token'] = token
    
    sess.post(login_url, data=login_payload)
      
    #r = sess.get('http://127.0.0.1/DVWA-Master/robots.txt')
    
    return sess