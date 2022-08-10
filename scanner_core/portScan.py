"""Class which carries out a number of different port scans"""
"""City Unviersity Project"""
#imports
from datetime import datetime
from ipaddress import IPv4Network
import os
from socket import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import sr1, RandShort, sr
import requests
from threading import Thread, Lock
import time
from queue import Queue
from scanner_core import utilities, logger
from scanner_cli import cliParser
import logging
import csv
#check code for reuse

#initialise logger
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

#global vars
portQueue = Queue()

lockPrint = Lock()

host = ''

online = True
filesave = False
fileList = list()

def appendtofile(data):
    global fileList
    print('true')
    fileList.append(data)
    
#check if port is open using standart TCP connection 
def check_port(port, timeout=0.5):
    startTime = time.time()
    
    global online
    global fileList
    
    #create socket
    sock = socket(AF_INET, SOCK_STREAM)
    
    #try to connect to the specified port with timeout
    try:
        sock.settimeout(0.5)
       
        sock.connect((host, port))
       
        #lockprint use because of threading
        with lockPrint:
            
            print(f'Target host {host} with IP {utilities.reverseDnsLookupPort(host)[2]} is open to connect on: {port}'  , displayPortService(int(port)))
            online =  False 
            
        return port          
    except:
         
         return 
        
    sock.close() 
    #print('Time taken:', time.time() - startTime)


#threading funciton which calls the port scan function
def multiThread():
    
    global portQueue
    global fileList
    
    #get the port form the queue and check the connection
    while True:
        #try:
            process =  portQueue.get()
            
            saveport = check_port(process)
            strV = f'Target host {host} with IP {utilities.reverseDnsLookupPort(host)[2]} has NO open ports!' + '\n'
            
            if saveport is not None:
                
                strf = f'Target host {host} with IP {utilities.reverseDnsLookupPort(host)[2]} is open to connect on: {saveport}'  + displayPortService(int(saveport)) + '\n'
                fileList.append(strf)
            
            elif saveport is None:
                if fileList is None:
                    fileList.append(strV)
                    
            portQueue.task_done()
            
        #except:
            
            #myLogger.critical('Aborting Scan Please Try Again!')
            #cliParser.cli()

#start threding
def run_multi_scan(threads, ports, timeout):

    global filesave
    global portQueue
    
    dict_to_pass = {'timeout':timeout}
    
    #start threading with the number of specified threads
    try:
        
        for thread in range(threads):

            thread = Thread(target=multiThread)
            thread.daemon = True
            thread.start()

        for process in ports:
            
            portQueue.put(process)

        portQueue.join()
        
    except:
        
        myLogger.critical('Aborting Scan Please Try Again!')
        cliParser.cli()
        
    #save file
    if filesave == True:
        saveFile()    
        
    myLogger.info('Scan Finished!\n')
    
    if online != False:
        
        myLogger.info('No Ports Open')

#check if the host is online
def checkHostOnline(hostname, waittime=600):
    
    myLogger.info('Starting Host Ping!')
    #ip verificaiton
    assert isinstance(hostname, str), \
        "IP Address or Hostname should be in str format"

    #ping using the windows cmd ping command
    try:
        
        if os.system("ping -c 1 " + hostname + '\n') == 0:
        
            online = True
        else:

            online = False
            
    except OSError:
        
        myLogger.warning('OS Error Try Again !') 
        cliParser.cli()
       
    myLogger.info('Finished Host Ping Success!') 
    
    return online
    
#stealthy tcp scan explained in documenatation
def stealthTCPScan(url):
    
    #var init
    dst_ip = url
    src_port = RandShort()
    ports= (80,1)

    #loop through the port range
    for dst_port in ports:
        stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=3)
        
        #checking the repsonse code and determenig the port status
        if str(type(stealth_scan_resp)) == "<class 'NoneType'>":
            
                print('Filtered')
            
        elif stealth_scan_resp.haslayer(TCP):
            
            if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='R'), timeout=3)
                
                print('Open')
                
        elif stealth_scan_resp.getlayer(TCP).flags == 0x14:
            
                print('Closed')
            
        elif stealth_scan_resp.haslayer(ICMP):
            
            if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            
                print('Filtered')

#function for saving a file
def saveFile():
    
    try:   
        with open('scanner_core\\data\\openPorts.txt', 'a') as file:

                    #create file formatting
                    dateTimeObj = datetime.now()
                    
                    formatted = str(fileList).replace('\\n\",', '\n')
                        
                    file.write('\n'+str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
                    
                    file.writelines('\n' + formatted)
                    file.write('\n')

    except OSError:
        
                myLogger.info('Could not open/read file!!!')

#load the TCP ports services so they can be displayed during the scan
def displayPortService(serviceNumber):
    try:
        with open('scanner_core/data/scanData/TCP_Ports.txt', 'r') as content:
            
            port_details = ''
            readerFile = csv.reader(content)
            readerFile = list(readerFile)
            
            for file in readerFile:
               
                if int(file[1]) == serviceNumber:
                    port_details = file
                    
            return str(port_details)
            
    except OSError:
                myLogger.info('Could not open/read file!!!')  
                      
    except Exception as e:
        exit(e)


#entry funciton for the port scan function
def portSettings(url, portRanges, filesavePass, timeout=0.4, threads=200):

    #var init
    global host
    host = url
    
    global filesave
    
    filesave = filesavePass
    
    myLogger.info(url+'\n')
    myLogger.info('Scan Starting!')
    
    #string format
    
    if '-' in portRanges:
        portStart, portEnd = portRanges.split("-")
        portStart, portEnd = int(portStart), int(portEnd)
        
        if portStart >= 0 and portStart <=65536 and portEnd >=1 and portEnd <= 65536:

            portsL = list()
            for port in range(portStart,portEnd):
                portsL.append(port)
                
        elif portStart < 0 and portStart > 65536 and portEnd < 1 and portEnd > 65536 :

            myLogger.warning('Port Range Invalid !')
            cliParser.cli()
    
    #portsL = int(portRanges)
       
    
    #stealthTCPScan()
    
    #validation of arguments
    if threads < 10 or threads > 250:

        myLogger.warning('Threads number should be between 10 and 250')
        cliParser.cli()
        
    if timeout > 1 or timeout < 0.3:
        
        myLogger.warning('Timeout should be between 0.3 and 1 seconds')
        cliParser.cli()
        
    
        
    #run scan   
    #if checkHostOnline('127.0.0.1')== True:
        
    run_multi_scan(threads,portsL,timeout)  
        
    #else:
        
    #myLogger.info('Host is down please try again or try another host!')
        
    #displayPortService()
