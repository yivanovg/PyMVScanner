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
timeout = 0.5
online = True
filesave = False
fileList = list()

def appendtofile(data):
    
    global fileList
    print('true')
    fileList.append(data)
    
#check if port is open using standart TCP connection 
def check_port(port):
    
    global online
    global fileList
    
    #create socket
    sock = socket(AF_INET, SOCK_STREAM)
    
    #try to connect to the specified port with timeout
    try:
        sock.settimeout(timeout)
       
        sock.connect((host, port))
       
        #lockprint use because of threading
        with lockPrint:
            
            print(f'Target host {host} with IP {utilities.reverseDnsLookupPort(host)[2]} is open to connect on: {port}'  , displayPortService(int(port)))
            online =  False 
            
        return port          
    except:
         
         return 
        

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
            #exit()

#start threding
def run_multi_scan(threads, ports):

    global filesave
    global portQueue
    
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
        exit()
        
    #save file
    if filesave == True:
        saveFile()    
        
    myLogger.info('Scan Finished!\n')
    
    if online != False:
        
        myLogger.info('No Ports Open')

    
#stealthy tcp scan explained in documenatation
def stealthTCPScan(url, portPass):
    
    #var init
    dst_ip = url
    src_port = RandShort()
    ports= portPass

    #loop through the port range
    for dst_port in ports:
        
        stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=3)
        
        #checking the repsonse code and determenig the port status
        if str(type(stealth_scan_resp)) == "<class 'NoneType'>":
            
                print('Filtered port:', dst_port,'\n')
                temps= 'Filtered port: ', dst_port
                fileList.append(temps)
                
        elif stealth_scan_resp.haslayer(TCP):
            
            if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='R'), timeout=3)
                
                print('Open port: ', dst_port,'\n')
                temps1= 'Open port: ', dst_port
                fileList.append(temps1)
                
        elif stealth_scan_resp.getlayer(TCP).flags == 0x14:
            
                print('Closed port: ', dst_port,'\n')
                temps2= 'Closed port: ', dst_port
                fileList.append(temps2)
                
        elif stealth_scan_resp.haslayer(ICMP):
            
            if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            
                print('Filtered port: ', dst_port, '\n')
                temps3= 'Filtered port: ', dst_port
                fileList.append(temps3)
              
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
def portSettings(url, portRanges, filesavePass=False, timeout_pass=0.5, threads=200, scan='TCP'):

    #var init
    global host
    host = url
    global timeout
    global filesave
    
    filesave = filesavePass
    
    myLogger.info(url+'\n')
    myLogger.info('Scan Starting!')
    timeout = timeout_pass
    #string format
    
    #split port ranges
    if '-' in portRanges:
        portStart, portEnd = portRanges.split("-")
        portStart, portEnd = int(portStart), int(portEnd)
        
        if portStart >= 0 and portStart <=65536 and portEnd >=1 and portEnd <= 65536:

            portsL = list()
            for port in range(portStart,portEnd):
                portsL.append(port)
                
        elif portStart < 0 and portStart > 65536 and portEnd < 1 and portEnd > 65536 :

            myLogger.warning('Port Range Invalid !')
            exit()
    
    #validation of arguments
    if threads < 10 or threads > 250:

        myLogger.warning('Threads number should be between 10 and 250')
        exit()
        
    if timeout > 1 or timeout < 0.3:
        
        myLogger.warning('Timeout should be between 0.3 and 1 seconds')
        exit()
        
    if scan == 'TCP':
     run_multi_scan(threads,portsL) 
      
    elif scan == 'TCP STEALTH':
        stealthTCPScan(url,portsL)
        if filesave == True:
            saveFile()