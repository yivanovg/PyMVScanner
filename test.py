
import logging
logging.getLogger('runtime').setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import sr1, RandShort, sr


def stealthTCPScan():
    dst_ip = '137.74.187.102'
    src_port = RandShort()
    dst_port= 80


    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=3)

    print(str(type(stealth_scan_resp)))

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
            
stealthTCPScan()           
            
            
        