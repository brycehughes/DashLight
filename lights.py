from scapy.all import *

ignore = {'fc:f8:ae:4e:a2:4b','b8:27:eb:45:1c:54','00:00:00:00:00:00'}

lights= {'00:07:a6:03:62:db':'Living Room'}
lightsip  = {'192.168.1.167':'Living Room'} 


def arp_display(pkt):
    if pkt.haslayer(IP):
        

        
def send_response(pkt):
    packet = Ether(dst="40:b4:cd:a5:3f:40",type=0x888e)/EAPOL(version=2,type='KEY',len=117)/Raw(load=loadstring)
    pkt[Ether].src="00:00:00:00:00:00"
    sendp(pkt)
    print pkt.show()

        
print sniff(prn=arp_display,store=0,count=0)
