'''
Created on 2013 11 7

@author: jlt

robotframework scapy library
'''

import socket 
import fcntl 
import struct 
import pexpect
import time
from scapy.all import * 
import threading  
send_net0='eth0'
send_net1='eth1'
send_net2='eth2'
send_net3='eth3'
recv_net='eth1'
s_mac0='00:00:00:00:00:11'
s_mac1='00:00:00:00:00:12'
s_mac2='00:00:00:00:00:13'
s_mac3='00:00:00:00:00:14'
d_mac='00:00:00:00:00:00'
dst_addr_b='ff:ff:ff:ff:ff:ff'
s_ip0='192.168.1.11'
s_ip1='192.168.1.12'
s_ip2='192.168.1.13'
s_ip3='192.168.1.14'
d_ip='192.168.1.1'
arp_test=0
icmp_test=0
udp_test=0

class sniff_arp_recv(threading.Thread):    
    def sniff_callback(self,p):
        global arp_test
        global dst_addr
        if ARP in p and p[ARP].op ==2 and cmp(p[ARP].pdst[0:len(self.s_ip)],self.s_ip[0:len(self.s_ip)])==0 and \
                cmp(p[ARP].psrc[0:len(self.d_ip)],self.d_ip[0:len(self.d_ip)])==0:
           print "sucess+++++++++++++++++++++++++++++"
           arp_test=arp_test+1
           print p.display()
           dst_addr=p[ARP].hwsrc
           thread.exit_thread()
    
    def __init__(self,net,s_mac,s_ip,d_ip):  
        threading.Thread.__init__(self)  
        net = net.encode('ascii')
        self.net =net
        self.s_ip   = s_ip  
        self.s_mac  = s_mac  
        self.d_ip   = d_ip  
    def run(self): 
        '''
        pkt=sniff(prn=self.sniff_callback,iface='eth0',timeout=2,filter='arp')
        '''
        pkt=sniff(prn=self.sniff_callback,iface=self.net,timeout=2,filter='arp')
        thread.exit_thread()

class sniff_udp_recv(threading.Thread):    
    def sniff_callback(self,p):
        global udp_test
        if UDP in p and cmp(p[IP].src[0:len(self.s_ip)],self.s_ip[0:len(self.s_ip)])==0 and \
                cmp(p[IP].dst[0:len(self.d_ip)],self.d_ip[0:len(self.d_ip)])==0:
            print p.display()
            udp_test=udp_test+1 
            thread.exit_thread()
   
    def __init__(self,net,s_ip,d_ip,data):  
        threading.Thread.__init__(self)  
        net = net.encode('ascii')
        self.net =net  
        self.s_ip   = s_ip  
        self.d_ip   = d_ip  
        self.data   = data
    def run(self): 
        '''
        pkt=sniff(prn=self.sniff_callback,iface='eth1',timeout=2,filter='udp')
        pkt=sniff(prn=self.sniff_callback,iface=self.net,timeout=2,filter='udp')
        '''
        pkt=sniff(prn=self.sniff_callback,iface=self.net,timeout=2,filter='udp')
        thread.exit_thread()


class sniff_icmp_recv(threading.Thread):    
    def sniff_callback(self,p):
        global icmp_test
        if ICMP in p and p[ICMP].type==0x8 and cmp(p[IP].src[0:len(self.s_ip)],self.s_ip[0:len(self.s_ip)])==0 and \
                cmp(p[IP].dst[0:len(self.d_ip)],self.d_ip[0:len(self.d_ip)])==0:
            print p.display()
            icmp_test=icmp_test+1 
            thread.exit_thread()
   
    def __init__(self,net,s_ip,d_ip,data):  
        threading.Thread.__init__(self)  
        net = net.encode('ascii')
        self.net =net  
        self.s_ip   = s_ip  
        self.d_ip   = d_ip  
        self.data   = data
    def run(self): 
        pkt=sniff(prn=self.sniff_callback,iface=self.net,timeout=2,filter='icmp')
        thread.exit_thread()
   

class scapySession:
    def __init__(self):
        self.name = None
        self.handle = None

class arp: 
    def __init__(self):
        self.curSession = None
        self.session_list = []
        self.index = 0
    def get_mac(self,send_net,s_mac,s_ip,d_ip):
        global sniff_thread
        sniff_thread = sniff_arp_recv(send_net,s_mac,s_ip,d_ip)
        sniff_thread.start()
        time.sleep(0.2)
        p=Ether(src=s_mac,dst=dst_addr_b,type=0x0806)/ARP(hwtype=0x0001,ptype=0x0800,op=0x0001,hwsrc=s_mac,psrc=s_ip,hwdst=dst_addr_b,pdst=d_ip)
        sendp(p,iface=send_net,count=1)
        '''
        sendp(p,iface="eth0",count=1)
        sendp(p,iface=send_net,count=1)
        time.sleep(5)
        '''
        sniff_thread.join()
        if(arp_test>=1):
            print arp_test,"OK"
            return dst_addr
        else :
            print arp_test,"fail"
            return  "fail"



    def send_and_recv_udp(self,send_net,s_mac,d_mac,s_ip,d_ip,recv_net):
        global udp_test
        data="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        sniff_udp_thread = sniff_udp_recv(recv_net,s_ip,d_ip,data)
        sniff_udp_thread.start()
        time.sleep(0.1)
        p2=Ether(src=s_mac,dst=d_mac,type=0x0800)/IP(src=s_ip,dst=d_ip)/UDP()/data
        sendp(p2,iface=send_net,count=1)
        sniff_udp_thread.join()
        if(udp_test>=1):
            udp_test=0
            print   "OK"
            return  "OK"
        else :
            print "fail"
            return  "fail"


    def send_and_recv_icmp(self,send_net,s_mac,d_mac,s_ip,d_ip,recv_net):
        global sniff_icmp_thread
        global icmp_test
        data="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        sniff_icmp_thread = sniff_icmp_recv(recv_net,s_ip,d_ip,data)
        sniff_icmp_thread.start()
        time.sleep(0.1)
        p2=Ether(src=s_mac,dst=d_mac,type=0x0800)/IP(src=s_ip,dst=d_ip)/ICMP()/data
        '''
        sendp(p,iface=send_net,count=1)
        '''
        sendp(p2,iface=send_net,count=1)
        sniff_icmp_thread.join()
        if(icmp_test>=1):
            icmp_test=0
            print   "OK"
            return  "OK"
        else :
            print "fail"
            return  "fail"

    def loop_send_and_not_recv_icmp(self,send_net,d_mac,s_ip,d_ip,recv_net):
        s_mac="00:00:10:00:00:00"
        a=s_ip
        a1='.' 
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        c=s_ip[0:len(s_ip)-len(a)]
        n=254
        i=2
        print s_ip
        for i in range(n):
            if(i==0):
                i=i+1
            i=i+1

            d="%d"%(i)
            f="%x"%(i)
            e=c+d
            s_mac1=s_mac[0:len(s_mac)-len(f)]+f
            print "d and i is ",d,i
            print s_mac1
            print e 
            ret=self.send_and_recv_icmp(send_net0,s_mac1,d_mac,e,d_ip,recv_net)
            if(ret=="fail"):
                print "OK.............."
            else :
                print "fail+++++++++++++++++++"
                return "fail"
        return "OK"

    def loop_send_and_not_recv_udp(self,send_net,d_mac,s_ip,d_ip,recv_net):
        s_mac="00:00:10:00:00:00"
        a=s_ip
        a1='.' 
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        c=s_ip[0:len(s_ip)-len(a)]
        n=254
        i=2
        print s_ip
        for i in range(n):
            if(i==0):
                i=i+1
            i=i+1

            d="%d"%(i)
            f="%x"%(i)
            e=c+d
            s_mac1=s_mac[0:len(s_mac)-len(f)]+f
            print "d and i is ",d,i
            print s_mac1
            print e 
            '''
            ret=self.send_and_recv_udp(send_net0,s_mac1,d_mac,e,d_ip,recv_net)
            '''
            ret=self.send_and_recv_udp('eth1',s_mac1,d_mac,e,d_ip,recv_net)
            if(ret=="fail"):
                print "OK.............."
            else :
                print "udp notfail ++++++++++++++++++"
                return "fail"
        return "OK"


    def loop_send_and_recv_udp(self,send_net,d_mac,s_ip,d_ip,recv_net):
        s_mac="00:00:10:00:00:00"
        a=s_ip
        a1='.' 
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        c=s_ip[0:len(s_ip)-len(a)]
        n=254
        i=2
        print s_ip
        for i in range(n):
            if(i==0):
                i=i+1
            i=i+1

            d="%d"%(i)
            f="%x"%(i)
            e=c+d
            s_mac1=s_mac[0:len(s_mac)-len(f)]+f
            print "d and i is ",d,i
            print s_mac1
            print e 
            '''
            ret=self.send_and_recv_udp(send_net0,s_mac1,d_mac,e,d_ip,recv_net)
            '''
            ret=self.send_and_recv_udp('eth1',s_mac1,d_mac,e,d_ip,recv_net)
            if(ret=="fail"):
                print "udp fail ++++++++++++++++++"
                return "fail"
            else :
                    print "OK.............."
        return "OK"

    def loop_send_and_recv_icmp(self,send_net,d_mac,s_ip,d_ip,recv_net):
        s_mac="00:00:10:00:00:00"
        a=s_ip
        a1='.' 
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        c=s_ip[0:len(s_ip)-len(a)]
        n=254
        i=2
        print s_ip
        for i in range(n):
            if(i==0):
                i=i+1
            i=i+1

            d="%d"%(i)
            f="%x"%(i)
            e=c+d
            s_mac1=s_mac[0:len(s_mac)-len(f)]+f
            print "d and i is ",d,i
            print s_mac1
            print e 
            ret=self.send_and_recv_icmp(send_net0,s_mac1,d_mac,e,d_ip,recv_net)
            if(ret=="fail"):
                print "fail+++++++++++++++++++"
                return "fail"
            else :
                    print "OK.............."
        return "OK"
    def get_mac_and_send_icmp(self,recv_net,s_mac,s_ip,d_ip,send_net,s_ip1,s_mac1,d_ip1,):
        ret=self.get_mac(recv_net,s_mac,s_ip,d_ip)
        if(ret!="fail"):
            ret1=self.get_mac(send_net,s_mac1,s_ip1,d_ip1)
            if(ret1!="fail"):
                ret2=self.send_and_recv_icmp(send_net,s_mac1,ret1,s_ip1,s_ip,recv_net)
                if(ret2=="OK"):
                    return  "OK"
                if(ret2=="fail"):
                    print "send_and_recv_icmp fail"
                    return  "fail" 
        else :
            print "get mac  fail"
            return "fail"
        
    def loop_get_mac(self,send_net0,d_ip):
        s_mac="00:00:00:00:00:00"
        a=d_ip
        a1='.' 
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        a=a[a.find(a1)+1:]
        c=d_ip[0:len(d_ip)-len(a)]
        n=254
        i=0
        for i in range(n):
            if(i==0):
                i=i+1
            i=i+1
            d="%d"%(i)
            f="%x"%(i)
            if(d!=a):
                e=c+d
                s_mac1=s_mac[0:len(s_mac)-len(f)]+f
                print s_mac1
                print e 
                ret=self.get_mac(send_net0,s_mac1,e,d_ip)
                if(ret=="fail"):
                    print "fail.............."
                    return "fail"
                else :
                    print "OK.............."
        return "OK"
    def get_rand_vid(self,count):
        a = []
        count = int(count)
        while count > 1:
            a.append(count)
            count = count - 1
        return a
    def get_ip_address(self,ifname): 
        ifname = ifname.encode('ascii')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24]) 



if __name__ == '__main__':
    l = arp()
    print "eth3 = "+ l.get_ip_address('eth3') 
    '''

    ret=l.send_and_recv_icmp(send_net0,s_mac1,s_mac2,s_ip1,s_ip2,send_net1)
    print ret,"111111111+++++++++++++++++"

    ret=l.send_and_recv_icmp(send_net0,s_mac1,s_mac2,s_ip1,s_ip2,send_net2)
    print ret,"111111111+++++++++++++++++"

    ret=l.get_mac(send_net1,s_mac1,s_ip1,d_ip)
    ret=l.loop_send_and_recv_udp(send_net0,ret,s_ip1,s_ip0,send_net0)
    ret=l.send_and_recv_udp(send_net1,s_mac1,ret,s_ip1,d_ip,send_net1)
    ret=l.loop_send_and_recv_udp(send_net0,s_mac1,ret,s_ip1,s_ip0,send_net0)
    if(ret!="fail"):
        l.send_and_recv_icmp(send_net0,s_mac1,ret,s_ip1,s_ip0,send_net0)
        l.loop_send_and_not_recv_icmp(send_net0,ret,s_ip1,d_ip,send_net0)

    '''
