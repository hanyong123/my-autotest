'''
Created on 2013-3-25

@author: hany
'''
from scapy.all import *
import threading
import socket
import time
import sys

class attackDefenseTestLib:
    def __init__(self,host_lan_ip,host_wan_ip,router_lan_ip,router_wan_ip):
        self.host_lan_ip = host_lan_ip
        self.host_wan_ip = host_wan_ip
        self.router_lan_ip = router_lan_ip
        self.router_wan_ip = router_wan_ip
        self.host_lan_iface_name =  self.get_host_iface_name(host_lan_ip)
        self.host_wan_iface_name = self.get_host_iface_name(host_wan_ip)
        self.host_lan_iface_mac = self.get_host_iface_mac(host_lan_ip)
        self.router_lan_iface_mac = self.get_router_iface_mac(router_lan_ip)
        
    
    def get_router_iface_mac(self, ip):
        ans, unans = arping(ip)
        for pair in ans:
            if pair[1].hwsrc == None:
                raise RuntimeError('arp router wan mac error')
            else:
                return pair[1].hwsrc
            
    def get_host_iface_name(self, ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == ip:
                return str(dev.name)
        raise RuntimeError('can not find iface')
    
    def get_host_iface_mac(self, ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == ip:
                return str(dev.mac)
        raise RuntimeError('can\'t find host wan iface')
    
    def lan_should_recv_icmp_port_unreachable(self):
        ip = IP(src=self.host_lan_ip,dst=self.router_lan_ip)
        udp = UDP(dport=17800)
        p = ip/udp/'fuck you!!!'
        ans,unans = sr(p,timeout=2,retry=2)
        if len(ans) == 0:
            raise RuntimeError('no response icmp port unreachable')
        for p in ans:
            if p[1].haslayer(ICMP):
                icmp = p[1].getlayer(ICMP)
                if icmp.code != 3 :
                    raise RuntimeError('no response icmp port unreachable')
    
    def wan_should_recv_icmp_port_unreachable(self):
        ip = IP(src=self.host_wan_ip,dst=self.router_wan_ip)
        udp = UDP(sport=17801,dport=17800)
        p = ip/udp/'fuck you!!!'
        ans,unans = sr(p,timeout=2,retry=2)
        if len(ans) == 0:
            raise RuntimeError('no response icmp port unreachable')
        for p in ans:
            if p[1].haslayer(ICMP):
                icmp = p[1].getlayer(ICMP)
                if icmp.code != 3 :
                    raise RuntimeError('no response icmp port unreachable')
    
    def udp_flood_attck_test(self):
        class udp_flood(threading.Thread):
            def __init__(self,host_lan_ip,
                         host_wan_ip,
                         host_lan_iface_mac,
                         router_lan_iface_mac,
                         host_lan_iface_name):
                threading.Thread.__init__(self)
                self.host_lan_ip = host_lan_ip
                self.host_wan_ip = host_wan_ip
                self.host_lan_iface_mac = host_lan_iface_mac
                self.router_lan_iface_mac = router_lan_iface_mac
                self.host_lan_iface_name = host_lan_iface_name
                self.stop_event = threading.Event()
            
            def stop(self):
                self.stop_event.set()
            
            def stopped(self):
                return self.stop_event.isSet()
            
            def run(self):
                e = Ether(src=self.host_lan_iface_mac,dst=self.router_lan_iface_mac)
                ip = IP(src=self.host_lan_ip,dst=self.host_wan_ip,id=1111,ttl=99)
                udp = UDP(sport=1000,dport=2002)
                p = e/ip/udp/'aaaaaaaaaaaaa'
                time.clock()
                while not self.stopped():
                    st = time.clock()
                    sendp(p,count=100,iface=self.host_lan_iface_name)
                    while time.clock() - st < 1:
                        pass
        
        udp_flood_thread = udp_flood(self.host_lan_ip,
                                       self.host_wan_ip,
                                       self.host_lan_iface_mac,
                                       self.router_lan_iface_mac,
                                       self.host_lan_iface_name)
        udp_flood_thread.start()
        filter_rule = 'udp and dst host '+self.host_wan_ip
        a = sniff(filter=filter_rule,iface=self.host_wan_iface_name,timeout=15)
        num_pkts = len(a)
        pps = int(num_pkts/15)
        udp_flood_thread.stop()
        time.sleep(3)
        return str(pps)
    
    def tcp_flood_attck_test(self):
        class tcp_flood(threading.Thread):
            def __init__(self,host_lan_ip,
                         host_wan_ip,
                         host_lan_iface_mac,
                         router_lan_iface_mac,
                         host_lan_iface_name):
                threading.Thread.__init__(self)
                self.host_lan_ip = host_lan_ip
                self.host_wan_ip = host_wan_ip
                self.host_lan_iface_mac = host_lan_iface_mac
                self.router_lan_iface_mac = router_lan_iface_mac
                self.host_lan_iface_name = host_lan_iface_name
                self.stop_event = threading.Event()
                
            def stop(self):
                self.stop_event.set()
            
            def stopped(self):
                return self.stop_event.isSet()
            
            def run(self):
                e = Ether(src=self.host_lan_iface_mac,dst=self.router_lan_iface_mac)
                ip = IP(src=self.host_lan_ip,dst=self.host_wan_ip,id=1111,ttl=99)
                tcp = TCP(sport=1000,dport=1025,flags="S")
                p = e/ip/tcp/'aaaaaaaaaaaaa'
                time.clock()
                while not self.stopped():
                    st = time.clock()
                    sendp(p,count=100,iface=self.host_lan_iface_name)
                    while time.clock() - st < 1:
                        pass
        
        tcp_flood_thread = tcp_flood(self.host_lan_ip,
                                       self.host_wan_ip,
                                       self.host_lan_iface_mac,
                                       self.router_lan_iface_mac,
                                       self.host_lan_iface_name)
        tcp_flood_thread.start()
        filter_rule = 'tcp and dst host '+self.host_wan_ip
        a = sniff(filter=filter_rule,iface=self.host_wan_iface_name,timeout=15)
        num_pkts = len(a)
        pps = int(num_pkts/15)
        tcp_flood_thread.stop()
        time.sleep(3)
        return str(pps)
        
    def icmp_flood_atttck_test(self):
        class icmp_flood(threading.Thread):
            def __init__(self,host_lan_ip,
                         host_wan_ip,
                         host_lan_iface_mac,
                         router_lan_iface_mac,
                         host_lan_iface_name):
                threading.Thread.__init__(self)
                self.host_lan_ip = host_lan_ip
                self.host_wan_ip = host_wan_ip
                self.host_lan_iface_mac = host_lan_iface_mac
                self.router_lan_iface_mac = router_lan_iface_mac
                self.host_lan_iface_name = host_lan_iface_name
                self.stop_event = threading.Event()
                
            def stop(self):
                self.stop_event.set()
            
            def stopped(self):
                return self.stop_event.isSet()

            def run(self):
                e = Ether(src=self.host_lan_iface_mac,dst=self.router_lan_iface_mac)
                ip = IP(src=self.host_lan_ip,dst=self.host_wan_ip)
                p = e/ip/ICMP()/'aaaaaaaaaaaaa'
                time.clock()
                while not self.stopped():
                    st = time.clock()
                    sendp(p,count=100,iface=self.host_lan_iface_name)
                    while time.clock() - st < 1:
                        pass

        icmp_flood_thread = icmp_flood(self.host_lan_ip,
                                       self.host_wan_ip,
                                       self.host_lan_iface_mac,
                                       self.router_lan_iface_mac,
                                       self.host_lan_iface_name)
        icmp_flood_thread.start()
        filter_rule = 'icmp and dst host '+self.host_wan_ip
        a = sniff(filter=filter_rule,iface=self.host_wan_iface_name,timeout=15)
        num_pkts = len(a)
        pps = int(num_pkts/15)
        icmp_flood_thread.stop()
        time.sleep(3)
        return str(pps)
        
        
    def virus_filter_test(self,on_or_off):
        class virus_filter_sniif(threading.Thread):
            def __init__(self,
                         host_wan_ip,
                         host_wan_iface_name):
                threading.Thread.__init__(self)
                self.host_wan_ip = host_wan_ip
                self.host_wan_iface_name = host_wan_iface_name
                self.tcp_135_139_ok = False
                self.tcp_4444_ok = False
                self.tcp_445_ok = False
                self.tcp_69_ok = False
                self.tcp_39213_ok = False
                self.tcp_1433_ok = False
                self.udp_135_139_ok = False
                self.udp_4444_ok = False
                self.udp_445_ok = False
                self.udp_69_ok = False
                self.udp_39213_ok = False
                self.stop_event = threading.Event()
            
            def stop(self):
                self.stop_event.set()
            
            def stopped(self):
                return self.stop_event.isSet()
            
            def stop_callback(self,pkt):
                if self.stopped():
                    return True
                
            def sniff_callback(self,pkt):
                if pkt.haslayer(TCP):
                    tcp = pkt.getlayer(TCP)
                    if tcp.dport == 135 or \
                       tcp.dport == 136 or \
                       tcp.dport == 137 or \
                       tcp.dport == 138 or \
                       tcp.dport == 139:
                        self.tcp_135_139_ok = True
                    elif tcp.dport == 4444:
                        self.tcp_4444_ok = True
                    elif tcp.dport == 445:
                        self.tcp_445_ok = True
                    elif tcp.dport == 69:
                        self.tcp_69_ok = True
                    elif tcp.dport == 39213:
                        self.tcp_39213_ok = True
                    elif tcp.dport == 1433:
                        self.tcp_1433_ok = True
                elif pkt.haslayer(UDP):
                    udp = pkt.getlayer(UDP)
                    if udp.dport == 135 or \
                       udp.dport == 136 or \
                       udp.dport == 137 or \
                       udp.dport == 138 or \
                       udp.dport == 139:
                        self.udp_135_139_ok = True
                    elif udp.dport == 4444:
                        self.udp_4444_ok = True
                    elif udp.dport == 445:
                        self.udp_445_ok = True
                    elif udp.dport == 69:
                        self.udp_69_ok = True
                    elif udp.dport == 39213:
                        self.udp_39213_ok = True
            def run(self):
                    sniff(store=0, 
                             prn=self.sniff_callback, 
                             stop_filter=self.stop_callback, 
                             iface=self.host_wan_iface_name)
        
        tcp_dport = [135,136,137,138,139,4444,445,69,39213,1433]
        udp_port = [135,136,137,138,139,4444,445,69,39213]
        e = Ether(src=self.host_lan_iface_mac,dst=self.router_lan_iface_mac)
        th = virus_filter_sniif(self.host_wan_ip,self.host_wan_iface_name)
        th.start()
        for dp in tcp_dport:
            p = e/IP(src=self.host_lan_ip,dst=self.host_wan_ip)/TCP(dport=dp)
            sendp(p,count=5,iface=self.host_lan_iface_name)
            time.sleep(5)
        for dp in udp_port:
            p = e/IP(src=self.host_lan_ip,dst=self.host_wan_ip)/UDP(dport=dp)
            sendp(p,count=5,iface=self.host_lan_iface_name)
            time.sleep(5)
        th.stop()
        time.sleep(5)
        if on_or_off == 'on':
            if th.tcp_135_139_ok == True:
                raise RuntimeError('tcp_135_139_ok == True')
            if th.tcp_4444_ok == True:
                raise RuntimeError('tcp_4444_ok == True')
            if th.tcp_445_ok == True:
                raise RuntimeError('tcp_445_ok == True')
            if th.tcp_69_ok == True:
                raise RuntimeError('tcp_69_ok == True')
            if th.tcp_39213_ok == True:
                raise RuntimeError('tcp_39213_ok == True')
            if th.tcp_1433_ok == True:
                raise RuntimeError('tcp_1433_ok == True')
            if th.udp_135_139_ok == True:
                raise  RuntimeError('udp_135_139_ok == True')
            if th.udp_4444_ok == True:
                raise  RuntimeError('udp_4444_ok == True')
            if th.udp_445_ok == True:
                raise  RuntimeError('udp_445_ok == True')
            if th.udp_69_ok == True:
                raise RuntimeError('udp_69_ok == True')
            if th.udp_39213_ok == True:
                raise RuntimeError('udp_39213_ok == True')
        elif on_or_off == 'off':
            if th.tcp_135_139_ok == False:
                raise RuntimeError('tcp_135_139_ok == False')
            if th.tcp_4444_ok == False:
                raise RuntimeError('tcp_4444_ok == False')
            if th.tcp_445_ok == False:
                raise RuntimeError('tcp_445_ok == False')
            if th.tcp_69_ok == False:
                raise RuntimeError('tcp_69_ok == False')
            if th.tcp_39213_ok == False:
                raise RuntimeError('tcp_39213_ok == False')
            if th.tcp_1433_ok == False:
                raise RuntimeError('tcp_1433_ok == False')
            if th.udp_135_139_ok == False:
                raise  RuntimeError('udp_135_139_ok == False')
            if th.udp_4444_ok == False:
                raise  RuntimeError('udp_4444_ok == False')
            if th.udp_445_ok == False:
                raise  RuntimeError('udp_445_ok == False')
            if th.udp_69_ok == False:
                raise RuntimeError('udp_69_ok == False')
            if th.udp_39213_ok == False:
                raise RuntimeError('udp_39213_ok == False')
            
    def arp_attack_test(self,prot_on_or_off):
        class arpSniff:
            def __init__(self,host_lan_iface_name,router_lan_ip,router_lan_mac,timeout):
                self.host_lan_iface_name = host_lan_iface_name
                self.router_lan_mac = router_lan_mac
                self.timeout = timeout
                self.router_lan_ip = router_lan_ip
                self.arp_count = 0
            
            def sniff_callback(self,pkt):
                if pkt.haslayer(ARP):
                    e = pkt.getlayer(Ether)
                    arp = pkt.getlayer(ARP)
                    if e.dst == 'ff:ff:ff:ff:ff:ff' and \
                    arp.hwsrc == self.router_lan_mac and \
                    arp.psrc == self.router_lan_ip:
                        self.arp_count = self.arp_count + 1
            def run(self):
                sniff(store=0,prn=self.sniff_callback,timeout=self.timeout,iface=self.host_lan_iface_name)
        
        arp_sniff_obj = arpSniff(self.host_lan_iface_name,self.router_lan_ip,\
                                 self.router_lan_iface_mac,30)
        arp_sniff_obj.run() 
        if prot_on_or_off == 'off' and arp_sniff_obj.arp_count > 0:
            raise RuntimeError('receeive gateway arp')
        
        if prot_on_or_off == 'on' and arp_sniff_obj.arp_count == 0:
            raise RuntimeError('no recive the arp')
        
        
                         
    def should_rcv_tcp_rst(self):
        class tcpRstSniff(threading.Thread):
            def __init__(self,host_lan_ip,router_lan_ip,interface,timeout=60):
                threading.Thread.__init__(self)
                self.interface = interface
                self.timeout = timeout
                self.host_lan_ip = host_lan_ip
                self.router_lan_ip = router_lan_ip
                self.recv_tcp_rst = False
            
            def sniff_callback(self,pkt):
                if pkt.haslayer(TCP):
                    ip = pkt.getlayer(IP)
                    tcp = pkt.getlayer(TCP)
                    if ip.src == self.router_lan_ip and \
                        ip.dst == self.host_lan_ip and tcp.flags == 0x014:
                        self.recv_tcp_rst = True
            
            def stop_callback(self,pkt):
                return self.recv_tcp_rst
            
            def run(self):
                sniff(store=0,prn=self.sniff_callback,timeout=self.timeout,\
                      stop_filter=self.stop_callback,iface=self.interface)
        
        pt = tcpRstSniff(self.host_lan_ip,self.router_lan_ip,self.host_lan_iface_name)
        pt.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((self.router_lan_ip,17800))
            client.send('fuck you!!!')
        except socket.error, msg:
            client.close()
            client = None
        time.sleep(5)
        if pt.recv_tcp_rst == False:
            pt.recv_tcp_rst = True
            time.sleep(3)
            raise  RuntimeError('no recv tcp rst')
        
            
if __name__ == '__main__':
    a = attackDefenseTestLib('192.168.1.25','100.0.0.100','192.168.1.1','100.0.10.100')
    a.arp_attack_test()
    sys.stdout = sys.__stdout__ 
    