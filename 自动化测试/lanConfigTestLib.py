# -*- coding: GBK -*-
'''
Created on 2013-3-14

@author: hany
'''

from scapy.all import *
from robot.libraries import  BuiltIn
import subprocess
import socket
import wmi
import sys
reload(sys)
sys.setdefaultencoding('GBK')

lan_config_pcap_dir = 'lan_config_pcap/'

class lanConfigTestLib:
    def __init__(self,host_lan_ip):
        self.host_lan_ip = host_lan_ip
        self.host_lan_mac = self.get_host_iface_mac(host_lan_ip)
        self.host_lan_iface = self.get_host_iface_name(host_lan_ip)
    
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
        raise RuntimeError('can not find iface')
    
    def should_be_mac(self,mac):
        class pingReplySniff:
            def __init__(self,mac,host_lan_iface,timeout=30):
                self.mac = mac
                self.host_lan_iface = host_lan_iface
                self.timeout = timeout
                self.test_ok = False
            
            def sniff_callback(self,pkt):
                if pkt.haslayer(ICMP):
                    icmp = pkt.getlayer(ICMP)
                    if icmp.type == 0:
                        ether = pkt.getlayer(Ether)
                        router_lan_mac = ether.src
                        router_lan_mac = router_lan_mac.replace(':','-')
                        router_lan_mac = router_lan_mac.upper()
                        if router_lan_mac == self.mac:
                            self.test_ok = True
            
            def stop_callback(self,pkt):
                return self.test_ok
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_lan_iface)
                casename = BuiltIn.BuiltIn().get_variable_value('${TEST NAME}')
                pcapfilename = lan_config_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        
        p = pingReplySniff(mac,self.host_lan_iface)
        p.run()
        if p.test_ok == False :
            raise RuntimeError('the icmp reply src mac not router lan mac')
    
    def set_host_lan_addr(self,ip,mask,gateway):
        c = wmi.WMI ()
        for nic in c.Win32_NetworkAdapter ():
            if nic.NetConnectionID != None and nic.MACAddress != None:
                if nic.MACAddress.upper() == self.host_lan_mac.upper():
                    if len(gateway) != 0:
                        cmd = 'netsh interface IP set address '+nic.NetConnectionID+ \
                        ' static '+ip+' '+mask+' gateway='+gateway+' gwmetric=1'
                    else:
                        cmd = 'netsh interface IP set address '+nic.NetConnectionID+ \
                        ' static '+ip+' '+mask+' gateway='
                    subprocess.call(cmd)
                   
                
                
 

        
if __name__ == '__main__':
    p = lanConfigTestLib('192.168.1.25')
    p.set_host_lan_addr('192.168.1.25','255.255.255.0','192.168.1.1')