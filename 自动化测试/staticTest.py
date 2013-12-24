'''
Created on 2013-2-4

@author: hany
'''
from robot.libraries import  BuiltIn
from scapy.all import *
import wmi
import subprocess
import threading
import time
def get_var(var_name):
    m = BuiltIn.BuiltIn()
    return m.get_variable_value(var_name)

static_pcap_dir = 'static_pcap/'
class DNSTest:
    def __init__(self,router_wan_ip,dns1,dns2,host_wan_iface,url,timeout=80):
        self.dns1 = dns1
        self.dns2 = dns2
        self.router_wan_ip = router_wan_ip
        self.url = url
        self.timeout = timeout
        self.bSuccess = False
        self.bdns1 = False
        self.bdns2 = False
        self.host_wan_iface = host_wan_iface
        
    def sniff_callback(self,pkt):
        if pkt.haslayer(DNS):
            dns =  pkt.getlayer(DNS)
            dnsq = pkt.getlayer(DNSQR)
           
            if dns.qr == 0 and dnsq.qname == self.url+'.':
                ip = pkt.getlayer(IP)
                if self.dns1 == '' and ip.dst == self.dns2 and ip.src == self.router_wan_ip:
                    self.bSuccess = True
                elif self.dns2 == '' and ip.dst == self.dns1 and ip.src == self.router_wan_ip:
                    self.bSuccess = True
                elif self.dns1 != '' and self.dns2 != '':
                    if ip.dst == self.dns1 and ip.src == self.router_wan_ip:
                        self.bdns1 = True
                    if ip.dst == self.dns2 and ip.src == self.router_wan_ip:
                        self.bdns2 = True
                    if self.bdns1 and self.bdns2:
                        self.bSuccess = True
                else:
                    self.bSuccess = True
                    
                        
    def stop_callback(self,pkt):
        return self.bSuccess
    
    def run(self):
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=self.host_wan_iface)
        casename = get_var('${TEST NAME}')
        pcapfilename = static_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

class pingThread(threading.Thread):
    def __init__(self,host_lan_ip,host_lan_mac,router_lan_mac,host_lan_iface_name):
        threading.Thread.__init__(self)
        self.host_lan_ip = host_lan_ip
        self.host_lan_mac = host_lan_mac
        self.router_lan_mac = router_lan_mac
        self.host_lan_iface_name = host_lan_iface_name
        print self.host_lan_ip
        print self.host_lan_mac
        print self.router_lan_mac
        print self.host_lan_iface_name
    
    def GetAIPAddress(self):
        return "%d.%d.%d.%d" %(random.randint(1,126),random.randint(0,255),random.randint(0,255),random.randint(1,254))
    
    def GetBIPAddress(self):
        return "%d.%d.%d.%d" %(random.randint(128,191),random.randint(1,255),random.randint(0,255),random.randint(1,254))
    
    def GetCIPAddress(self):
        return "%d.%d.%d.%d" %(random.randint(192,223),random.randint(0,255),random.randint(1,254),random.randint(1,254))
    
    def GetRandomIP(self):
        ip = None
        while True:
            sel = random.randint(1,3)
            if sel == 1:
                ip = self.GetAIPAddress()
                if ip.find('10.') == 0:
                    continue
                else:
                    return ip
                    break
            elif sel == 2:
                ip = self.GetBIPAddress()
                if ip.find('172.') == 0:
                    continue
                else:
                    return ip
                    break
            elif sel == 3:
                ip = self.GetCIPAddress()
                if ip.find('192.168.') == 0:
                    continue
                else:
                    return ip
                    break
    def run(self):
        time.sleep(5)
        for i in range(100):
            dstIp = self.GetRandomIP()
            print dstIp
            p = Ether(src=self.host_lan_mac,dst=self.router_lan_mac)/IP(src=self.host_lan_ip,dst=dstIp)/ICMP()
            sendp(p,iface=self.host_lan_iface_name)
            time.sleep(1)

class PingCheck:
    def __init__(self,host_wan_iface_name,timeout=120):
        self.timeout = timeout
        self.host_wan_iface_name = host_wan_iface_name
        self.ping_pkt_count = 0
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(ICMP):
            icmp = pkt.getlayer(ICMP)
            if icmp.type == 8:
                self.ping_pkt_count = self.ping_pkt_count + 1
    
    def run(self):
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=None,iface= self.host_wan_iface_name)
        casename = get_var('${TEST NAME}')
        pcapfilename = static_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)
 
class mtuSniif:
    def __init__(self,host_wan_iface_name,host_wan_ip,router_wan_ip,timeout=120):
        self.timeout = timeout
        self.host_wan_iface_name = host_wan_iface_name
        self.host_wan_ip = host_wan_ip
        self.router_wan_ip = router_wan_ip
        self.mtu = 0
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(IP):
            ip = pkt.getlayer(IP)
            if ip.proto == 1 and ip.src == self.router_wan_ip and ip.dst == self.host_wan_ip and ip.frag == 0:
                self.mtu = len(ip)
    
    def stop_callback(self,pkt):
        if self.mtu != 0:
            return True
        return False
    
    def run(self):
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface= self.host_wan_iface_name)
        casename = get_var('${TEST NAME}')
        pcapfilename = static_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)
        
class macCloneSniff:
    
    def __init__(self,host_wan_iface_name,timeout=120):
        self.timeout = timeout
        self.host_wan_iface_name = host_wan_iface_name
        self.router_wan_mac = None
     
    def sniff_callback(self,pkt):
        if pkt.haslayer(ICMP):
            icmp = pkt.getlayer(ICMP)
            if icmp.type == 0:
                e = pkt.getlayer(Ether)
                self.router_wan_mac = str(e.src)
                print self.router_wan_mac
    
    def stop_callback(self,pkt):
        if self.router_wan_mac != None:
            return True
        return False
    
    def run(self):
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface= self.host_wan_iface_name)
        casename = get_var('${TEST NAME}')
        pcapfilename = static_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)
                
class staticTest:
    def __init__(self,host_lan_ip,host_wan_ip,router_lan_ip,router_wan_ip):
        self.host_lan_ip = host_lan_ip
        self.host_wan_ip = host_wan_ip
        self.router_lan_ip = router_lan_ip
        self.router_wan_ip = router_wan_ip
        self.host_lan_mac = self.get_host_lan_mac(host_lan_ip)
        self.host_wan_mac = self.get_host_wan_mac(host_wan_ip)
        self.router_lan_mac =  self.get_router_lan_mac(router_lan_ip)
        self.router_wan_mac = self.get_router_wan_mac(router_wan_ip)
        
    def get_host_wan_mac(self,host_wan_ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == host_wan_ip:
                return str(dev.mac)
        raise RuntimeError('can\'t find host wan iface')
    
    def get_host_lan_mac(self,host_lan_ip):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == host_lan_ip:
                return str(dev.mac)
        raise RuntimeError('can\'t find host lan iface')
    
    def re_host_lan_mac(self):
        s = self.host_lan_mac.replace(':','-')
        s = s.upper()
        return s
    
    def get_router_lan_mac(self,router_lan_ip):
        ans,unans = arping(router_lan_ip)
        for pair in ans:
            if pair[1].hwsrc == None:
                raise RuntimeError('arp router lan mac error')
            else:
                return pair[1].hwsrc
    
    def get_router_wan_mac(self,router_wan_ip,):
        ans,unans = arping(router_wan_ip)
        for pair in ans:
            if pair[1].hwsrc == None:
                raise RuntimeError('arp router wan mac error')
            else:
                return pair[1].hwsrc
    def get_host_wan_iface_name(self):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == self.host_wan_ip:
                return str(dev.name)
        raise RuntimeError('can\'t find wan iface')
    
    def get_host_lan_iface_name(self):
        for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == self.host_lan_ip:
                return str(dev.name)
        raise RuntimeError('can\'t find lan iface')
        
    def ping_router_wan_should_reply(self):
        p = IP(src=self.host_wan_ip,dst= self.router_wan_ip)/ICMP()
        i = self.get_host_wan_iface_name()
        ans,unans = sr(p,iface=i,timeout=2,retry=5,multi=1)
        if len(ans) == 0:
            raise RuntimeError('No Recv Ping reply')
    
    def ping_router_wan_get_mtu(self,len=2000):
        line = 'ping '+self.router_wan_ip+ ' -l '+ str(len)
        subprocess.Popen(line,shell=True)
        i = self.get_host_wan_iface_name()
        p = mtuSniif(i,self.host_wan_ip,self.router_wan_ip)
        p.run()
        print str(p.mtu)
        return str(p.mtu)
    
    def nslookup(self,url):
        cmd ='ping '+url
        subprocess.Popen(cmd,shell=True)
    
    def DNSCheck(self,dns1,dns2,url):
        i = self.get_host_wan_iface_name()
        p = DNSTest(self.router_wan_ip,dns1,dns2,i,url)
        p.run()
        if p.bSuccess == False:
            raise RuntimeError('DNS Check Error')
        
    def send_100_random_dstip_ping(self):
        i = self.get_host_lan_iface_name()
        p = pingThread(self.host_lan_ip,self.host_lan_mac,self.router_lan_mac,i)
        p.start()
    
    def get_ping_req_count(self):
        i = self.get_host_wan_iface_name()
        p = PingCheck(i)
        p.run()
        print p.ping_pkt_count
        return str(p.ping_pkt_count)
    
    def mac_clone_check(self,mac):
        i = self.get_host_wan_iface_name()
        line = 'ping '+self.router_wan_ip
        print line
        subprocess.Popen(line,shell=True)
        p = macCloneSniff(i,20)
        p.run()
        if p.router_wan_mac == None:
            raise RuntimeError('ping fail')
        s = p.router_wan_mac.replace(':','-')
        s = s.upper()
        s1 = mac.upper()
        if s != s1 :
            line = s +'!=' + s1
            raise RuntimeError(line)
        
if __name__ == '__main__':
    pass