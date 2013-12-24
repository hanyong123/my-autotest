'''
Created on 2013-1-23

@author: hany
'''
from robot.libraries import  BuiltIn
from scapy.all import *
import sys
import subprocess
import threading
import time
import wmi

var_host_wan_ip = '${host_wan_ip}'
var_host_lan_ip = '${host_lan_ip}'
pppoe_pcap_dir = 'pppoe_pcap/'

def get_var(var_name):
    m = BuiltIn.BuiltIn()
    return m.get_variable_value(var_name)


def block_all_out_lan_data(router_lan_ip,host_lan_ip):
    cmd = 'net start PolicyAgent'
    subprocess.call(cmd,shell= True)
    cmd = 'ipseccmd -p "a" -r "a" -f '+host_lan_ip+'='+router_lan_ip+':80:TCP -n PASS -x'
    subprocess.call(cmd,shell=True)
    cmd = 'ipseccmd -p "c" -r "c" -f '+host_lan_ip+'=*  -n BLOCK -x'
    subprocess.call(cmd,shell=True)
    time.sleep(5)

def disable_block(router_lan_ip,host_lan_ip):
    cmd = 'ipseccmd -p "a" -r "a" -f '+host_lan_ip+'='+router_lan_ip+':80:TCP -n PASS -y'
    subprocess.call(cmd,shell=True)
    cmd = 'ipseccmd -p "a" -r "a" -f '+host_lan_ip+'='+router_lan_ip+':80:TCP -n PASS -o'
    subprocess.call(cmd,shell=True)
    cmd = 'ipseccmd -p "c" -r "c" -f '+host_lan_ip+'=*  -n BLOCK -y'
    subprocess.call(cmd,shell=True)
    cmd = 'ipseccmd -p "c" -r "c" -f '+host_lan_ip+'=*  -n BLOCK -o'
    subprocess.call(cmd,shell=True)
    cmd = 'net stop PolicyAgent'
    subprocess.call(cmd,shell=True)
    cmd = 'net start PolicyAgent'
    subprocess.call(cmd,shell=True)
    time.sleep(5)
    
def get_host_wan_iface_name():
    host_wan_ip = get_var(var_host_wan_ip)
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        if dev.ip == host_wan_ip:
            return dev.name
    raise RuntimeError('can\'t find wan iface')

def get_host_wan_iface_mac():
    host_wan_ip = get_var(var_host_wan_ip)
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        return str(dev.mac)
    raise RuntimeError('can\'t find wan iface')

def get_host_lan_iface_name():
    host_lan_ip = get_var(var_host_lan_ip)
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        if dev.ip == host_lan_ip:
            return dev.name
    raise RuntimeError('can\'t find wan iface')


def re_host_lan_mac():
    host_lan_ip = get_var(var_host_lan_ip)
    for iface_name in sorted(ifaces.data.keys()):
            dev = ifaces.data[iface_name]
            if dev.ip == host_lan_ip:
                mac = str(dev.mac)
                mac = mac.replace(':','-')
                mac = mac.upper()
                return mac
    raise RuntimeError('can\'t find host lan iface')

def get_router_lan_iface_mac():
    router_lan_ip = get_var('${router_lan_ip}')
    ans,unans = arping(router_lan_ip)
    for pair in ans:
        return pair[1].hwsrc
    
def vm_ifconfig_down(vm_user,vm_passwd,vm_path,iface):
    cmd = 'vmrun -T ws -gu '+vm_user+' -gp '+vm_passwd+' runProgramInGuest '+vm_path+' /sbin/ifconfig '+iface+' down'
    print cmd
    subprocess.check_call(cmd,shell=True)

def vm_ifconfig_up(vm_user,vm_passwd,vm_path,iface):
    cmd = 'vmrun -T ws -gu '+vm_user+' -gp '+vm_passwd+' runProgramInGuest '+vm_path+' /sbin/ifconfig '+iface+' up'
    print cmd
    subprocess.check_call(cmd,shell=True)
    time.sleep(10)
    
procPing = None
def send_data(dstIp):
    global procPing
    cmd = 'ping '+dstIp+ ' -n 50'
    procPing = subprocess.Popen(cmd,shell=True)

def recv_ping_reply():
    global procPing
    s = procPing.communicate()[0]
    if s.find('Reply from') == -1:
        raise RuntimeError('No recv ping reply')
      
class PPP_CHAP(Packet):
    name = "PPP CHAP"
    fields_desc = [ByteEnumField('code',None,{0x01:'Challenge',0x02:'Response',0x03:'Success',0x04:'Failure'}),
                   XByteField('id',None),
                   ShortField('len',None),
                   StrLenField('data','',length_from=lambda pkt:pkt.len-4)]
    
bind_layers(PPP,PPP_CHAP,proto=0xc223)

class PPP_PAP(Packet):
    name = "PPP PAP"
    fields_desc = [ByteEnumField('code',None,{0x01:'Authenticate - Request',0x02:'Authenticate - Ack',0x03:'Authenticate-Nak '}),
                   XByteField('id',None),
                   ShortField('len',None),
                   XByteField('dataLen',None),
                   StrLenField('data','',length_from=lambda pkt:pkt.dataLen)]

bind_layers(PPP,PPP_PAP,proto=0xc023)

class PPPoETag(Packet):
    name = "PPPoE Tag"
    fields_desc = [ ShortEnumField('tag_type', None,
                                   {0x0000: 'End-Of-List',
                                    0x0101: 'Service-Name',
                                    0x0102: 'AC-Name',
                                    0x0103: 'Host-Uniq',
                                    0x0104: 'AC-Cookie',
                                    0x0105: 'Vendor-Specific',
                                    0x0110: 'Relay-Session-Id',
                                    0x0201: 'Service-Name-Error',
                                    0x0202: 'AC-System-Error',
                                    0x0203: 'Generic-Error'}),
                    FieldLenField('tag_len', None, length_of='tag_value', fmt='H'),
                    StrLenField('tag_value', '', length_from=lambda pkt:pkt.tag_len)]
    def extract_padding(self, s):
        return '', s
    
class PPPoED_Tags(Packet):
    name = "PPPoE Tag List"
    fields_desc = [ PacketListField('tag_list', None, PPPoETag) ]

bind_layers(PPPoED, PPPoED_Tags, type=1)

hostUiq = None
acCookie = None 
class PPPoEConnectWaitObj:
    
    def __init__(self,timeout=80):
        self.timeout = timeout
        self.connect_success = None
        
    
    def sniff_callback(self,pkt):
        global hostUiq
        global acCookie
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            if pppoed.code == 0x07:
                tags = pkt.getlayer(PPPoED_Tags)
                for tag in tags.tag_list:
                    if tag.tag_type == 0x0104:
                        acCookie = tag.tag_value
                        break
            if pppoed.code == 0x19:
                tags = pkt.getlayer(PPPoED_Tags)
                for tag in tags.tag_list:
                    if tag.tag_type == 0x0103:
                        hostUiq = tag.tag_value
                        break
                        
        if pkt.haslayer(PPP_CHAP):
            chap = pkt.getlayer(PPP_CHAP)
            if chap.code == 0x04:
                self.connect_success = False
                print 'chap auth fail'
            elif chap.code == 0x03 and chap.data == 'Access granted':
                self.connect_success = True
                print 'chap auth success'
                
        if pkt.haslayer(PPP_PAP):
            pap = pkt.getlayer(PPP_PAP)
            if pap.code == 0x03 and pap.data == 'Login incorrect' or pap.data == 'Authentication failure':
                self.connect_success = False
                print 'PAP auth fail'
            elif pap.code == 0x02 and pap.data == 'Session started successfully':
                self.connect_success = True
                print 'PAP auth success'
                    
    def stop_callback(self,pkt):
        if self.connect_success != None:
            return True
        return False
        
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        print pcapfilename
        wrpcap(pcapfilename,pkts)
        if self.connect_success == False or self.connect_success == None:
            raise RuntimeError('PPPoE connect Error')
        
def PPPoEConnectWait(timeout=80):
    wait = PPPoEConnectWaitObj(timeout)
    wait.run()

class serviceNameTestSniff:
    def __init__(self,serviceName,timeout=80):
        self.timeout = timeout
        self.serviceName = serviceName
        self.bSendPADO = False
        self.bPADIContainServiceName = None
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            if pppoed.code == 9:
                tags = pppoed.getlayer(PPPoED_Tags)
                serviceName = ''
                for tag in tags.tag_list:
                    if tag.tag_type == 257:
                        serviceName = tag.tag_value
                        if serviceName ==  self.serviceName:
                            self.bPADIContainServiceName = True
                            break
                        else:
                            self.bPADIContainServiceName = False
            if pppoed.code == 7:
                    self.bSendPADO = True
    
    def stop_callback(self,pkt):
        if self.bPADIContainServiceName != None and self.bSendPADO == True:
            return True
        return False
    
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)
        
    
def PADIContainServiceName(serviceName):
    p = serviceNameTestSniff(serviceName)
    p.run()
    if p.bPADIContainServiceName == None or p.bPADIContainServiceName == False:
        raise  RuntimeError('PADI NOT Contain Service Name')
    if p.bSendPADO == False:
        raise RuntimeError('No Response PADO')
    
def shouldNotResponsePADO(serviceName):
    p = serviceNameTestSniff(serviceName,20)
    p.run()
    if p.bPADIContainServiceName == None or p.bPADIContainServiceName == False:
        raise  RuntimeError('PADI NOT Contain Service Name')
    if p.bSendPADO == True:
        raise RuntimeError('Response PADO')
    
def PADIShouldNotContainServiceName(serviceName):
    p = serviceNameTestSniff(serviceName)
    p.run()
    if p.bPADIContainServiceName == True:
        raise RuntimeError('PADI Contain Service Name')
    if p.bSendPADO == False:
        raise  RuntimeError('No Response PADO')

class ACNmaeTest:
    def __init__(self,serviceName,timeout=20):
        self.timeout = timeout
        self.serviceName = serviceName
        self.bPADOContainErrorServiceName = False
        self.bSendPADR = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            if pppoed.code == 7:
                tags = pppoed.getlayer(PPPoED_Tags)
                serviceName = ''
                for tag in tags.tag_list:
                    if tag.tag_type == 257:
                        serviceName = tag.tag_value
                    if serviceName == self.serviceName:
                        self.bPADOContainErrorServiceName = True
                        break
            if pppoed.code == 25:
                self.bSendPADR = True
            
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=None,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def PADOShouldContainerrorServiceNmae(serviceName):
    p = ACNmaeTest(serviceName)
    p.run()
    if p.bPADOContainErrorServiceName  == False:
        raise RuntimeError('PADO Not Contain Service Nmae')
    if p.bSendPADR == True:
        raise RuntimeError('Send PADR')

def reponseallPADOtoPADR(serviceName):
    p = ACNmaeTest(serviceName)
    p.run()
    if p.bPADOContainErrorServiceName  == False:
        raise RuntimeError('PADO Not Contain Service Nmae')
    if p.bSendPADR == False:
        raise RuntimeError('No response Send PADR')
    
def nslookup(url):
    cmd ='ping '+url
    subprocess.Popen(cmd,shell=True)

class DNSTest:
    def __init__(self,dns1,dns2,router_wan_ip,url,timeout=80):
        self.dns1 = dns1
        self.dns2 = dns2
        self.timeout = timeout
        self.bSuccess = False
        self.bdns1 = False
        self.bdns2 = False
        self.router_wan_ip = router_wan_ip
        self.url = url
    
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
                    if ip.src == self.router_wan_ip:
                        self.bSuccess = True
                    
                        
    def stop_callback(self,pkt):
        return self.bSuccess
    
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def DNSTestOK(dns1,dns2,router_wan_ip,url):
    p = DNSTest(dns1,dns2,router_wan_ip,url)
    p.run()
    if p.bSuccess == False:
        raise RuntimeError('DNS Test Fail')

class pingFromLanToWanThread(threading.Thread):
    def __init__(self,lan_ip,wan_ip):
        threading.Thread.__init__(self)
        self.lan_ip = lan_ip
        self.wan_ip = wan_ip
        self.srcMac = self.get_host_lan_iface_mac()
        self.ping_reply_ok = False
        self.stop = threading.Event()
    
    def stopPt(self):
        self.stop.set()
        
    def get_host_lan_iface_mac(self):
        c = wmi.WMI ()
        nicConfigs = c.Win32_NetworkAdapterConfiguration(IPEnabled = True)
        for name in nicConfigs:
            if name.IPAddress[0] == self.lan_ip:
                return name.MACAddress
    def run(self):
        router_lan_mac = get_router_lan_iface_mac()
        p = Ether(src=self.srcMac,dst=router_lan_mac)/IP(src=self.lan_ip,dst=self.wan_ip)/ICMP()
        lan_iface = get_host_lan_iface_name()
        for i in range(30):
            if self.stop.isSet():
                break
            sendp(p,iface=lan_iface)
            self.stop.wait(1)
#        sendp(p,iface=lan_iface,count=30,inter=1)
    
pt = None
def ping_from_lan_to_wan(lan_ip,wan_ip):
    global pt
    pt = pingFromLanToWanThread(lan_ip,wan_ip)
    pt.start()

def stop_ping():
    global pt
    if pt != None:
        pt.stopPt()
    pt = None
    
class pingreplyok:
    def __init__(self,timeout=20):
        self.timeout = timeout
        self.ping_reply_ok = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(ICMP):
            icmp = pkt.getlayer(ICMP)
            if icmp.type == 0:
                self.ping_reply_ok = True
    
    def stop_callback(self,pkt):
        return self.ping_reply_ok
    
    def run(self):
        i = get_host_lan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def ping_reply_should_ok():
    p = pingreplyok()
    p.run()
    if p.ping_reply_ok == False:
        raise RuntimeError('No Recv Ping Reply')
        
        
class pingsniifLan:
    
    def __init__(self,host_lan_ip,pppoe_server_ip,timeout=80):
        self.host_lan_ip = host_lan_ip
        self.pppoe_server_ip = pppoe_server_ip 
        self.timeout = timeout
        self.lan_ping_request_ok = False
        self.lan_ping_reply_ok = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(ICMP):
            ip  = pkt.getlayer(IP)
            icmp = pkt.getlayer(ICMP)
            if icmp.type == 8:
                if ip.src == self.host_lan_ip and ip.dst == self.pppoe_server_ip and pkt.haslayer(PPPoE) == False:
                    self.lan_ping_request_ok = True
                    s = pkt.summary()
                    print s
                
            if icmp.type == 0:
                if ip.src == self.pppoe_server_ip and ip.dst == self.host_lan_ip and pkt.haslayer(PPPoE) == False:
                    self.lan_ping_reply_ok = True
                    s = pkt.summary()
                    print s
    def stop_callback(self,pkt):
        if self.lan_ping_request_ok and  self.lan_ping_reply_ok:
            return True
        return False
    
    def run(self):
        i = get_host_lan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '_lan.pcap'
        wrpcap(pcapfilename,pkts)

def ping_test_lan_side_ok(host_lan_ip,pppoe_server_ip):
    p = pingsniifLan(host_lan_ip,pppoe_server_ip)
    p.run()
    if p.lan_ping_request_ok == False:
        raise RuntimeError('ping request fail')
    if p.lan_ping_reply_ok == False:
        raise RuntimeError('ping reply fail')


class pingsniifWan:
    
    def __init__(self,router_wan_ip,pppoe_server_ip,timeout=80):
        self.router_wan_ip = router_wan_ip
        self.pppoe_server_ip = pppoe_server_ip 
        self.timeout = timeout
        self.wan_ping_request_ok = False
        self.wan_ping_reply_ok = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(ICMP):
            ip  = pkt.getlayer(IP)
            icmp = pkt.getlayer(ICMP)
            if icmp.type == 8:
                if ip.src == self.router_wan_ip and ip.dst == self.pppoe_server_ip and pkt.haslayer(PPPoE) == True:
                    self.wan_ping_request_ok = True
                    s = pkt.summary()
                    print s
                
            if icmp.type == 0:
                if ip.src == self.pppoe_server_ip and ip.dst == self.router_wan_ip and pkt.haslayer(PPPoE) == True:
                    self.wan_ping_reply_ok = True
                    s = pkt.summary()
                    print s
                    
    def stop_callback(self,pkt):
        if self.wan_ping_request_ok and  self.wan_ping_reply_ok:
            return True
        return False
    
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '_wan.pcap'
        wrpcap(pcapfilename,pkts)

def ping_test_wan_side_ok(router_wan_ip,pppoe_server_ip):
    p = pingsniifWan(router_wan_ip,pppoe_server_ip)
    p.run()
    if p.wan_ping_request_ok == False:
        raise RuntimeError('wan ping request fail')
    if p.wan_ping_reply_ok == False:
        raise RuntimeError('wan ping reply fail')

class reconPakCheck:
    def __init__(self,timeout=80):
        self.timeout = timeout
        self.PADT  = False
        self.reconOk = False
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            if pppoed.code == 0xa7:            #PADT
                self.PADT = True
            if pppoed.code == 9 and self.PADT == True:
                self.reconOk = True
    
    def stop_callback(self,pkt):
        return self.reconOk
    
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)
        
def reconCheck():
    p = reconPakCheck()
    p.run()
    if p.reconOk == False:
        raise RuntimeError('recon check fail')

class PPP_LCP(Packet):
    name = "PPP LCP"
    fields_desc = [ByteEnumField('code',None,{0x09:'echo-request',0x0a:'echo-raply',0x05:'termination request'}),
                   XByteField('id',None),
                   ShortField('len',None),
                   StrLenField('magic','',length_from=lambda pkt:pkt.len)]

bind_layers(PPP,PPP_LCP,proto=0xc021)

class lcpIntervalCheck:
    
    def __init__(self,timeout=60):
        self.timeout = timeout
        self.pre_time = 0
        self.src = self.get_pppoe_server_iface_mac()
        self.lcp_count = 0
        self.lcp_req_interval_total = 0
        self.lcp_req_interval_time = 0
    
    def get_pppoe_server_iface_mac(self):
        router_lan_ip = get_var('${remote_lib_ip}')
        ans,unans = arping(router_lan_ip)
        for pair in ans:
            return pair[1].hwsrc
        
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPP_LCP):
            ether = pkt.getlayer(Ether)
            lcp = pkt.getlayer(PPP_LCP)
            t  = pkt.time
            if ether.src != self.src and lcp.code == 9:
                self.lcp_count = self.lcp_count + 1
                if self.pre_time == 0:
                    self.pre_time = t
                else:
                    self.lcp_req_interval_total = self.lcp_req_interval_total+ (t - self.pre_time)
                    self.pre_time = t
                    interval_count = self.lcp_count - 1
                    self.lcp_req_interval_time = int(round(self.lcp_req_interval_total/interval_count))
                    print self.lcp_req_interval_time
   
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=None,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def IntervalCheck():
    p = lcpIntervalCheck()
    p.run()
    if p.lcp_req_interval_time != 6:
        line = 'lcp interval time ' + str(p.lcp_req_interval_time)+'!=6'
        raise RuntimeError(line)

class faulCheck:
    
    def __init__(self,timeout=80):
        self.lcp_req_count = 0
        self.lcp_term_req_count = 0
        self.pre_time = 0
        self.pre_time1 = 0
        self.lcp_req_interval_total = 0
        self.lcp_req_interval_time = 0
        self.lcp_term_req_interval_time = 0
        self.timeout = timeout
        self.bsendPADT = False
        
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPP_LCP):
            lcp = pkt.getlayer(PPP_LCP)
            t = pkt.time
            if lcp.code == 9:
                self.lcp_req_count = self.lcp_req_count + 1
                if self.pre_time == 0:
                    self.pre_time = t
                else:
                    self.lcp_req_interval_total = self.lcp_req_interval_total+ (t - self.pre_time)
                    self.pre_time = t
                    interval_count = self.lcp_req_count - 1
                    self.lcp_req_interval_time = int(round(self.lcp_req_interval_total/interval_count))
            
            if lcp.code == 5:
                self.lcp_term_req_count = self.lcp_term_req_count + 1
                if self.lcp_term_req_count == 1:
                    self.pre_time1 = t
                else:
                    self.lcp_term_req_interval_time = int(round(t  - self.pre_time1))
                    
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            if pppoed.code == 0xa7:            #PADT
                self.bsendPADT = True
    
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=None,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def link_faul_lcp_check():
    p = faulCheck()
    p.run()
    print 'lcp_req_count:%d' %(p.lcp_req_count)
    print 'lcp_term_req_count:%d' %(p.lcp_term_req_count)
    print 'lcp_req_interval_time:%d' %(p.lcp_req_interval_time)
    print 'lcp_term_req_interval_time:%d' %(p.lcp_term_req_interval_time)
    if p.lcp_req_count != 10:
        line = 'lcp req count '+str(p.lcp_req_count)+'!=10'
        raise RuntimeError(line)
    
    if p.lcp_term_req_count != 2:
        line = 'PADT count '+str(p.lcp_term_req_count)+'!=2'
        raise RuntimeError(line)
    
    if p.lcp_req_interval_time != 6:
        line = 'LCP Interval time '+str(p.lcp_term_req_count)+'!=6'
        raise RuntimeError(line)
    
    if p.lcp_term_req_interval_time != 3:
        line = 'PADT Interval time '+str(p.lcp_term_req_interval_time)+'!=3'
        raise RuntimeError(line)
    
    if p.bsendPADT == False:
        raise RuntimeError('Not PADT')

class padiCheck:
    
    def __init__(self,timeout=80):
        self.pre_time = 0
        self.interval_5 = False
        self.interval_10 = False
        self.interval_20 = False
        self.timeout = timeout 
    
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            t = pkt.time
            if pppoed.code == 9:
                if self.pre_time == 0:
                    self.pre_time = t
                else:
                    interval = t - self.pre_time
                    print 'interval time:%d' %(interval)
                    self.pre_time = t
                    if int(round(interval)) == 5:
                        self.interval_5 = True
                    if int(round(interval)) == 10:
                        self.interval_10 = True
                    if int(round(interval)) == 20:
                        self.interval_20 = True
    def run(self):
        i = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=None,iface=i)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def padi_check():
    p = padiCheck()
    p.run()
    if p.interval_5 == False or p.interval_10 == False or p.interval_20 == False:
        raise RuntimeError('PADI Interval Time Error')


class PADTCheck:
    def __init__(self,timeout=30):
        self.timeout = timeout
        self.sessionId = 0
        self.pppoe_server_iface_mac = self.get_pppoe_server_iface_mac()
        self.PADT1 = False
        self.PADT2 = False
        self.host_wan_iface_name = None
        self.flag = True
        
    def get_pppoe_server_iface_mac(self):
        pppoe_server_iface_ip = get_var('${remote_lib_ip}')
        ans,unans = arping(pppoe_server_iface_ip)
        for pair in ans:
            return pair[1].hwsrc
        
        
    def sendPADTToRouterWan(self,router_wan_mac):
        global hostUiq
        global acCookie
        pppoed = PPPoED()
        pppoed.version = 1
        pppoed.type = 1
        pppoed.code = 0xa7
        pppoed.sessionid = self.sessionId
        pppoed.len = 17
        tag = PPPoETag()
        tag.tag_type = 0x0103
        tag.tag_value = hostUiq
        tag1 = PPPoETag()
        tag1.tag_type = 0x0104
        tag1.tag_value = acCookie
        e = Ether()
        e.src = self.pppoe_server_iface_mac
        e.dst = router_wan_mac
        pak = e/pppoed/tag/tag1
        sendp(pak,count=1,iface=self.host_wan_iface_name)
         
        
    def sniff_callback(self,pkt):
        if pkt.haslayer(PPPoE):
            pppoe = pkt.getlayer(PPPoE)
            e = pkt.getlayer(Ether)
            self.sessionId = pppoe.sessionid
            if e.src != self.pppoe_server_iface_mac and self.flag == True:
                self.router_wan_mac = e.src
                self.sendPADTToRouterWan(e.src)
                self.flag = False
            
        if pkt.haslayer(PPPoED):
            pppoed = pkt.getlayer(PPPoED)
            ether = pkt.getlayer(Ether)
            if pppoed.code == 0xa7 and ether.src == self.pppoe_server_iface_mac and  pppoed.sessionid == self.sessionId:
                self.PADT1 = True
                
            if pppoed.code == 0xa7 and ether.src == self.router_wan_mac and  pppoed.sessionid == self.sessionId:
                self.PADT2 = True
    
    def stop_callback(self,pkt):
        if self.PADT1 and self.PADT2:
            return True
        return False
    
    def run(self):
        self.host_wan_iface_name = get_host_wan_iface_name()
        pkts = sniff(store=1,prn=self.sniff_callback,timeout=self.timeout,stop_filter=self.stop_callback,iface=self.host_wan_iface_name)
        casename = get_var('${TEST NAME}')
        pcapfilename = pppoe_pcap_dir+casename + '.pcap'
        wrpcap(pcapfilename,pkts)

def PADT_check():
    p = PADTCheck()
    p.run()
    if p.PADT1==False or p.PADT2 == False:
        raise RuntimeError('PADT Check Fail')
    
if __name__ == '__main__':
    pass