'''
Created on 2013-3-18

@author: hany
'''
from scapy.all import *
import wmi
import sys
reload(sys)
sys.setdefaultencoding('GBK')

class dhcpServerTestLib:
    def __init__(self,host_lan_ip,router_lan_ip):
        self.router_lan_ip = router_lan_ip
        self.host_lan_ip = host_lan_ip
        self.host_lan_mac = self.get_host_iface_mac(host_lan_ip)
        self.host_lan_iface = self.get_host_iface_name(host_lan_ip)
        self.router_lan_mac = self.get_router_iface_mac(router_lan_ip)
        
        self.client_ip = None
        self.client_mac = "de:8e:3f:06:7f:fc"
        self.client_raw_mac = "\xde\x8e\x3f\x06\x7f\xfc"
        self.client_name = "netcore-846db97"
        
        self.client_mac2 = "25:d6:15:29:c8:99"
        self.client_raw_mac2 = '\x25\xd6\x15\x29\xc8\x99'
        self.client_name2 = "netcore-846db98"
        self.client_ip2 = None 
    
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
    
    def get_router_iface_mac(self, ip):
        ans, unans = arping(ip)
        for pair in ans:
            if pair[1].hwsrc == None:
                raise RuntimeError('arp router wan mac error')
            else:
                return pair[1].hwsrc
    
    def dhcp_release_ip(self,release_ip):
        dis_opt = [("message-type", "release"),
                    ("server_id", self.router_lan_ip),
                    ("client_id",'\x01\xde\x8e\x3f\x06\x7f\xfc'),
                   "end"]
        sendp(Ether(src=self.client_mac,dst=self.router_lan_mac)
              / IP(src=release_ip,dst=self.router_lan_ip)
              / UDP(sport=68, dport=67)
              / BOOTP(xid=2,ciaddr=release_ip,chaddr=self.client_raw_mac) 
             / DHCP(options=dis_opt), iface=self.host_lan_iface)
    
    def dhcp_release2(self):
        dis_opt = [("message-type", "release"),
                    ("server_id", self.router_lan_ip),
                    ("client_id",'\x01\x25\xd6\x15\x29\xc8\x99'),
                   "end"]
        sendp(Ether(src=self.client_mac2,dst=self.router_lan_mac)
              / IP(src=self.client_ip2,dst=self.router_lan_ip)
              / UDP(sport=68, dport=67)
              / BOOTP(xid=2,ciaddr=self.client_ip2,chaddr=self.client_raw_mac2) 
             / DHCP(options=dis_opt), iface=self.host_lan_iface)
                    
    def dhcp_release(self):
        dis_opt = [("message-type", "release"),
                    ("server_id", self.router_lan_ip),
                    ("client_id",'\x01\xde\x8e\x3f\x06\x7f\xfc'),
                   "end"]
        sendp(Ether(src=self.client_mac,dst=self.router_lan_mac)
              / IP(src=self.client_ip,dst=self.router_lan_ip)
              / UDP(sport=68, dport=67)
              / BOOTP(xid=2,ciaddr=self.client_ip,chaddr=self.client_raw_mac) 
             / DHCP(options=dis_opt), iface=self.host_lan_iface)
    
    def dhcp_decline(self):
        dis_opt = [("message-type", "decline"),
                    ("requested_addr",self.client_ip),
                    ("server_id", self.router_lan_ip),
                    ("client_id",'\x01\xde\x8e\x3f\x06\x7f\xfc'),
                   "end"]
        sendp(Ether(src=self.client_mac,dst=self.router_lan_mac)
              / IP(src='0.0.0.0',dst='255.255.255.255')
              / UDP(sport=68, dport=67)
              / BOOTP(ciaddr='0.0.0.0',chaddr=self.client_raw_mac) 
             / DHCP(options=dis_opt), iface=self.host_lan_iface)
        
    def start_dhcp_client2(self,req_ip):
        conf.checkIPaddr = False
        dis_opt = [("message-type", "discover"),
                    ("hostname",self.client_name2),
                   "end"]
        
        if req_ip != None:
            dis_opt.insert(1, ("requested_addr", req_ip))
            
        ans, unans = srp(Ether(src=self.client_mac2, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac2)
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response offer')
        bootp = None
        for p in ans:
            bootp = p[1].getlayer(BOOTP)
            self.client_ip2 = bootp.yiaddr
            break
        dis_opt = [("message-type", "request"),
                   ("requested_addr", bootp.yiaddr),
                   ("hostname",self.client_name2),
                   ("server_id", self.router_lan_ip),
                   "end"]

        ans, unans = srp(Ether(src=self.client_mac2, dst='ff:ff:ff:ff:ff:ff')
                        / IP(src='0.0.0.0', dst='255.255.255.255')
                        / UDP(sport=68, dport=67)
                        / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac2)
                        / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response ACK')
        
    def start_dhcp_client(self,req_ip):
        conf.checkIPaddr = False
        dis_opt = [("message-type", "discover"),
                    ("hostname",self.client_name),
                   "end"]
        
        if req_ip != None:
            dis_opt.insert(1, ("requested_addr", req_ip))
            
        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac)
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response offer')
        bootp = None
        for p in ans:
            bootp = p[1].getlayer(BOOTP)
            self.client_ip = bootp.yiaddr
            break
        dis_opt = [("message-type", "request"),
                   ("requested_addr", bootp.yiaddr),
                   ("hostname",self.client_name),
                   ("server_id", self.router_lan_ip),
                   "end"]

        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                        / IP(src='0.0.0.0', dst='255.255.255.255')
                        / UDP(sport=68, dport=67)
                        / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac)
                        / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response ACK')
    
    def dhcp_magic_num_test(self):
        conf.checkIPaddr = False
        dis_opt = [("message-type", "discover"),
                    ("hostname",self.client_name)]
        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac,options='\x00\x00\x00\x00')
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response offer')
        bootp = None
        for p in ans:
            bootp = p[1].getlayer(BOOTP)
            self.client_ip = bootp.yiaddr
        print self.client_ip
        dis_opt = [("message-type", "request"),
                   ("requested_addr", bootp.yiaddr),
                   ("hostname",self.client_name),
                   ("server_id", self.router_lan_ip),
                   "end"]

        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                        / IP(src='0.0.0.0', dst='255.255.255.255')
                        / UDP(sport=68, dport=67)
                        / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac,options='\x00\x00\x00\x00')
                        / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response ACK')
        
    def no_end_option_should_not_reply_dhcp_offer(self):
        conf.checkIPaddr = False
        dis_opt = [("message-type", "discover"),
                    ("hostname",self.client_name)]
        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac)
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=2, retry=3)
        if len(ans) != 0:
            for a in ans:
                dhcp = a[1].getlayer(DHCP)
                for opt in dhcp.options:
                    if opt == 'end':
                        break
                    if opt[0] == 'message-type' and opt[1] == 2:
                        raise RuntimeError('dhcp response the dhcp offer')
                        break
            
    def send_too_long_discovery_dhcp_server_should_not_reply_offer(self):
        conf.checkIPaddr = False
        dis_opt = []
        dis_opt.append(('message-type', 1))
        dis_opt.append(('server_id', self.router_lan_ip))
        dis_opt.append(('time_server', '0.0.0.0'))
        dis_opt.append(('IEN_name_server', '0.0.0.0'))
        dis_opt.append(('log_server', '0.0.0.0'))
        dis_opt.append(('cookie_server', '0.0.0.0'))
        dis_opt.append(('lpr_server', '0.0.0.0'))
        dis_opt.append(('NIS_server', '0.0.0.0'))
        dis_opt.append(('NTP_server', '0.0.0.0'))
        dis_opt.append(('NetBIOS_server', '0.0.0.0'))
        dis_opt.append(('NetBIOS_dist_server', '0.0.0.0'))
        for i in range(100):
            dis_opt.append(('requested_addr', '0.0.0.0'))
        dis_opt.append('end')
        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac)
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=5, retry=2)
            
        if len(ans) != 0:
            for a in ans:
                dhcp = a[1].getlayer(DHCP)
                for opt in dhcp.options:
                    if opt == 'end':
                        break
                    if opt[0] == 'message-type' and opt[1] == 2:
                        raise RuntimeError('dhcp response the dhcp offer')
                        break
        
        
        
    def send_dhcp_discovery_zero_len_dhcp_server_should_not_reply_offer(self):
        conf.checkIPaddr = False
        dis_opt = []
        ans, unans = srp(Ether(src=self.client_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr='0.0.0.0', chaddr=self.client_raw_mac)
                      / DHCP(options=dis_opt), iface=self.host_lan_iface, timeout=5, retry=2)
            
        if len(ans) != 0:
            for a in ans:
                dhcp = a[1].getlayer(DHCP)
                for opt in dhcp.options:
                    if opt == 'end':
                        break
                    if opt[0] == 'message-type' and opt[1] == 2:
                        raise RuntimeError('dhcp response the dhcp offer')
                        break
        
       
        
    def host_get_ip_should_be_right(self,dhcp_start_ip,dhcp_end_ip):
        self.start_dhcp_client(None)
        start = socket.ntohl(struct.unpack("I", socket.inet_aton(str(dhcp_start_ip)))[0])
        end = socket.ntohl(struct.unpack("I", socket.inet_aton(str(dhcp_end_ip)))[0])
        print self.client_ip
        ip = socket.ntohl(struct.unpack("I", socket.inet_aton(str(self.client_ip)))[0])
        if ip < start or ip > end:
            raise RuntimeError('dhcp offer ip not in the rang')
        
    def host_get_spefic_ip(self,spe_ip):
        self.start_dhcp_client(spe_ip)
        print self.client_ip
        if self.client_ip != spe_ip:
            raise RuntimeError('dhcp not offer the specific ip')
        
    def get_dhcp_client_ip(self):
        return self.client_ip
    
    def get_dhcp_client_ip2(self):
        return self.client_ip2
    
    def get_dhcp_client_mac(self):
        return self.client_mac
    
    def get_dhcp_client_name(self):
        return self.client_name
    
    def del_host_lan_addr(self,ip):
        c = wmi.WMI ()
        for nic in c.Win32_NetworkAdapter ():
            if nic.NetConnectionID != None and nic.MACAddress != None:
                if nic.MACAddress.upper() == self.host_lan_mac.upper():
                    cmd = 'netsh interface IP delete address '+nic.NetConnectionID+ \
                    ' '+ip
                    subprocess.call(cmd)
                    break
        
    def add_host_lan_addr(self,ip,mask):
        c = wmi.WMI ()
        for nic in c.Win32_NetworkAdapter ():
            if nic.NetConnectionID != None and nic.MACAddress != None:
                if nic.MACAddress.upper() == self.host_lan_mac.upper():
                    cmd = 'netsh interface IP add address '+nic.NetConnectionID+ \
                    ' '+ip+' '+mask
                    subprocess.call(cmd)
                    break
    
    def get_list(self):
        a = ['a','b','c']
        return a
if __name__ == '__main__':
    p = dhcpServerTestLib('192.168.1.25','192.168.1.1')
    p.start_dhcp_client(None)
