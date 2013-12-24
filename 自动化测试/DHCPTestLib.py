'''
Created on 2013-2-21

@author: hany
'''
from scapy.all import *
import socket
import struct
import threading
from robot.libraries import  BuiltIn
import time

dhcp_pcap_dir = 'dhcp_pcap/'

def get_var(var_name):
    m = BuiltIn.BuiltIn()
    return m.get_variable_value(var_name)

class DHCPTestLib:
    
    def __init__(self, host_lan_ip, host_wan_ip, router_lan_ip):
        self.host_lan_ip = host_lan_ip
        self.host_wan_ip = host_wan_ip
        self.router_lan_ip = router_lan_ip
        #self.host_lan_mac = self.get_host_iface_mac(host_lan_ip)
        #self.host_wan_mac = self.get_host_iface_mac(host_wan_ip)
        #self.router_lan_mac = self.get_router_iface_mac(router_lan_ip)
        self.dhcp_release_sniff_thread = None
        self.dhcp_con_sniff_thread = None
        self.pt = None
     
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
    
    def dhcp_wan_ip_should_in_ip_pool(self, start_ip, end_ip, ip):
        if ip == '0.0.0.0':
            raise RuntimeError('the wan ip not in dhcp range')
        start = socket.ntohl(struct.unpack("I", socket.inet_aton(str(start_ip)))[0])
        end = socket.ntohl(struct.unpack("I", socket.inet_aton(str(end_ip)))[0])
        ip = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip)))[0])
        if ip < start and ip > end:
            raise RuntimeError('the wan ip not in dhcp range')
        
    def ping_wan_side_host_should_get_reply(self, remote_host_ip):
        p = Ether(src=self.host_lan_mac, dst=self.router_lan_mac) / IP(src=self.host_lan_ip, dst=remote_host_ip) / ICMP()
        send_iface_name = self.get_host_iface_name(self.host_lan_ip)
        ans, unans = srp(p, iface=send_iface_name, timeout=10, retry=5)
        if len(ans) == 0:
            raise RuntimeError('ping no recv reply!!!')
    
    def start_dhcp_release_sniff_thread(self):
        class dhcpReleaseSniff(threading.Thread):
            
            def __init__(self, host_wan_iface, timeout=80):
                threading.Thread.__init__(self)
                self.host_wan_iface = host_wan_iface
                self.dhcp_release_ok = False
                self.timeout = timeout
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k, v in dhcp.options:
                        if k == 'message-type' and v == 7:
                            self.dhcp_release_ok = True
                            break
            
            def stop_callback(self, pkt):
                return self.dhcp_release_ok
                
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        self.dhcp_release_sniff_thread = dhcpReleaseSniff(i, 60)
        self.dhcp_release_sniff_thread.start()
    
    def dhcp_release_should_ok(self):
        is_ok = False
        for i in range(60):
            if self.dhcp_release_sniff_thread.dhcp_release_ok == True:
                is_ok = True
                break
            time.sleep(1)
        if is_ok == False:
            raise RuntimeError('Not Recv DHCP Release')
                 
    def start_dhcp_con_sniff_thread(self, ip):
        class dhcpConSniff(threading.Thread):
            def __init__(self, host_wan_iface, pre_router_wan_ip, timeout=60):
                threading.Thread.__init__(self)
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.dhcp_con_ok = False
                self.dhcp_discovery_ok = False
                self.dhcp_offer_ok = False
                self.dhcp_req_ok = False
                self.dhcp_ack_ok = False
                self.pre_router_wan_ip = pre_router_wan_ip
                self.dhcp_dis_have_pre_ip_ok = False
                self.dhcp_offer_ip_ok = False
                self.dhcp_nak_ok = False
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    btp = pkt.getlayer(BOOTP)
                    for k, v in dhcp.options:
                        if k == 'message-type' and v == 1:
                            for opt in dhcp.options:
                                if opt[0] == 'requested_addr' and opt[1] == self.pre_router_wan_ip:
                                    self.dhcp_dis_have_pre_ip_ok = True
                                    break
                            self.dhcp_discovery_ok = True
                            break;
                        if k == 'message-type' and v == 2:
                            if btp.yiaddr != self.pre_router_wan_ip:
                                self.dhcp_offer_ip_ok = True
                            self.dhcp_offer_ok = True
                            break
                        if k == 'message-type' and v == 3:
                            self.dhcp_req_ok = True
                            break
                        if k == 'message-type' and v == 5:
                            self.dhcp_ack_ok = True
                            break
                        
                        if k == 'message-type' and v == 6:
                            self.dhcp_nak_ok = True
                            break
                            
                    if self.dhcp_discovery_ok and self.dhcp_offer_ok and self.dhcp_req_ok and self.dhcp_ack_ok:
                        self.dhcp_con_ok = True
            
            def stop_callback(self, pkt):
                if self.dhcp_nak_ok == True:
                    return True
                return self.dhcp_con_ok
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        self.dhcp_con_sniff_thread = dhcpConSniff(i, ip)
        self.dhcp_con_sniff_thread.start()
    
    def dhcp_nak_should_ok(self):
        for i in range(60):
            if self.dhcp_con_sniff_thread.dhcp_con_ok == True:
                break
            time.sleep(1)
        
        if self.dhcp_con_sniff_thread.dhcp_dis_have_pre_ip_ok == False:
            raise RuntimeError('dhcp discovery no contain req client ip')
        
        if self.dhcp_con_sniff_thread.dhcp_nak_ok == False:
            raise RuntimeError('dhcp server no send nak')
        
    def dhcp_con_should_ok(self):
        for i in range(60):
            if self.dhcp_con_sniff_thread.dhcp_con_ok == True:
                break
            time.sleep(1)
        if self.dhcp_con_sniff_thread.dhcp_dis_have_pre_ip_ok == False:
            raise RuntimeError('dhcp discovery no contain req client ip')
        if  self.dhcp_con_sniff_thread.dhcp_con_ok == False:
            raise RuntimeError('DHCP Discovery Error')
    
    def dhcp_should_get_other_ip(self):
        for i in range(60):
            if self.dhcp_con_sniff_thread.dhcp_con_ok == True:
                break
            time.sleep(1)
        if self.dhcp_con_sniff_thread.dhcp_dis_have_pre_ip_ok == False:
            raise RuntimeError('dhcp discovery no contain req client ip')
        
        if self.dhcp_con_sniff_thread.dhcp_offer_ip_ok == False:
            raise RuntimeError('DHCP should get other ip')
        
        if  self.dhcp_con_sniff_thread.dhcp_con_ok == False:
            raise RuntimeError('DHCP Discovery Error')
        
        
    def dhcp_magic_test(self):
        class dhcpMagicTestSniff:
            def __init__(self, vm_ip, vm_mac, host_wan_iface, timeout=60):
                self.vm_ip = vm_ip
                self.vm_mac = vm_mac
                self.timeout = timeout
                self.host_wan_iface = host_wan_iface
                self.magicTestOk = False
                        
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    e = pkt.getlayer(Ether)
                    dhcp = pkt.getlayer(DHCP)
                    dis = pkt.getlayer(BOOTP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 3:
                            self.magicTestOk = True
                                
                        if k[0] == 'message-type' and k[1] == 1:
                            ether = Ether(src=self.vm_mac, dst=e.src)
                            ip = IP(src=self.vm_ip, dst='100.0.0.200')
                            udp = UDP(sport=67, dport=68)
                            btp = BOOTP()
                            btp.op = 2
                            btp.htype = 1
                            btp.hlen = 6
                            btp.hops = 0
                            btp.xid = dis.xid
                            btp.secs = 0
                            btp.flags = 0x0000
                            btp.ciaddr = '0.0.0.0'
                            btp.yiaddr = '100.0.0.200'
                            btp.siaddr = self.vm_ip
                            btp.giaddr = '0.0.0.0'
                            btp.chaddr = dis.chaddr
                            btp.options = '\x63\x81\x53\x63'
                            dp = DHCP()
                            opt = []
                            opt.append(('message-type', 2))
                            opt.append(('server_id', self.vm_ip))
                            opt.append(('lease_time', 600))
                            opt.append(('subnet_mask', '255.255.0.0'))
                            opt.append(('router', self.vm_ip))
                            opt.append(('name_server', '8.8.8.8'))
                            opt.append('end')
                            for i in range(26):
                                opt.append('pad')
                            dp.options = opt
                            pak = ether / ip / udp / btp / dp
                            sendp(pak, iface=self.host_wan_iface)
                            break
                      
            def stop_callback(self, pkt):
                return self.magicTestOk
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        p = dhcpMagicTestSniff(self.host_wan_ip, self.host_wan_mac, i, 10)
        p.run()
        if p.magicTestOk == False:
            raise RuntimeError('magic test fail')
    
    def dhcp_request_no_end_opt(self):
        class sniffSend:
            def __init__(self, host_wan_ip, host_wan_mac, host_wan_iface, timeout):
                self.host_wan_iface = host_wan_iface
                self.host_wan_ip = host_wan_ip
                self.host_wan_mac = host_wan_mac
                self.timeout = timeout
                self.stop_sniff = False
                self.resend_dhcp_discovery = False
                self.send_error_dhcp_pak = False
                
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    e = pkt.getlayer(Ether)
                    dhcp = pkt.getlayer(DHCP)
                    dis = pkt.getlayer(BOOTP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                                             
                        if k[0] == 'message-type'  and k[1] == 1:
                            if self.send_error_dhcp_pak == True:
                                self.resend_dhcp_discovery = True
                                self.stop_sniff = True
                                break
                            ether = Ether(src=self.host_wan_mac, dst=e.src)
                            ip = IP(src=self.host_wan_ip, dst='100.0.0.200')
                            udp = UDP(sport=67, dport=68)
                            btp = BOOTP()
                            btp.op = 2
                            btp.htype = 1
                            btp.hlen = 6
                            btp.hops = 0
                            btp.xid = dis.xid
                            btp.secs = 0
                            btp.flags = 0x0000
                            btp.ciaddr = '0.0.0.0'
                            btp.yiaddr = '100.0.0.200'
                            btp.siaddr = self.host_wan_ip
                            btp.giaddr = '0.0.0.0'
                            btp.chaddr = dis.chaddr
                            dp = DHCP()
                            opt = []
                            opt.append(('message-type', 2))
                            opt.append(('server_id', self.host_wan_ip))
                            opt.append(('lease_time', 600))
                            opt.append(('subnet_mask', '255.255.0.0'))
                            opt.append(('router', self.host_wan_ip))
                            opt.append(('name_server', '8.8.8.8'))
                            # opt.append('end')
                            for i in range(27):
                                opt.append('pad')
                            dp.options = opt
                            pak = ether / ip / udp / btp / dp
                            sendp(pak, iface=self.host_wan_iface)
                            self.send_error_dhcp_pak = True
                            break
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)                
        
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffSend(self.host_wan_ip, self.host_wan_mac, i, 10)
        p.run()
        if p.resend_dhcp_discovery == False:
            raise RuntimeError('No Resend DHCP Discovery')
        
    
    def dhcp_pkt_length_too_long_check(self):
        class sniffSend:
            def __init__(self, host_wan_ip, host_wan_mac, host_wan_iface, timeout):
                self.host_wan_iface = host_wan_iface
                self.host_wan_ip = host_wan_ip
                self.host_wan_mac = host_wan_mac
                self.timeout = timeout
                self.stop_sniff = False
                self.dhcp_request_ok = False
                self.dhcp_dis_ok = False
                self.dhcp_send_offer_ok = False
                
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    e = pkt.getlayer(Ether)
                    dhcp = pkt.getlayer(DHCP)
                    dis = pkt.getlayer(BOOTP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 3:
                            self.dhcp_request_ok = True
                            self.stop_sniff = True
                            break
                                   
                        if k[0] == 'message-type'  and k[1] == 1:
                            
                            if self.dhcp_send_offer_ok == True:
                                self.dhcp_dis_ok = True
                                self.stop_sniff = True
                                break
                            ether = Ether(src=self.host_wan_mac, dst=e.src)
                            ip = IP(src=self.host_wan_ip, dst='100.0.0.200')
                            udp = UDP(sport=67, dport=68)
                            btp = BOOTP()
                            btp.op = 2
                            btp.htype = 1
                            btp.hlen = 6
                            btp.hops = 0
                            btp.xid = dis.xid
                            btp.secs = 0
                            btp.flags = 0x0000
                            btp.ciaddr = '0.0.0.0'
                            btp.yiaddr = '100.0.0.200'
                            btp.siaddr = self.host_wan_ip
                            btp.giaddr = '0.0.0.0'
                            btp.chaddr = dis.chaddr
                            dp = DHCP()
                            opt = []
                            opt.append(('message-type', 2))
                            opt.append(('server_id', self.host_wan_ip))
                            opt.append(('lease_time', 600))
                            opt.append(('subnet_mask', '255.255.0.0'))
                            opt.append(('router', self.host_wan_ip))
                            opt.append(('name_server', '8.8.8.8'))
                            
                            opt.append(('time_server', '0.0.0.0'))
                            opt.append(('IEN_name_server', '0.0.0.0'))
                            opt.append(('log_server', '0.0.0.0'))
                            opt.append(('cookie_server', '0.0.0.0'))
                            opt.append(('lpr_server', '0.0.0.0'))
                            opt.append(('NIS_server', '0.0.0.0'))
                            opt.append(('NTP_server', '0.0.0.0'))
                            opt.append(('NetBIOS_server', '0.0.0.0'))
                            opt.append(('NetBIOS_dist_server', '0.0.0.0'))
                            for i in range(100):
                                opt.append(('requested_addr', '0.0.0.0'))
                            opt.append('end')
                            for i in range(26):
                                opt.append('pad')
                            dp.options = opt
                            pak = ether / ip / udp / btp / dp
                            sendp(pak, iface=self.host_wan_iface)
                            self.dhcp_send_offer_ok = True
                            break
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)                
        
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffSend(self.host_wan_ip, self.host_wan_mac, i, 10)
        p.run()
        if p.dhcp_request_ok == True:
            raise RuntimeError('router reponse DHCP request')
        if p.dhcp_dis_ok == False and p.dhcp_request_ok == False:
            raise RuntimeError('router no send dhcp discovery')
    
    def dhcp_options_len_zero_test(self):
        class sniffSend:
            def __init__(self, host_wan_ip, host_wan_mac, host_wan_iface, timeout):
                self.host_wan_iface = host_wan_iface
                self.host_wan_ip = host_wan_ip
                self.host_wan_mac = host_wan_mac
                self.timeout = timeout
                self.stop_sniff = False
                self.dhcp_request_ok = False
                self.dhcp_dis_ok = False
                self.dhcp_send_offer_ok = False
                
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    e = pkt.getlayer(Ether)
                    dhcp = pkt.getlayer(DHCP)
                    dis = pkt.getlayer(BOOTP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 3:
                            self.dhcp_request_ok = True
                            self.stop_sniff = True
                            break
                                   
                        if k[0] == 'message-type'  and k[1] == 1:
                            
                            if self.dhcp_send_offer_ok == True:
                                self.dhcp_dis_ok = True
                                self.stop_sniff = True
                                break
                            ether = Ether(src=self.host_wan_mac, dst=e.src)
                            ip = IP(src=self.host_wan_ip, dst='100.0.0.200')
                            udp = UDP(sport=67, dport=68)
                            btp = BOOTP()
                            btp.op = 2
                            btp.htype = 1
                            btp.hlen = 6
                            btp.hops = 0
                            btp.xid = dis.xid
                            btp.secs = 0
                            btp.flags = 0x0000
                            btp.ciaddr = '0.0.0.0'
                            btp.yiaddr = '100.0.0.200'
                            btp.siaddr = self.host_wan_ip
                            btp.giaddr = '0.0.0.0'
                            btp.chaddr = dis.chaddr
                            dp = DHCP()
                            opt = []
                            dp.options = opt
                            pak = ether / ip / udp / btp / dp
                            sendp(pak, iface=self.host_wan_iface)
                            self.dhcp_send_offer_ok = True
                            break
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)                
        
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffSend(self.host_wan_ip, self.host_wan_mac, i, 10)
        p.run()
        if p.dhcp_request_ok == True:
            raise RuntimeError('router reponse DHCP request')
        if p.dhcp_dis_ok == False and p.dhcp_request_ok == False:
            raise RuntimeError('router no send dhcp discovery')
    
    
    def start_dhcp_discovery_interval_check_thread(self):
        class sniffkk(threading.Thread):
            def __init__(self, host_wan_iface, timeout=100):
                threading.Thread.__init__(self)
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.pre_time = 0
                self.interval_3_ok = False
                self.interval_3_2_ok = False
                self.interval_60_ok = False
                self.stop_sniff = False
            
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    t = pkt.time
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 1:
                            if self.pre_time == 0:
                                self.pre_time = t
                            else:
                                interval = t - self.pre_time
                                self.pre_time = t
                                print str(int(round(interval)))
                                if int(round(interval)) == 3 and self.interval_3_ok == False:
                                    self.interval_3_ok = True
                                elif int(round(interval)) == 3 and self.interval_3_ok == True:
                                    self.interval_3_2_ok = True
                                elif int(round(interval)) == 60:
                                    self.interval_60_ok = True
                            
                            if self.interval_3_ok and self.interval_3_2_ok and self.interval_60_ok:
                                self.stop_sniff = True
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)                     
                            
        i = self.get_host_iface_name(self.host_wan_ip)
        self.pt = sniffkk(i)
        self.pt.start()
        
        
    def dhcp_discovery_interval(self):
        for i in range(120):
            time.sleep(1)
    
        if self.pt.interval_3_ok == False:
            raise RuntimeError('no interval 3')
        
        if self.pt.interval_3_2_ok == False:
            raise RuntimeError('no interval 3')
        
        if self.pt.interval_60_ok == False:
            raise RuntimeError('no interval 60')
            
    def start_dhcp_request_interval_check_thread(self):
        class sniffkk(threading.Thread):
            def __init__(self, host_wan_iface, timeout=120):
                threading.Thread.__init__(self)
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.pre_time = 0
                self.req_interval_time_ok = None
                self.ack_ok = False
                self.stop_sniff = False
            
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        if k[0] == 'message-type' and k[1] == 3:
                            if self.pre_time == 0:
                                self.pre_time = pkt.time
                            else:
                                request_interval_time = pkt.time - self.pre_time
                                self.pre_time = pkt.time
                                print int(round(request_interval_time))
                                if int(round(request_interval_time)) == 30:
                                    self.req_interval_time_ok = True
                                else:
                                    self.req_interval_time_ok = False
                        
                        if k[0] == 'message-type' and k[1] == 5:
                            self.ack_ok = True
                  
                if self.req_interval_time_ok != None and self.ack_ok == True:
                    self.stop_sniff = True                   
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        
        i = self.get_host_iface_name(self.host_wan_ip)
        self.pt = sniffkk(i)
        self.pt.start()
    
    def dhcp_req_interval_time_test(self):
        for i in range(120):
            if self.pt.stop_sniff == True:
                break
            time.sleep(1)
        
        if self.pt.req_interval_time_ok == False:
            raise RuntimeError('dhcp req interval time no 30s')
        
        if self.pt.ack_ok == False:
            raise RuntimeError('the dhcp server no send ack')
    
    def dhcp_con_test(self):
        class sniffCon:
            def __init__(self, host_wan_iface, timeout=60):
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.dhcp_con_ok = False
                self.dhcp_discovery_ok = False
                self.dhcp_offer_ok = False
                self.dhcp_req_ok = False
                self.dhcp_ack_ok = False
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k, v in dhcp.options:
                        if k == 'message-type' and v == 1:
                            self.dhcp_discovery_ok = True
                            break;
                        if k == 'message-type' and v == 2:
                            self.dhcp_offer_ok = True
                            break
                        if k == 'message-type' and v == 3:
                            self.dhcp_req_ok = True
                            break
                        if k == 'message-type' and v == 5:
                            self.dhcp_ack_ok = True
                            break
                    if self.dhcp_discovery_ok and self.dhcp_offer_ok and self.dhcp_req_ok and self.dhcp_ack_ok:
                        self.dhcp_con_ok = True
            
            def stop_callback(self, pkt):
                return self.dhcp_con_ok
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '_01.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffCon(i)
        p.run()
        if p.dhcp_con_ok == False:
            raise  RuntimeError('dhcp con fail')
    
    def start_fault_sniff_thread(self):
        class sniffkk(threading.Thread):
            def __init__(self, host_wan_iface, timeout=60):
                threading.Thread.__init__(self)
                self.timeout = timeout
                self.dhcp_req_count = 0
                self.host_wan_iface = host_wan_iface
                self.stop_sniff = False
                
            
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        if k[0] == 'message-type' and k[1] == 3:
                            self.dhcp_req_count = self.dhcp_req_count + 1
                            break
                       
                                
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '_02.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        self.pt = sniffkk(i)
        self.pt.start()
    
    def should_have_multi_dhcp_req(self):
        self.pt.stop_sniff = True
        time.sleep(5)
        print self.pt.dhcp_req_count
        if self.pt.dhcp_req_count <= 1:
            raise RuntimeError('no multi dhcp req')                              
    
    def dhcp_server_should_response_ack(self):
        class sniffkk:
            def __init__(self, host_wan_iface, timeout=60):
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.dhcp_ack_ok = False
            
            def stop_callback(self, pkt):
                return self.dhcp_ack_ok 
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        if k[0] == 'message-type' and k[1] == 5:
                            self.dhcp_ack_ok = True
                            break
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '_03.pcap'
                wrpcap(pcapfilename, pkts)
                
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffkk(i)
        p.run()
        if p.dhcp_ack_ok == False:
            raise  RuntimeError('dhcp no response ack')
    
    def dhcp_ip_timeout_test(self):
        class sniffkk:
            def __init__(self, host_wan_iface, timeout=120):
                self.host_wan_iface = host_wan_iface
                self.timeout = timeout
                self.dhcp_req_count = 0
                self.dhcp_discovery_count = 0
                self.pre_time = 0
                self.interval_10_recv_3_dis_ok = False
                self.stop_sniff = False
                
            
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 3:
                            self.dhcp_req_count = self.dhcp_req_count + 1
                            break
                        
                        if k[0] == 'message-type' and k[1] == 1:
                            if self.pre_time == 0:
                                self.pre_time = pkt.time
                            self.dhcp_discovery_count = self.dhcp_discovery_count + 1
                            if self.dhcp_discovery_count == 3:
                                self.stop_sniff = True
                                interval = pkt.time - self.pre_time
                                if interval <= 10:
                                    self.interval_10_recv_3_dis_ok = True
                            break
                  
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=None, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '_02.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffkk(i)
        p.run()
        if p.dhcp_req_count <= 1:
            raise  RuntimeError('no multi dhcp req')
        
        print p.dhcp_discovery_count
        if p.dhcp_discovery_count != 3:
            raise  RuntimeError('no recv 3 discovery count')
        
        if p.interval_10_recv_3_dis_ok == False:
            raise  RuntimeError('recv 3 discovery within 10s')                 
                
    
    def ping_wan_mac_check_should_ok(self, wan_ip, mac):
        i = self.get_host_iface_name(self.host_wan_ip)
        ans, unans = srp(Ether() / IP(src=self.host_wan_ip, dst=wan_ip) / ICMP(), iface=i, timeout=5)
        if len(ans) == 0:
            raise RuntimeError('no ping reply')
        
        mac_src = ans[0][1].src
        print mac_src
        mac_src = mac_src.replace(':', '-')
        mac_src = mac_src.upper()
        mac = mac.upper()
        if mac_src != mac:
            raise RuntimeError('mac clone fail')
    
    def ping_router_wan_get_mtu(self, router_wan_ip, length=2000):
        class mtuSniif:
            def __init__(self, host_wan_iface_name, host_wan_ip, router_wan_ip, timeout=120):
                self.timeout = timeout
                self.host_wan_iface_name = host_wan_iface_name
                self.host_wan_ip = host_wan_ip
                self.router_wan_ip = router_wan_ip
                self.mtu = 0
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(IP):
                    ip = pkt.getlayer(IP)
                    if ip.proto == 1 and ip.src == self.router_wan_ip and ip.dst == self.host_wan_ip and ip.frag == 0:
                        self.mtu = len(ip)
            
            def stop_callback(self, pkt):
                if self.mtu != 0:
                    return True
                return False
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface_name)
                casename = 'mtu_check_sniff'
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        i = self.get_host_iface_name(self.host_wan_ip)
        line = 'ping ' + router_wan_ip + ' -l ' + str(length) + ' -n 20'
        print line
        pro = subprocess.Popen(line, shell=True)
        p = mtuSniif(i, self.host_wan_ip, router_wan_ip)
        p.run()
        print str(p.mtu)
        pro.terminate()
        if p.mtu == 0:
            raise RuntimeError('No Ping Reply')
        return str(p.mtu)
    
    def re_host_lan_mac(self):
        lan_mac = self.host_lan_mac.replace(':', '-')
        lan_mac = lan_mac.upper()
        return lan_mac
    
    def send_dhcp_nak(self):
        class sniffkk:
            def __init__(self, host_wan_iface, host_wan_ip, host_wan_mac, timeout=120):
                self.host_wan_iface = host_wan_iface
                self.host_wan_ip = host_wan_ip
                self.host_wan_mac = host_wan_mac
                self.timeout = timeout
                self.stop_sniff = False
            
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    e = pkt.getlayer(Ether)
                    btp = pkt.getlayer(BOOTP)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if k[0] == 'message-type' and k[1] == 1:
                            opt = [("message-type", "nak"), "end"]
                            print btp.chaddr
                            sendp(Ether(src=self.host_wan_mac, dst=e.src)
                                  / IP(src=self.host_wan_ip, dst='0.0.0.0')
                                  / UDP(sport=67, dport=68)
                                  / BOOTP(chaddr=btp.chaddr, xid=btp.xid)
                                  / DHCP(options=opt), iface=self.host_wan_iface)
                            self.stop_sniff = True
                            break
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        
        i = self.get_host_iface_name(self.host_wan_ip)
        p = sniffkk(i, self.host_wan_ip, self.host_wan_mac)
        p.run()
        if p.stop_sniff == False:
            raise RuntimeError('send dhcp nak fail')
    
    def start_dhcp_client(self, req_ip):            
        conf.checkIPaddr = False
        i = self.get_host_iface_name(self.host_wan_ip)
        fam, hw = get_if_raw_hwaddr(i)
        dis_opt = [("message-type", "discover"), "end"]
        ans, unans = srp(Ether(src=self.host_wan_mac, dst='ff:ff:ff:ff:ff:ff')
                      / IP(src='0.0.0.0', dst='255.255.255.255')
                      / UDP(sport=68, dport=67)
                      / BOOTP(ciaddr=req_ip, chaddr=hw)
                      / DHCP(options=dis_opt), iface=i, timeout=2, retry=3)
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response offer')
        
        dis_opt = [("message-type", "request"),
                   ("requested_addr", req_ip),
                   ("server_id", self.host_wan_ip),
                   "end"]
        ans, unans = srp(Ether(src=self.host_wan_mac, dst='ff:ff:ff:ff:ff:ff')
                        / IP(src='0.0.0.0', dst='255.255.255.255')
                        / UDP(sport=68, dport=67)
                        / BOOTP(ciaddr=req_ip, chaddr=hw)
                        / DHCP(options=dis_opt), iface=i, timeout=2, retry=3)
        
        if len(ans) == 0:
            raise RuntimeError('DHCP Server No Response ACK')
    
    def start_dhcp_decline_sniff_thread(self, pre_ip):
        class sniffkk(threading.Thread):
            def __init__(self, host_wan_iface, pre_ip, timeout=120):
                threading.Thread.__init__(self)
                self.host_wan_iface = host_wan_iface
                self.router_wan_mac = None
                self.timeout = timeout
                self.pre_router_wan_ip = pre_ip
                self.dhcp_dis_have_pre_ip_ok = False
                self.dhcp_discovery_ok = False
                self.dhcp_offer_ip_ok = False
                self.dhcp_offer_ok = False
                self.dhcp_req_ok = False
                self.dhcp_ack_ok = False
                self.dhcp_con_ok = False
                self.dhcp_decline_ok = False
                self.stop_sniff = False
                self.router_send_arp_ok = False
                
            def stop_callback(self, pkt):
                return self.stop_sniff
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(ARP):
                    e = pkt.getlayer(Ether)
                    arp = pkt.getlayer(ARP)
                    if e.src == self.router_wan_mac and \
                    arp.op == 1 and \
                    arp.pdst == self.pre_router_wan_ip and \
                    self.dhcp_decline_ok == False: 
                        self.router_send_arp_ok = True
                if pkt.haslayer(DHCP):
                    dhcp = pkt.getlayer(DHCP)
                    btp = pkt.getlayer(BOOTP)
                    e = pkt.getlayer(Ether)
                    for k in dhcp.options:
                        if k == 'end':
                            break
                        
                        if  k[0] == 'message-type' and k[1] == 1:
                            self.router_wan_mac = e.src
                            if self.pre_router_wan_ip == btp.ciaddr:
                                self.dhcp_dis_have_pre_ip_ok = True
                            self.dhcp_discovery_ok = True
                            break
                        
                        if  k[0] == 'message-type' and k[1] == 2:
                            if self.pre_router_wan_ip == btp.yiaddr:
                                self.dhcp_offer_ip_ok = True
                            self.dhcp_offer_ok = True
                            break
                        
                        if k[0] == 'message-type' and k[1] == 3:
                            self.dhcp_req_ok = True
                            break
                        
                        if k[0] == 'message-type' and k[1] == 5:
                            self.dhcp_ack_ok = True
                            break
                        
                        if k[0] == 'message-type' and k[1] == 4:
                            self.dhcp_decline_ok = True
                            break
                    if self.dhcp_discovery_ok and self.dhcp_offer_ok and self.dhcp_req_ok and self.dhcp_ack_ok:
                        self.dhcp_con_ok = True
                    
                    if self.dhcp_con_ok and self.dhcp_decline_ok:
                        self.stop_sniff = True
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        
        i = self.get_host_iface_name(self.host_wan_ip)
        self.pt = sniffkk(i, pre_ip)
        self.pt.start()
        
    
    def dhcp_decline_test_should_ok(self):
        for i in range(60):
            if self.pt.stop_sniff:
                break
            time.sleep(1)
        
        self.pt.stop_sniff = True
        if self.pt.dhcp_con_ok == False:
            raise RuntimeError('DHCP con fail')
        
        if self.pt.router_send_arp_ok == False:
            raise RuntimeError('router wan no send arp')
        
        if self.pt.dhcp_decline_ok == False:
            raise RuntimeError('dhcp no recv dhcp decline')
        
        if self.pt.dhcp_dis_have_pre_ip_ok == False:
            raise RuntimeError('dhcp discovery no contain req client ip')
        
    def nslookup(self, url):
        cmd = 'ping ' + url
        subprocess.Popen(cmd, shell=True)
                      
    def dns_test(self, dns1, dns2, router_wan_ip, url):
        class DNSTest:
            def __init__(self, host_wan_iface, dns1, dns2, router_wan_ip, url, timeout=80):
                self.dns1 = dns1
                self.dns2 = dns2
                self.timeout = timeout
                self.bSuccess = False
                self.bdns1 = False
                self.bdns2 = False
                self.host_wan_iface = host_wan_iface
                self.url = url
                self.router_wan_ip = router_wan_ip
            
            def sniff_callback(self, pkt):
                if pkt.haslayer(DNS):
                    dns = pkt.getlayer(DNS)
                    dnsq = pkt.getlayer(DNSQR)
                    if dns.qr == 0 and dnsq.qname == self.url + '.':
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
                            
                                
            def stop_callback(self, pkt):
                return self.bSuccess
            
            def run(self):
                pkts = sniff(store=1, prn=self.sniff_callback, timeout=self.timeout, stop_filter=self.stop_callback, iface=self.host_wan_iface)
                casename = get_var('${TEST NAME}')
                pcapfilename = dhcp_pcap_dir + casename + '.pcap'
                wrpcap(pcapfilename, pkts)
        
        i = self.get_host_iface_name(self.host_wan_ip)
        p = DNSTest(i, dns1, dns2, router_wan_ip, url)
        p.run()
        if p.bSuccess == False:
            raise RuntimeError('dns test fail')
            
if __name__ == '__main__':
    pass
