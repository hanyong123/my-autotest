'''
Created on 2013 11  4

@author: zhaohy
'''
from scapy.all import *
import time
import sys
import platform
import subprocess

	
def send_l2_pkt(p, iface='eth1', timeout=3):
	conf.checkIPaddr = 0
	ans = srp1(p, iface=iface, timeout=int(timeout))
	#ans = srp1(p, iface=iface)
	print "return pkt"
	print ans
	return ans

def pkt_dhcp_discover():
	p = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")\
	/UDP(sport=68, dport=67)/BOOTP(xid=int("1111"),chaddr=mac2str("00:11:22:33:44:55"))/DHCP(options=\
	[("message-type", str("discover")), ("client_id", "\x01\x00\x11\x22\x33\x44\x55")\
	, ("param_req_list", "\x01\x03\x06\x0c\x0f\x1c\x21\x28\x29\x2a\x2c\xf9\x79"), "end"])
	return p

def pkt_dhcp_request(alloced_ip, server_id):
	print "alloced_ip is: %s"  % alloced_ip
	#print "server_id is :" + server_id
	p = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")\
	/UDP(sport=68, dport=67)/BOOTP(xid=int("1111"),chaddr=mac2str("00:11:22:33:44:55"))/DHCP(options=\
	[("message-type", str("request")), ("client_id", "\x01\x00\x11\x22\x33\x44\x55")\
	, ("requested_addr", alloced_ip),  ("server_id", server_id), ("param_req_list"\
	, "\x01\x03\x06\x0c\x0f\x1c\x21\x28\x29\x2a\x2c\xf9\x79"), "end"])
	return p

def resolve_dhcp_offer(p):
	if not p is None:
		if p.haslayer(DHCP):
			dhcp = p.getlayer(DHCP)
			bootp = p.getlayer(BOOTP)
			cli_ip_by_ser = bootp.yiaddr
			for key in dhcp.options:
				if key[0] == 'server_id':
					return (cli_ip_by_ser, key[1])
	else:
		return (None, None)
def resolve_dhcp_ack(p):
	if not p is None:
		if p.haslayer(DHCP):
			dhcp = p.getlayer(DHCP)
			bootp = p.getlayer(BOOTP)
			cli_ip_by_ser = bootp.yiaddr
			for key in dhcp.options:
				if key[0] == 'message-type' and key[1] == 5:
					return 0
		else:
			return -1
	else:
		return -1


if __name__ == '__main__':
	p = pkt_dhcp_discover();
	#ans = srp1(p, iface="eth3", timeout =3)
	ans = send_l2_pkt(p, iface="eth2", timeout =4)
	cli_ip_by_ser, server_ip = resolve_dhcp_offer(ans)
	print cli_ip_by_ser
	print server_ip
	if ((cli_ip_by_ser != None) and (server_ip != None)):
		p = pkt_dhcp_request(cli_ip_by_ser, server_ip)
		#ans = srp1(p, iface="eth3", timeout =3)
		ans = send_l2_pkt(p, iface="eth3", timeout =3)
		re = resolve_dhcp_ack(ans)
		print re
