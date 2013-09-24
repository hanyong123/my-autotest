'''
Created on 2013 8 28 

@author: hany
'''
from scapy.all import *
import time
import sys
import platform
import subprocess

def execut_scapy_command(s):
    r =  eval(s)
    return r

def get_mac_by_iface(iface_name):
    iface_name = iface_name.encode('ascii')
    sysstr = platform.system()
    if sysstr == 'Windows':
        dev = ifaces.data[iface_name]
        return str(dev.mac)
    if sysstr == 'Linux':
        t = get_if_raw_hwaddr(iface_name)
        s = str2mac(t[1])
        return s

def get_order_mac(count):
    a = []
    while count > 0:
        space = 6 - len(str(count))
        suffix = '0'*space+str(count)
        mac = '00:00:00:'+suffix[0:2]+':'+suffix[2:4]+':'+suffix[4:6]
        a.insert(0,mac)
        count = count - 1
    return a
    
def get_rand_mac(count):
    a = []
    count = int(count)
    while count > 0:
        mac = str(RandMAC())
        mac = '00:00:00'+ mac[8:]
        if mac not in a:
            a.append(mac)
            count = count - 1
    return a
        
    
def get_mac_table_entry(send_if,recv_if,mon_if,test_num):
    send_if = send_if.encode('ascii')
    recv_if = recv_if.encode('ascii')
    mon_if = mon_if.encode('ascii')
    m  = get_order_mac(test_num)
    t = get_if_raw_hwaddr(recv_if)
    s = str2mac(t[1])
    pkts = []
    for mac in m:
        p = Ether(src=mac,dst=s)/IP()/ICMP()/'aaaaaaaaaaaaaaaaaaaaaaa'
        pkts.append(p)
    sendpfast(pkts,pps=500,iface=send_if)
    pkts = []
    for mac in m:
        p = Ether(src=s,dst=mac)/IP()/ICMP()/'aaaaaaaaaaaaaaaaaaaaaaa'
        pkts.append(p)
    f = 'ether src '+s+' and icmp'
    p = subprocess.Popen(['tshark','-i',mon_if,'-f',f,'-w','1.pcap'])
    time.sleep(5)
    sendpfast(pkts,pps=500,iface=recv_if)
    time.sleep(5)
    p.kill()
    a = rdpcap('1.pcap')
    os.remove('1.pcap')
    return test_num-len(a.res)

def get_mac_table_max_entry(send_if,recv_if,mon_if):
    st = 15000
    n2 = 0
    n1 = get_mac_table_entry(send_if,recv_if,mon_if,st)
    print n1
    while True:
        st = st+5000
        n2 = get_mac_table_entry(send_if,recv_if,mon_if,st)
        print n2
        if n1 == n2:
            return str(n1 + 4)
        else:
            n1 = n2
def test_learn_rate(send_if,recv_if,mon_if,rate,learn_num):
    send_if = send_if.encode('ascii')
    recv_if = recv_if.encode('ascii')
    mon_if = mon_if.encode('ascii')
    m  = get_order_mac(learn_num)
    t = get_if_raw_hwaddr(recv_if)
    s = str2mac(t[1])
    pkts = []
    for mac in m:
        p = Ether(src=mac,dst=s)/IP()/ICMP()/'aaaaaaaaaaaaaaaaaaaaaaa'
        pkts.append(p)
    sendpfast(pkts,pps=rate,iface=send_if)
    pkts = []
    for mac in m:
        p = Ether(src=s,dst=mac)/IP()/ICMP()/'aaaaaaaaaaaaaaaaaaaaaaa'
        pkts.append(p)
    f = 'ether src '+s+' and icmp'
    p = subprocess.Popen(['tshark','-i',mon_if,'-f',f,'-w','1.pcap'])
    time.sleep(5)
    sendpfast(pkts,pps=500,iface=recv_if)
    time.sleep(5)
    p.kill()
    a = rdpcap('1.pcap')
    os.remove('1.pcap')
    if len(a.res) == 0:
        print 'sdsdsda'
        return True
    else:
        return False

def get_learn_rate(send_if,recv_if,mon_if,learn_num):
    learn_num = int(learn_num.encode('ascii'))
    rate = 100
    test_learn_rate(send_if,recv_if,mon_if,rate,learn_num)
    return str(rate)


if __name__ == '__main__':
    a = get_mac_table_max_entry('eth3','eth2','eth4')
    print a
