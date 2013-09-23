'''
Created on 2013 8 28 

@author: hany
'''
from scapy.all import *
import threading
import time
import sys
import platform
from multiprocessing import Process,Queue,Value

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
        
    
class sniffThread(Process):
    
    def __init__(self,filter,iface,timeout=60,count=None):
        Process.__init__(self)
        self.rule = filter
        self.iface = iface
        self.timeout = timeout
        self.count = count
        self.p = None
        self.done = Value('d',0.0)
        self.sniff_count = Value('d',0.0)
        self.bstop = False
        self.q = Queue(1)
    
    def stop(self):
        return self.bstop
    
    def set_stop(self):
        self.bstop = True
        
    def run(self):
        if self.count == None and self.timeout == None:
            self.p = sniff(filter=self.rule,iface=self.iface,stopperTimeout=5,stopper=self.stop)   
        else:
            self.p = sniff(filter=self.rule,iface=self.iface,timeout=self.timeout,count=self.count)
        self.done.value = 1
        #if self.p != None:
        sys.stdout = sys.__stdout__
        print self.p
        self.sniff_count.value = len(self.p.res)


def start_sniff_thread(filter,iface,timeout=60,count=1):
    filter = filter.encode('ascii')
    iface = iface.encode('ascii')
    global sniff_thread
    if count == None and timeout == None:
        sniff_thread = sniffThread(filter,iface,timeout,count)
    else:
        sniff_thread = sniffThread(filter,iface,int(timeout),int(count))
    sniff_thread.start()
    return sniff_thread

def should_sniff_pkt(t):
    sniff_thread = t
    while sniff_thread.done.value == 0:
        time.sleep(1)
    time.sleep(3)
    print sniff_thread.sniff_count.value
    if sniff_thread.sniff_count.value == 0:
        raise RuntimeError('no sniff pkt')
    

def should_not_sniff_pkt(t):
    sniff_thread = t
    while sniff_thread.done.value == 0:
        time.sleep(1)
    time.sleep(3)
    print sniff_thread.sniff_count.value    
    if sniff_thread.sniff_count.value != 0:
        raise RuntimeError('sniff pkt')

def get_mac_table_entry(send_if,recv_if,mon_if,test_num):
    send_if = send_if.encode('ascii')
    recv_if = recv_if.encode('ascii')
    mon_if = mon_if.encode('ascii')
    m  = get_order_mac(test_num)
    print '1'
    t = get_if_raw_hwaddr(recv_if)
    print '2'
    print str(t)
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
    ts = start_sniff_thread(f,mon_if,None,None)
    sendpfast(pkts,pps=500,iface=recv_if)
    ts.set_stop()
    while ts.done == False:
        time.sleep(1)
    print ts.sniff_count
    return test_num-ts.sniff_count

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
            return n1 + 4
        else:
            n1 = n2
        
if __name__ == '__main__':
    a = get_mac_table_max_entry('eth3','eth2','eth4')
    print a
