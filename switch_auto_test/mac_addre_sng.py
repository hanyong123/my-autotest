'''
Created on 2013year8moth28day

@author: hany
'''
from scapy.all import *
import sys

def pkt_construct(s):
    p = eval(s)
    sys.stdout = sys.__stdout__
    p.show()
    
if __name__ == '__main__':
    pkt_construct('Ether()')