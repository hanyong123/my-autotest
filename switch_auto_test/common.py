'''
Created on 2013 8 28 

@author: hany
'''
from scapy.all import *

p = None

def pkt_construct(s):
    global p
    p = eval(s)
    
def execut_scapy_command(s):
    r =  eval(s)
    return r

    
if __name__ == '__main__':
    pass