'''
Created on 2013 9 3

@author: hany

robotframework scapy library
'''
import pexpect
import time

class scapySession:
    def __init__(self):
        self.name = None
        self.handle = None

class scapyLibary:
    def __init__(self):
        self.curSession = None
        self.session_list = []
        self.index = 0
    
    def open_scapy_session(self,name=None):
        self.index = self.index + 1
        self.curSession = pexpect.spawn('scapy')
        time.sleep(2)
        self.curSession.expect('>>>')
        s = scapySession()
        if name == None:
            s.name = str(self.index)
        else:
            s.name = name
        s.handle = self.curSession
        self.session_list.append(s)
    
    def ansysnc_excute_scapy_conmmand(self,cmd):
	self.curSession.sendline(cmd)

    def excute_scapy_conmmand(self,cmd):
        self.curSession.sendline(cmd)
        self.curSession.expect('>>>')
        return self.curSession.before
    
    
    def switch_session(self,name):
        for s in self.session_list:
            if s.name == str(name):
                self.curSession = s.handle
                break
    
    def send_ctrl_c(self):
        self.curSession.sendcontrol('c')
        self.curSession.expect('>>>')
        return self.curSession.before
    
    def close_scapy_session(self):
        self.curSession.close()
        
                        
if __name__ == '__main__':
    l = scapyLibary()
    l.open_scapy_session()
    s = l.excute_scapy_conmmand("p = IP(src='192.168.1.3',dst='192.168.1.1')/ICMP()/'aaaaaaaaaaaaaaaaaaaaaa'")
    print s
    s = l.excute_scapy_conmmand('send(p)')
    print s
