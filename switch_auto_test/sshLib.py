'''
Created on 2013 11 18 

@author: nicole
'''
import pexpect
import time

class sshSession:
    def __init__(self):
         self.name = None
         self.handle = None

class sshLib:
    def __init__(self):
        self.sessionList = []
        self.curSession = None
        self.index = 0

    def open_ssh_session(self,ip,user,passwd=None,cmd=None,name=None):
        ip = ip.encode('ascii')
        user = user.encode('ascii')
        if passwd != None:
            passwd = passwd.encode('ascii')
        s = sshSession()
        self.index = self.index + 1
        self.curSession = pexpect.spawn(('ssh %s@%s')%(user,str(ip)))
        time.sleep(10)
        if name==None :
           s.name = str(self.index)
        else:
           s.name = name   
        s.handle = self.curSession
        self.sessionList.append(s)
        r=''
        i = -1
        i = self.curSession.expect([" password:","continue connecting (yes/no)?"])
        if i==0:
            r = self.curSession.sendline(passwd)
            print r
            time.sleep(1)
            x = self.curSession.expect(["Permission denied, please try again.","Press RETURN to get started."])
            if x == 0:
               return "Permission denied, please try again."
            elif x ==1:
               return "Press RETURN to get started."
            else:
               return "Error1"
        elif i == 1:
            self.curSession.sendline('yes')
            x = self.curSession.expect(["Press RETURN to get started."," password:"])
            if x == 0:
                 return "Press RETURN to get started."
            elif x == 1:
                 r = self.curSession.sendline(passwd)
                 y=-1
                 y = self.curSession.expect("Press RETURN to get started.")
                 if y == 0:
                    return "Press RETURN to get started."
                 else:
                    return "Error2" 
            else:
                 return "Error3"
        else:
            r = self.curSession.read()
            self.curSession.expect(pexpect.EOF)
            self.curSession.close()
        return r

    def close_ssh_session(self):
        self.curSession.close()
    
    def execute_ssh_command(self,cmd):
        self.curSession.sendline(cmd)
        return self.curSession.before

    def switch_session(self,name):
        for s in self.sessionList:
            if s.name == str(name):
                self.curSession = s.handle

    def anysnc_execute_ssh_command(self,cmd):
        self.curSession.sendline(cmd)
    
    def ssh_key_generate(self,t,b=None,keydir=None,passwd=None):
        t = t.encode('ascii')
        if b == None:
            session = pexpect.spawn(('ssh-keygen -t %s')%t)
        else:
            session = pexpect.spawn(('ssh-keygen -b %s -t %s')%(b,t))
        time.sleep(2)
        print "1"
        session.expect("Enter file in which to save the key")
        print "2"
        session.sendline('\n')
        print "3"
        if passwd == None:        
            session.sendline('\n')
            session.sendline('\n')
        else:
            session.sendline(pwd)
            session.sendline(pwd)
        session.close()
          

if __name__ == '__main__':
    print 'hello'
    l = sshLib()
    #l.open_ssh_session('192.168.2.11','netcore','test')
