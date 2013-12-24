'''
Created on 2013-1-14

@author: hany
'''
import subprocess
import time
import wmi
import sys

class remoteWlconLib:
    
    def __init__(self,remote_wlan_host_ip):
        self.remote_wlan_host_ip = remote_wlan_host_ip
        self.XMLProfileFile = 'tmp.xml'
        self.guid = self.getWirelessInterfaceGUID()
    
    def WriteXMLProfile(self,ssid,key,security,encriType,authType,key_mode):
        f = open(self.XMLProfileFile,'w')
        f.write('<?xml version="1.0"?>\n')
        f.write('<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n')
        line = '<name>'+ssid+'</name>\n'
        f.write(line)
        f.write('<SSIDConfig>\n')
        f.write('    <SSID>\n')
        line = '        <name>'+ssid+'</name>\n'
        f.write(line)
        f.write('    </SSID>\n')
        f.write('</SSIDConfig>\n')
        f.write('<connectionType>ESS</connectionType>\n')
        f.write('<connectionMode>auto</connectionMode>\n')
        f.write('<autoSwitch>false</autoSwitch>\n')
        f.write('<MSM>\n')
        f.write('    <security>\n')
        f.write('        <authEncryption>\n')
        auth = ''
        encry = ''
        if security.lower() == 'none':
            auth = 'open'
            encry = 'none'
        else:
            if security.lower() == 'wep':
                encry = security.upper()
                auth = authType.lower()
            else:
                auth = security.upper()
                encry = encriType.upper()
        line = '            <authentication>'+auth+'</authentication>\n'
        f.write(line)
        line = '            <encryption>'+encry+'</encryption>\n'
        f.write(line)
        f.write('            <useOneX>false</useOneX>\n')
        f.write('        </authEncryption>\n')
        if security.lower() != 'none':
            f.write('        <sharedKey>\n')
            line = ''
            if encry == 'WEP':
                line = '            <keyType>networkKey</keyType>\n'
            else:
                if key_mode == 'hex':
                    line = '            <keyType>networkKey</keyType>\n'
                else:
                    line = '            <keyType>passPhrase</keyType>\n'
            f.write(line)
            f.write('            <protected>false</protected>\n')
            line = '            <keyMaterial>'+key+'</keyMaterial>\n'
            f.write(line)
            f.write('        </sharedKey>\n')
        f.write('    </security>\n')
        f.write('</MSM>\n')
        f.write('</WLANProfile>\n')
        f.close()
    
    def getWirelessInterfaceGUID(self):
        cmdline = 'wcm ei'
        restr = subprocess.check_output(cmdline,shell=True)
        i = restr.find('GUID: ')
        i = i + len('GUID: ')
        j = restr.find('\n',i)
        j = j - 1
        str = restr[i:j]
        return str
    
    def pingWait(self):
        c = wmi.WMI ()
        bSuc = True
        for j in range(12):
            for i in range(5):
                pings = c.Win32_PingStatus(Address = self.remote_wlan_host_ip)
                for ping in pings:
                    if ping.StatusCode != 0:
                        bSuc = False
                time.sleep(1)
            if bSuc == True:
                    return True
            else:
                    bSuc = True
        return  False
                    
    def getWirelessIfaceStaus(self):
        cmdline = 'wcm qi '+self.guid
        restr = subprocess.check_output(cmdline,shell=True)
        i = restr.find('Interface state: ')
        i = i + len('Interface state: ')
        j = restr.find('\n',i)
        j  = j -1
        return restr[i:j]
             
    def waitWirelessConnect(self,timeout=60):
        status = None
        for i in range(timeout):
            status = self.getWirelessIfaceStaus()
            if status != 'disconnected':
                break
            else:
                time.sleep(1)
                              
        if status == 'disconnected':
            self.reStartWirelessService()
            for i in range(timeout):
                status = self.getWirelessIfaceStaus()
                if status != 'disconnected':
                    break
                else:
                    time.sleep(1)
            if status == 'disconnected':
                raise RuntimeError('wireless connect fail')
        if self.pingWait() == False:
            raise RuntimeError('wireless connect fail')
        
    
    def reStartWirelessService(self):
        cmdline = 'net stop WZCSVC'
        subprocess.check_output(cmdline,shell=True)
        cmdline = 'net start WZCSVC'
        subprocess.check_output(cmdline,shell=True)
    
    def wirelessConnect(self,ssid,key,security,encriType,authType,wpa_key_mode='asc'):
        self.WriteXMLProfile(ssid,key,security,encriType,authType,wpa_key_mode)
        cmdline = 'wcm.exe sp '+ self.guid +' '+self.XMLProfileFile
        subprocess.check_output(cmdline,shell=True)
        self.reStartWirelessService()
        self.waitWirelessConnect()
       
    def wirelessDisconnect(self,ssid):
        cmdline = 'wcm.exe dp '+ self.guid +' '+ ssid
        subprocess.call(cmdline,shell=True)
        
        
if __name__ == '__main__':
    from robotremoteserver import RobotRemoteServer
    RobotRemoteServer(remoteWlconLib(sys.argv[3]), *sys.argv[1:])