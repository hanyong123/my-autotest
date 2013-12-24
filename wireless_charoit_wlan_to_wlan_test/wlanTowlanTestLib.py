# coding=gbk
'''
Created on 2013-1-15

@author: hany
'''
import wmi
import time
import os
import subprocess
from lxml import *
import lxml.html as HTML 
from xlutils.copy import copy
from xlutils.save import save
import xlrd

    
class wlanTowlanTestLib:
   
    def __init__(self,wlan_host1_ip,wlan_host2_ip,wire_iface_name):
        self.XMLProfileFile = 'tmp.xml'
        self.wlan_host1_ip = wlan_host1_ip
        self.wlan_host2_ip = wlan_host2_ip
        self.wire_iface_name = wire_iface_name
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
    
    def enableWireInterface(self,enable=True):
        c = wmi.WMI ()
        for nic in c.Win32_NetworkAdapter ():
            if nic.NetConnectionID == self.wire_iface_name:
                if enable:
                    cmdline = "devcon.exe /r enable " +'@'+nic.PNPDeviceID
                else:
                    cmdline = "devcon.exe /r disable " +'@'+nic.PNPDeviceID
                subprocess.call(cmdline)
                break
    
    def waitWireIfaceConnected(self,timeout=300):
        for i in range(timeout):
            status = self.getWireIfaceStatus()
            if status == 2:
                time.sleep(10)
                break
            else:
                time.sleep(1)
        if status != 2:
            raise RuntimeError('waitWireIfaceConnected timeout')
    
    def  getWireIfaceStatus(self):
        c = wmi.WMI ()
        for nic in c.Win32_NetworkAdapter ():
            if nic.NetConnectionID == self.wire_iface_name:
                return nic.NetConnectionStatus
    
    def pingWait(self):
        c = wmi.WMI ()
        bSuc = True
        for j in range(12):
            for i in range(5):
                pings = c.Win32_PingStatus(Address = self.wlan_host2_ip)
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
        self.enableWireInterface(False)
        self.ssid = ssid
        self.WriteXMLProfile(ssid,key,security,encriType,authType,wpa_key_mode)
        cmdline = 'wcm.exe sp '+ self.guid +' '+self.XMLProfileFile
        subprocess.check_output(cmdline,shell=True)
        self.reStartWirelessService()
        self.waitWirelessConnect()
    
    def executChariotTest(self,type=1,t=60):
        f = open('tmp.lst','w')
        line = ''
        if type == 1:
            line = '1 '+self.wlan_host1_ip+' '+self.wlan_host2_ip+'\n'
            f.write(line)
            line = '1 '+self.wlan_host1_ip+' '+self.wlan_host2_ip+'\n'
            f.write(line)
            line = '1 '+self.wlan_host1_ip+' '+self.wlan_host2_ip+'\n'
            f.write(line)
        else:
            line = '1 '+self.wlan_host2_ip+' '+self.wlan_host1_ip+'\n'
            f.write(line)
            line = '1 '+self.wlan_host2_ip+' '+self.wlan_host1_ip+'\n'
            f.write(line)
            line = '1 '+self.wlan_host2_ip+' '+self.wlan_host1_ip+'\n'
            f.write(line)
        f.close()
        cmdline = 'clonetst test.tst tmp.lst test.tst'
        subprocess.check_output(cmdline,shell=True)
        cmdline = 'runtst test.tst -t ' + str(t)
        subprocess.check_call(cmdline)        
        if os.path.exists(self.chariot_result_dir) == False:
            os.mkdir(self.chariot_result_dir)
        self.output_filename = self.chariot_result_dir + '\\result.html'
        cmdline = 'fmttst test.tst '+self.output_filename+' -h -c -q'
        print cmdline
        subprocess.check_output(cmdline,shell=True)
        root = HTML.parse(self.output_filename)
        self.averge_throughput = root.xpath("//table[6]/tr[2]/td[2]/text()")[0]
        self. mininum_throughput = root.xpath("//table[6]/tr[2]/td[3]/text()")[0]
        self.maxnum_throughput = root.xpath("//table[6]/tr[2]/td[4]/text()")[0]
        print 'averge throughput ' + self.averge_throughput
        print 'mininum throughpu ' + self. mininum_throughput
        print 'maxnum throughput ' + self.maxnum_throughput
    
    def clean(self):
        cmdline = 'wcm.exe dp '+ self.guid +' '+ self.ssid
        subprocess.call(cmdline,shell=True)
        self.enableWireInterface(True)
        self.waitWireIfaceConnected()
    
    def getAvergeThroughput(self):
        return self.averge_throughput
    
    def getMininumThroughput(self):
        return self. mininum_throughput
    
    def getMaxnumThroughput(self):
        return self.maxnum_throughput
    
    def writeToExcel(self,r,c):
        wrb=xlrd.open_workbook('SDK性能验收.xls',formatting_info=True)
        wb=copy(wrb)
        ws=wb.get_sheet(4)
        r = int(r)
        c = int(c)
        ws.write(r,c,self.averge_throughput)
        wb.save('SDK性能验收.xls')
    
    def get_wl_basic_set_body(self,wl_enable,net_mode,wl_stand,wl_mac,ssid,ssid_broad,channel_width,channel_bind,channel):
        body = 'mode_name=netcore_set&wl_enable='+wl_enable+'&net_mode='+net_mode+'&wl_stand='+wl_stand+'&wl_mac='+wl_mac\
        +'&ssid='+ssid+'&ssid_broad='+ssid_broad+'&channel_width='+channel_width+'&channel_bind='+channel_bind+'&channel='+\
        channel+'&save=save'
        return body

    def get_wl_sec_set_body(self,sec_mode,key_size,key_mode_wep,key_wep,key_type,key_mode_wpa,key_wpa,key_time):
        body = None
        if sec_mode == '0':
            body = 'mode_name=netcore_set&sec_mode=0&save=save'
        elif sec_mode == '1':
            body = 'mode_name=netcore_set&sec_mode=1&key_size='+key_size+'&key_mode_wep='+key_mode_wep+'&key_wep='+key_wep+'&save=save'
        else:
            body = 'mode_name=netcore_set&sec_mode='+sec_mode+'&key_type='+key_type+'&key_mode_wpa='+key_mode_wpa+'&key_wpa='+key_wpa+\
            '&key_time='+key_time+'&save=save'
        return body
    
    def get_wl_advance_set_body(self,beacon,rts,fragment,rate_mode,shortGi,protection,preamble,wlan_partition,out_power,wmm):
        body = 'mode_name=netcore_set&beacon='+beacon+'&rts='+rts+'&fragment='+fragment
        body = body +'&rate_mode='+rate_mode+'&shortGi='+shortGi+'&protection='+protection
        body = body + '&preamble='+preamble+'&wlan_partition='+wlan_partition+'&out_power='+out_power+'&wmm='+wmm
        body = body + '&save=save'
        return body
       
   