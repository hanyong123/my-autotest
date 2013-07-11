'''
Created on 2013-1-11

@author: hany
'''

from wirelessChariotTestLib import  wirelessChariotTest



class wirelessTestlib:
    def __init__(self,remote_host_ip1,remote_host_ip2,local_host_wire_iface_name,wirelessIp):
        self.wt = wirelessChariotTest(remote_host_ip1,remote_host_ip2,local_host_wire_iface_name,wirelessIp)

    def wirelessConnect(self,ssid,key,security,encriType,authType,wpa_key_mode='asc'):
        self.wt.wirelessConnect(ssid, key, security, encriType, authType,wpa_key_mode)
    
    def executChariotTest(self,type=1,t=60):
        self.wt.executChariotTest(type,t)
    
    def getAvergeThroughput(self):
        self.wt.getAvergeThroughput()
    
    def getMininumThroughput(self):
        self.wt.getMininumThroughput()
    
    def getMaxnumThroughput(self):
        self.wt.getMaxnumThroughput()
        
    def writeToExcel(self,r,c):
        self.wt.writeToExcel(r, c)

    def clean(self):
        self.wt.clean()
        
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




