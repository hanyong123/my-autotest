# coding=utf-8
'''
Created on 2013-6-13

@author: hany
'''
from robot.libraries import  BuiltIn
import threading
import time
import subprocess 


def process_special_charators(string):
    if string != None:
        if string.find('\'')!= -1:
            return string.replace('\'','!')
        elif string.find('\\')!= -1:
            return string.replace('\\','!')
        else:
            return string
    else:
        return None
   

def string_lower(string):
    return string.lower()

def remove_leading_space(string):
    return string.strip()

def get_autoit_run_result():
    f = open('autoit_status','r')
    s = f.read()
    f.close()
    return s.strip()

def set_host_if_dhcp(if_name):
    cmd = 'netsh interface ip set address name="'+if_name+'" source=dhcp'
    subprocess.call(cmd,shell=True)
    time.sleep(5)
    

def set_host_if_static(if_name,ip,mask,gateway):
    cmd = 'netsh interface ip set address name="'+if_name+'" source=static addr=' + \
        ip+' mask='+mask+' gateway='+gateway+' gwmetric=1'
    subprocess.call(cmd,shell=True)
    time.sleep(5)
    
if __name__ == '__main__':
    pass
  
