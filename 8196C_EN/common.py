'''
Created on 2013-6-13

@author: hany
'''
from robot.libraries import  BuiltIn
import threading
import time

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

def async_open_browser(url,browser):
    class browserThread(threading.Thread):
        def __init__(self,url,browser):
            threading.Thread.__init__(self)            
            self.url = url
            self.browser = browser

        def run(self):
             BuiltIn.BuiltIn().run_keyword('Open Browser',self.url,self.browser)
             time.sleep(10)

    pt = browserThread(url,browser)
    pt.start()

if __name__ == '__main__':
    pass
