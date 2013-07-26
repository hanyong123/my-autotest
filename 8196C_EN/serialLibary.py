'''
Created on 2013-7-23

@author: hany
'''

import serial


class serialLibary:
    def __init__(self):
        self.ser = None
    
    def open_connection(self,port='COM3',baud=38400,time_out=1):
        self.ser = serial.Serial(port, baud, timeout=time_out)
        self.ser.write('\n')
        self.ser.readlines()
        
    def execute_command(self,cmd):
        cmdline = cmd + '\n'
        self.ser.write(cmdline)
        self.ser.flush()
        s = self.ser.readlines()
        output = ''
        if s != None:
            for a in s[1:-1]:
                output = output + a.strip()
        return output
    
    def close_connection(self):
        self.ser.close()
            
if __name__ == '__main__':
    sl = serialLibary()
    sl.open_connection()
    s = sl.execute_command('flash')
    print s
    s = sl.execute_command('hany')
    print s
    sl.close_connection()
