'''
Created on 2013-4-3

@author: hany
'''
from robot.parsing import TestCaseFile
import pickle
from robot.libraries import  BuiltIn
import time
import sys


class common:
    def __init__(self):
        self.goto_case = self.load_goto_table('gotocase')
        self.goto_page = self.load_goto_table('gotopage')
    
    def load_goto_table(self,name):
        pk_file = open(name, 'rb')
        data1 = pickle.load(pk_file)
        return data1
    
    def goto_test_case_page(self):
        case = BuiltIn.BuiltIn().get_variable_value('${TEST NAME}')
        act = self.goto_case[case]
        for a in act:
            BuiltIn.BuiltIn().run_keyword(a.keyword,*a.params[0:])
            time.sleep(2)
    
    def goto_spec_page(self,page):
        act = self.goto_page[page]
        if act == None:
            raise RuntimeError('no exist the '+page+' page')
        for a in act:
            BuiltIn.BuiltIn().run_keyword(a.keyword,*a.params[0:])
            time.sleep(2)
             
if __name__ == '__main__':
    pass