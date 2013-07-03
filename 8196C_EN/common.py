'''
Created on 2013-6-13

@author: hany
'''
from robot.libraries import  BuiltIn


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

        
if __name__ == '__main__':
    pass
