'''
Created on 2013-6-13

@author: hany
'''

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
   
        
        
if __name__ == '__main__':
    pass