'''
Created on 2013-6-26

@author: hany
'''
import argparse
import os
import subprocess
import re
import codecs

def parse_config_file(filename):
    f = open(filename,'r')
    config = {}
    for line in f.readlines():
        if line[0] == '$':
            k = re.split('\s+',line)
            config[k[0]] = k[1]
    f.close()
    return config

if __name__ == '__main__':
    bowser = 'firefox'
    login_user = 'guest'
    login_passwd = 'guest'
    language = 'us'
    gateway = '192.168.1.1'
    testCasesFile = 'cases.txt'
    currnt_dir = os.getcwd()
    test_file_dir = currnt_dir+'\\'+'8196C_EN'
    out_put_dir = currnt_dir+'\\'+'report'
    parser = argparse.ArgumentParser(description='autotest from command line.')
    parser.add_argument('-f','--testCasesFile', help='contain test cases name file',required=False)
    parser.add_argument('-u','--user',help='router login user', required=False)
    parser.add_argument('-p','--passwd',help='router login password', required=False)
    parser.add_argument('-g','--gateway',help='router gateway', required=False)
    parser.add_argument('-b','--browser',help='auto test with browser', required=False)
    parser.add_argument('-l','--language',help='router web language', required=False)
    parser.add_argument('-o','--outputdir',help='report dir path', required=False)
    args = parser.parse_args()
    if args.testCasesFile != None:
        testCasesFile = args.testCasesFile
    if args.user != None:
        login_user = args.user
    if args.passwd != None:
        login_passwd = args.passwd
    if args.gateway != None:
        gateway = args.gateway
    if args.language != None:
        language = args.language
    if args.browser != None:
        bowser = args.browser
    if args.outputdir != None:
        out_put_dir = args.outputdir
    argfile_name = currnt_dir+'\\'+'argfile.txt'
    argfile = codecs.open(argfile_name,'w','utf-8')
    argfile.write('--outputdir\n')
    line = out_put_dir +'\n'
    argfile.write(line)
    argfile.write('--monitorcolors\n')
    argfile.write('on\n')
    argfile.write('--monitorwidth\n')
    argfile.write('118\n')
    cases = codecs.open(testCasesFile,'r','utf-8')
    for l in cases.readlines():
        argfile.write('--test\n')
        line = u'8196C EN.'+l
        argfile.write(line)
    cases.close()
    argfile.close()
    config_file_path = test_file_dir+'\\'+'config.txt'
    config = parse_config_file(config_file_path)
    config['${browser}'] = bowser
    config['${router_lan_ip}'] = gateway
    config['${login_user}'] = login_user
    config['${login_passwd}'] = login_passwd
    config['${language}'] = language
    f = open(config_file_path,'w')
    f.write('*** Variables ***\n')
    for k,v in config.iteritems():
        line = k+'    '+v+'\n'
        f.write(line)
    f.close()
    cmdline = 'pybot.bat --argumentfile '+argfile_name+' '+test_file_dir
    print cmdline
    subprocess.call(cmdline,cwd=test_file_dir)
        
    
        