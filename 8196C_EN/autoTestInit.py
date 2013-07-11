# coding=utf-8
'''
Created on 2013-3-27

@author: hany
'''
import string
import re
import time
import lxml.html
from robot.libraries import  BuiltIn
from lxml import etree
from robot.parsing import TestCaseFile
import pickle
import sys
import codecs
import gzip, cStringIO
reload(sys)
sys.setdefaultencoding('utf-8')

test_case_file_list = [u'DHCP服务器.txt',
                       u'DHCP接入.txt',
                       u'IPMAC绑定.txt',
                       u'IP过滤和协议过滤.txt',
                       u'MAC地址过滤.txt',
                       u'MTU配置.txt',
                       u'PPPOE接入.txt',
                       u'WAN口MAC配置.txt',
                       u'静态接入.txt',
                       u'内网配置.txt'
                      ]
page_futs = {
             'sys_log':['del_all_sys_log'],
             'interface':['connected'],
             'lan_dhcp_serer_set':['dhcp_start_ip','dhcp_end_ip','save_dhcp_server'],
             'restore_dfault':['default_set']
             }
class keyword:
    def __init__(self):
        self.keyword = ''
        self.params = []
        
        
class autoTestInit:
    def __init__(self):
        self.modules = []
        self.page_visiable_element = []
        self.case_goto = {}
        self.page_goto = {}
        self.include_case = []
        self.exclude_case = []
    def convert_string_to_utf8(self,html):
        if html[:3] == '\x1f\x8b\x08':
            html = gzip.GzipFile(fileobj = cStringIO.StringIO(html)).read()
        return html.decode('utf-8')
    
    def get_all_mould_applications(self,source):
        pattern = re.compile(r'Applications.*?;',re.S)
        match = pattern.search(source)
        if match == None:
            raise RuntimeError('No Applications')
        apps = match.group()
        pattern = re.compile(r'//.*?\n')
        apps = pattern.sub("",apps)
        pattern = re.compile(r'/\*.*?\*/',re.S)
        apps = pattern.sub("",apps)
        pattern = re.compile(r'name\s*:\s*\"\s*(\w+)\s*\"',re.M)
        apps = pattern.findall(apps)
        for a in apps:
            print a
            self.modules.append(a)
            
    def get_lang_var(self,source):
        pattern = re.compile(r'Language\.\w+\s*=\s*\{.+?\};',re.S)
        match = pattern.search(source)
        langs = match.group()
        pattern = re.compile(r'//.*?\n')
        langs = pattern.sub("",langs)
        pattern = re.compile(r'/\*.*?\*/',re.S)
        langs = pattern.sub("",langs)
        f = open('lang_var.txt','w')
        f.write('*** Variables ***\n')
        muds = ['common',
                'wan']
        for m in muds:
            self._get_all_dlg_string(m,langs,f)
        f.close()
        
    def _get_all_dlg_string(self,mud,source,f):
        pattern = re.compile('\"'+mud+'\":.*?},',re.S)
        match = pattern.search(source)
        common =  match.group()
        pattern = re.compile(r'\s*(?:\"(\w+)\"|(\w+))\s*:\s*(?:\"(.+)\"|\'(.+)\'),?\s*',re.M)
        a = pattern.findall(common)
        k = ''
        v = '\''
        for i in a:
            if i[0] != '':
                print i[0]
                k = i[0]
            if i[1] != '':
                print i[1]
                k = i[1]
            if i[2] != '':
                print i[2]
                v = i[2]
            if i[3] != '':
                print i[3]
                v = i[3]
            if k == 'time_r':
                continue
            if v.find('\\\'') != -1:
                v= v.replace(u'\\\'', u'\'')
            if v.find('\\\\') != -1:
                v= v.replace(u'\\\\', u'\\\\')
            if v.find('\\n') != -1:
                a = v.find('\\n')
                l = v[a+len('\\n'):].strip()
                v = v[:a].strip()+' '+l
                #v = v.replace(u'\\n', u'')
            line = '${'+mud+"_"+k+'}           '+v+'\n'
            f.write(line)
        
    
    def _get_log_actions(self,logs,log_mud,output):
        pattern = re.compile(log_mud+':\[(.*?)\]',re.S)
        a = pattern.findall(logs)
        acts = ''
        for i in a:
            acts = i
            break
        pattern = re.compile(r'\s*\"(.+)\",?\s*',re.M)
        a = pattern.findall(acts)
        c = 0
        for i in a:
            line = '${'+log_mud+'_'+str(c)+'}        '+i+'\n'
            output.write(line)
            c = c + 1
           
    def get_log_string(self,source):
        pattern = re.compile(r'igd.log_action={.*?};',re.S)
        match = pattern.search(source)
        logs = match.group()
        pattern = re.compile(r'//.*?\n')
        logs = pattern.sub("",logs)
        pattern = re.compile(r'/\*.*?\*/',re.S)
        logs = pattern.sub("",logs)
        f = open('log_var.txt','w')
        f.write('*** Variables ***\n')
        muds = ['LOG_CONNECT_STANDARD_PPPOE_action',
                'LOG_CONNECT_STANDARD_PPP_action',
                'LOG_CONNECT_STANDARD_GUANGDIAN_action']
        for i in muds:     
            self._get_log_actions(logs,i,f)
        f.close()
        
               
    def delete_all_hidden_element(self,e):
        if e.attrib.get('style') != 'display: none;':
            if len(e.getchildren()) != 0:
                for i in e.getchildren():
                    self.delete_all_hidden_element(i)
        else:
            e.clear()
                    
    
    def get_all_avaulabl_elements(self,innerhtml):
        elements = lxml.html.fragments_fromstring(innerhtml)
        element_list = {}
        for e in elements:
            self.delete_all_hidden_element(e)
            for a in e.iter():
                id = a.attrib.get('id')
                if id != None:
                    element_list[id] = a.tag
        return element_list
     
    def _get_match_futs(self,doc):
        pattern = re.compile(r'@(\[.*\])') 
        a = pattern.findall(doc)
        if len(a) == 0:
            return None
        futs  = []
        for i in a:
            futs = eval(i)
            break
        return futs
                        
    def _select_test_case_and_suite(self,ava_ele_list,record_kw):
        a = []
        for i in record_kw:
            a.append(i)
            
        for k,v in page_futs.iteritems():
            if k in self.page_goto.keys():
                continue
            match_page_ok = True
            for i in v:
                if not i in ava_ele_list:
                    match_page_ok = False
                    break
            if match_page_ok:
                self.page_goto[k] = a 
                    
        for name in test_case_file_list:
            suite = TestCaseFile(source=name).populate()
            for test in suite.testcase_table:
                if test.tags.value != None:
                    continue 
                case_fts = self._get_match_futs(test.doc.value)
                if case_fts == None:
                    continue
                match_case_ok = True
                for i in case_fts:
                    if not i in ava_ele_list:
                        match_case_ok = False
                        break
                if match_case_ok:
                    self.case_goto[test.name] = a
                    test.tags.value = ['include']
            suite.save()
            
    def clear_test_case_tag(self):
        for name in test_case_file_list:
            suite = TestCaseFile(source=name).populate()
            for test in suite.testcase_table:
                test.tags.value = None
            suite.save()
            
                           
    def select_test_case(self):
        self.clear_test_case_tag()
        for m in self.modules:
 #           if m != 'wan':
 #               continue
            record_kw = []
            record_kw.reverse()
            m_kw = keyword()
            m_kw.keyword = 'Execute JavaScript'
            m_kw.params.append('$.CurrentApp=\"'+m+'\";$.load(\"'+m+'\")')
            BuiltIn.BuiltIn().run_keyword(m_kw.keyword,*m_kw.params[0:])
            record_kw.append(m_kw)
            time.sleep(5)
            innerhtml = BuiltIn.BuiltIn().run_keyword('Execute JavaScript','return window.document.getElementById(\"content_layer\").innerHTML')
            time.sleep(5)
            ava_ele_list  = self.get_all_avaulabl_elements(innerhtml)
            bSel = False
            for k,v in ava_ele_list.iteritems():
                if k == 'conntype' and v == 'select':
                    l = BuiltIn.BuiltIn().run_keyword('Get List Items','id='+k)
                    for item in l:
                        kw = keyword()
                        kw.keyword = 'Select From List By Label'
                        kw.params.append(k)
                        kw.params.append(item)
                        BuiltIn.BuiltIn().run_keyword(kw.keyword,*kw.params[0:])
                        record_kw.append(kw)
                        time.sleep(5)     
                        innerhtml = BuiltIn.BuiltIn().run_keyword('Execute JavaScript','return window.document.getElementById(\"content_layer\").innerHTML')
                        time.sleep(5)
                        ava_ele_list  = self.get_all_avaulabl_elements(innerhtml)
                        if 'show_wan_advance' in ava_ele_list.keys():
                            if not 'mac_addr' in  ava_ele_list.keys():
                                kw = keyword()
                                kw.keyword = 'Click Element'
                                kw.params.append('id=show_wan_advance')
                                BuiltIn.BuiltIn().run_keyword(kw.keyword,*kw.params[0:])
                                record_kw.append(kw)
                                time.sleep(5)
                                innerhtml = BuiltIn.BuiltIn().run_keyword('Execute JavaScript','return window.document.getElementById(\"content_layer\").innerHTML')
                                time.sleep(5)
                                ava_ele_list  = self.get_all_avaulabl_elements(innerhtml)
                        index = BuiltIn.BuiltIn().run_keyword('Get Value','id='+k)
                        if index == '1':
                            if 'dns_a' in ava_ele_list.keys():
                                del ava_ele_list['dns_a']
                                ava_ele_list['dhcp_dns_a'] = 'input'
                            if 'dns_b' in ava_ele_list.keys():
                                del ava_ele_list['dns_b']
                                ava_ele_list['dhcp_dns_b'] = 'input'
                        if index == '3':
                            if 'dns_a' in ava_ele_list.keys():
                                del ava_ele_list['dns_a']
                                ava_ele_list['pppoe_dns_a'] = 'input'
                            if 'dns_b' in ava_ele_list.keys():
                                del ava_ele_list['dns_b']
                                ava_ele_list['pppoe_dns_b'] = 'input'
                        if index == '0':
                            if 'dns_a' in ava_ele_list.keys():
                                del ava_ele_list['dns_a']
                                ava_ele_list['static_dns_a'] = 'input'
                            if 'dns_b' in ava_ele_list.keys():
                                del ava_ele_list['dns_b']
                                ava_ele_list['static_dns_b'] = 'input'
                        self._select_test_case_and_suite(ava_ele_list.keys(),record_kw)
                        del record_kw[1:]
                    bSel = True
            if bSel != True:
                self._select_test_case_and_suite(ava_ele_list.keys(),record_kw)
        print str(self.case_goto)
        output = open('gotocase','wb')
        pickle.dump(self.case_goto,output)
        output.close()
        print str(self.page_goto)
        output = open('gotopage','wb')
        pickle.dump(self.page_goto,output)
        output.close()
      
                               
if __name__ == '__main__':
    f = open('hany.html')
    s = f.read()
    a = autoTestInit()
    a.get_lang_var(s)
   
    
