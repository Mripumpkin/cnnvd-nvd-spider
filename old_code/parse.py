#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import xml.etree.cElementTree as ET    #解析XML文件
from lxml import etree
import json
import os
import re
import sys
import requests
from pyquery.pyquery import PyQuery 
from cnnvd import Cnnvd
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import or_

######配置入库数据库
thorns_pgsql_host = '127.0.0.1'
thorns_pgsql_port = 55432
thorns_pgsql_db = 'vrp'
thorns_pgsql_passwd = 'Vrp2P&sd*#2)@1#21'  
thorns_pgsql_user = 'postgres'
#########################
severity_dict = {
    '超危': 3,
    '高危': 2,
    '中危': 1,
    '低危': 0
}

def connect_DBSession():
    engine = create_engine("postgresql+psycopg2://%s:%s@%s:%s/%s" % (thorns_pgsql_user, thorns_pgsql_passwd, thorns_pgsql_host, thorns_pgsql_port, thorns_pgsql_db))
    return sessionmaker(bind=engine)


def is_chinese(string):
    for ch in string:
        if u'\u4e00' <= ch <= u'\u9fff':     #unicode中文字符编码范围,判断是否为汉字
            return True
    return False


def parse_cnvd(path):
    allvul = []
    tree = ET.parse(path)
    root = tree.getroot()
    # parser = etree.XMLParser(recover=True)
    # with open(path, 'r') as f:
    #     data = f.read()
    # root = etree.fromstring(data.encode('utf-8'), parser=parser)
    for child_of_root in root:
        entry = {}
        for k in child_of_root:
            tag = k.tag.replace('{http://www.cnnvd.org.cn/vuln/1.0}', '').replace('-', '_')     #k.tag子节点名；k.text子节点值;新tag为entry下一级子节点
            value = k.text            
            if value:
                pass
                # value = value.encode('utf-8', 'ignore')     #忽略不能编码的值
            else:
                value = ''
            if tag == 'other_id':
                for t in k:
                    tag = t.tag.replace('{http://www.cnnvd.org.cn/vuln/1.0}', '').replace('-', '_')
                    value = t.text
                    entry[tag] = value      #将cve_id写入entry字典中
                continue
            if tag == 'vulnerable_configuration':
                for t in k:                 #t为entry下二级子节点cncpe
                    tag = t.tag.replace('{http://www.cnnvd.org.cn/vuln/1.0}', '').replace('-', '_')
                    if tag == 'cncpe':
                        cncpe = t.attrib            #cncpe为字典型
                        entry['cpe_operator'] = cncpe.get('operator').upper() if cncpe.get('operator') else cncpe.get('operator')   # 统一大写，将小写转大写
                        entry['cpe_negate'] = cncpe.get('negate').lower() if cncpe.get('negate') else cncpe.get('negate')           # 统一小写，将大写转小写                        
                        for cc in t:                #cc为三级子节点cncpe-lang
                            tag_c = cc.tag.replace('{http://www.cnnvd.org.cn/vuln/1.0}', '').replace('-', '_')
                            if tag_c == 'cncpe_lang':
                                vul_cpe = cc.attrib.get('name')
                                if is_chinese(vul_cpe):                                         # 丢弃cpe包含中文的
                                    continue
                                vul_cpe = vul_cpe.lower().replace('\\', '')                     # 统一小写, 处理转义字符
                                if 'vuln_software_list' in entry.keys():                        #若vuln_software_list也是entry子节点，cpe也是vuln_software_list的cpe

                                    entry['vuln_software_list'].append(vul_cpe)
                                else:
                                    entry['vuln_software_list'] = [vul_cpe]
                continue            
            if tag == 'vuln_software_list':
                continue
            if tag == 'refs':       
                for t in k:         #k为refs；t为ref；s为ref下面的标签
                    for s in t:
                        tag = s.tag.replace('{http://www.cnnvd.org.cn/vuln/1.0}','').replace('-', '_')
                        if tag == 'ref_url':                        #只取ref_url的值                    
                            url = ''
                            if s.text and bool(re.findall(r"^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)", s.text)):
                                url = s.text
                                if 'refs' in entry.keys():
                                    entry['refs'].append(url)
                                else:
                                    entry['refs'] = [url]
                        if tag == 'ref_source':           #有些参考网址是放在<ref-source>下                  
                            url = ''
                            if s.text and bool(re.findall(r"^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)", s.text)):
                                url = s.text
                                if 'refs' in entry.keys():
                                    entry['refs'].append(url)
                                else:
                                    entry['refs'] = [url]                                   
                continue
            if tag == 'vul_type':
                entry['vuln_type'] = value
                continue            
            if tag == 'severity':                       #危险等级赋值
                if severity_dict.get(value):
                    value = severity_dict.get(value)
            entry[tag] = value
        if not entry.get('refs'):
            entry['refs'] = []
        else:
            entry['refs'] = ','.join(entry.get('refs'))      #不能用b''字节连接
        if not entry.get('vuln_software_list'):
            entry['vuln_software_list'] = ''
        else:
            vuln_software_list = sorted([i for i in entry.get('vuln_software_list') if i])
            entry['vuln_software_list'] = ','.join(vuln_software_list)   # 将CPE转成小写
        # entry['patchinfo'] = getPatchinfo(entry['vuln_id'])
        allvul.append(Cnnvd(**entry))
        # import pdb;pdb.set_trace()     
    return allvul


def get_vuln_severity(vuln_id):
    try:
        url = 'http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD={}'.format(vuln_id)
        header = {
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
            'Accpet': '*/*',
        }
        resp = requests.get(url, headers=header, timeout=15, verify=False)
        doc = PyQuery(resp.text, parser='html')
        item = doc('div.fl.w770')
        __info = item('div.detail_xq.w770')
        risk_level = __info('li:nth-child(2)').text()
        risk_level = risk_level.encode('utf-8')
        if risk_level:
            risk_level = risk_level.replace('危害等级：', '').replace('超危', '3').replace('高危', '2').replace('中危', '1').replace('低危', '0')
            return str(risk_level.replace(' ', '').replace('\xc2\xa0', ''))
    except Exception as e:
        print(e)
        return ''


if __name__ == '__main__':
    """
    TODO 格式化漏洞等级
    1. severity 为空，重新获取
    2. 超危，高危，中危，低危：3，2，1，0
    name：G 编号撤回、编号重复、编号撤销、None、''、撤销、撤回
    """ 
    DBSession = connect_DBSession()
    session = DBSession()
    
    filter_xml = []
    error_xml = []
    
    # 删除文件中的null字节
    for i in error_xml:
        os.system('mv xml/{} xml/temp'.format(i))
        with open('xml/temp') as f, open('xml/'+i, 'w+') as ff:
            result = f.read().replace('\x00', '')       #不可见字符替换为空
            ff.write(result)
            
    check_list_xml = []
    cnnvd_xml_path = "/home/NvdParser/download/cnnvd/"
    for i in os.listdir(cnnvd_xml_path):            #listdir返回指定的文件夹包含的文件或文件夹的名字的列表
        if '.xml' in i and i not in filter_xml and i not in error_xml:
            check_list_xml.append(i)                #check_list_xml为所有要解析的xml 
    check_list_xml = sorted(check_list_xml, reverse=True)        #对所选对象排序sorted(iterable, key=None, reverse=False);reverse = True降序,reverse =False升序（默认）
    print(check_list_xml)

    for check in check_list_xml:
        print('parser xml {}'.format(check))
        try:
            allvul = parse_cnvd(cnnvd_xml_path+'/'+check)
            # import pdb;pdb.set_trace()
            count = 0
            for vul in allvul:
                count += 1
                try:
                    cnnvd_id = str(vul.vuln_id)
                    name = str(vul.name)
                    if name in ['编号撤回', '编号已被CVE保留', '编号错误', '编码撤回', '被拒绝的漏洞编号', '编号重复', '编号撤销', 'None', '', '撤销', '撤回', None]:
                        print('存在不入库的结果： {}: {}'.format(cnnvd_id, name))
                        continue
                        
                    commit_flag = False
                    tmps = session.query(Cnnvd).filter(Cnnvd.vuln_id == vul.vuln_id).first()        #ORM操作之query查询，到已有库vrp_cnnvd查询相同vuln_id,返回第一条结果      
                    if tmps:
                        #After20230825,cnnvd的xml中无cpe/vuln_solution/.. 需判断是否为空后再提交
                        for i in ['vuln_solution', 'cve_id', 'name', 'vuln_type', 'refs', 'severity', 'vuln_descript', 'bugtraq_id', 'published', 'modified', 'thrtype']:
                            if getattr(vul, i) and getattr(vul, i) != '':         
                                if getattr(vul, i) != getattr(tmps, i):             #getattr返回一个对象属性值
                                    commit_flag = True                              #入库时会check相同vuln_id的其他字段是否相同，不相同说明有更新，需要commit
                                    setattr(tmps, i, getattr(vul, i))               #设置对象属性值，用新的值更新老的
                            else:
                                continue
                        if commit_flag:
                            print('update {} {}/{}'.format(cnnvd_id, count, len(allvul)))
                    else:
                        commit_flag = True
                        session.add(vul)
                        print('insert {} {}/{}'.format(cnnvd_id, count, len(allvul)))
   
                    if commit_flag:
                        session.commit()

                except Exception as e:
                    print(e)
                    print(vul.__dict__)
                    session.rollback()
        except Exception as e:
            print(e)
    
    session.close()