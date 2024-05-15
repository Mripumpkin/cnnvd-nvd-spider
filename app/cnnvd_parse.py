#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import xml.etree.cElementTree as ET    #解析XML文件
from lxml import etree
import os
import re
import datetime 
from db.manager import SqlManager
from config.config import CNNVD as config_cnnvd
from db.model import Cnnvd 

from log.log import CustomLogger 

logger  = CustomLogger(__name__).get_logger()

SEVERITY_DICT = {
    '超危': 3,
    '高危': 2,
    '中危': 1,
    '低危': 0
}

class Save_Cnnvd():
    def __init__(self,path):
        self.cnnvd_xml_path = path
        self.title_list = ['编号撤回', '编号已被CVE保留', '编号错误', '编码撤回', '被拒绝的漏洞编号', '编号重复', '编号撤销', 'None', '', '撤销', '撤回', None]
        self.attr_list = ['cve', 'title', 'type', 'risk_level', 'descript']
    
    @staticmethod  
    def is_chinese(string):
        for ch in string:
            if u'\u4e00' <= ch <= u'\u9fff':     
                return True
        return False
    
    @staticmethod  
    def compare_data(data_x, data_y)->bool:
        type_x = type(data_x)
        if type_x == int:
            try:
                data_y = int(data_y)
            except ValueError:
                pass
        elif type_x == str:
            try:
                data_y = str(data_y)
            except ValueError:
                pass
        elif type_x == datetime.date:
            try:
                data_y = datetime.datetime.strptime(data_y, '%Y-%m-%d').date()
            except ValueError:
                pass
        return data_x == data_y
    
    async def get_max_uuid(self,dbm)->int:
        data  = await dbm.get_all_uuid()
        all_uuid = sorted(data, key=lambda x: int(x.uuid.split("-")[2]))
        if all_uuid:
            max_uuid = all_uuid[-1]
            num = int(max_uuid[0].split('-')[2]) 
        else:
            num = 100000
        return num

    async def save_to_db(self,check_list:dict):
        
        dbm = await SqlManager()
        uuid_num  = await self.get_max_uuid(dbm)
        check_list_xml = sorted([i for i in os.listdir(self.cnnvd_xml_path) if i.endswith('.xml')], reverse=True)
        keys_list = list(check_list.keys())
        check_list_xml = [item for item in check_list_xml if item.split(".")[0] in keys_list]
        for check in check_list_xml:
            logger.info(f"开始解析入库: {check}文件")
            all_data = []
            try:
                async for item in self.parse_cnnvd(self.cnnvd_xml_path+'/'+check):
                    vul = await self.parse_cnnvd_entry(item)
                    cnnvd_id = str(vul.cnnvd)
                    title = vul.title
                    try:
                        if title in self.title_list:
                            continue
                            
                        tmps = await dbm.get_cnnvd_vul_by_vulnid(cnnvd_id)  
                        if tmps:  
                            update_info = {}                                                   
                            for i in self.attr_list:
                                if getattr(vul, i):
                                    vul_data = getattr(vul, i)
                                    tmps_data = getattr(tmps, i)
                                    if vul_data == tmps_data or self.compare_data(tmps_data,vul_data):              
                                        continue          
                                    else: 
                                        update_info[i] = vul_data                 
                            if update_info:   
                                await dbm.update_cnnvd_vul(tmps.id, update_info)
                                await dbm.commit()
                        else:
                            uuid_num += 1
                            publish_time = str(vul.published)
                            uuid_year = datetime.datetime.strptime(publish_time, "%Y-%m-%d").strftime("%Y%m")
                            uuid = f'CVM-{uuid_year}-{uuid_num}'
                            vul.uuid = uuid
                            all_data.append(vul)
                    except Exception as e:
                        logger.error(f'录入错误:{vul.cnnvd},{e}')
                if all_data:
                    await dbm.add_connvd_all_vul(all_data)
                    await dbm.commit()
            except Exception as e:
                logger.error(e)   
        await dbm.close()
        
    
    async def parse_cnnvd(self,path):
        tree = ET.parse(path)
        root = tree.getroot()
        for child_of_root in root:
            yield child_of_root
    
    async def parse_cnnvd_entry(self,child_of_root):
        re_str = r"^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)"
        
        def handle_other_id(entry,k):
            for t in k:
                if  t.tag.replace(replace_data, '').replace('-', '_') == 'cve_id':
                    entry['cve'] = t.text

        def handle_refs(entry,k):
            for s in k:
                tag = s.tag.replace(replace_data, '').replace('-', '_')
                if tag in ['ref_url', 'ref_source']:
                    url = s.text if s.text and re.match(re_str, s.text) else ''
                    if url:
                        entry['refs'] = entry.get('refs', []) + [url]

        def handle_vul_type(entry,value):
            entry['type'] = value.text

        def handle_severity(entry,value):
            entry['risk_level'] = SEVERITY_DICT.get(value.text, 0)
        
        def handle_vuln_software_list(entry,k):
            pass
        
        def handle_name(entry,k):
            entry['title'] = k.text
            
        def handle_solution(entry,k):
            entry['solution'] = k.text
            
        def handle_descript(entry,k):
            entry['descript'] = k.text
        
        def handle_vuln_id(entry,k):
            entry['cnnvd'] = k.text
        
        def handle_source(entry,k):
            entry['source'] = "CNNVD漏洞库"
            
        
        handlers = {
            'other_id': handle_other_id,
            'refs': handle_refs,
            'vuln_type': handle_vul_type,
            'severity': handle_severity,
            'vuln_software_list':handle_vuln_software_list,
            'name':handle_name,
            'vuln_descript':handle_descript,
            'vuln-solution':handle_solution,
            'vuln_id':handle_vuln_id,
            'source':handle_source,
        }
          
        entry = {}   
        for k in child_of_root:
            value = k.text if k.text else ''
            tag = k.tag.replace('-', '_')
            replace_data, _, tag = tag.rpartition('}')
            replace_data = replace_data + "}"
            if tag in handlers:    
                handlers[tag](entry,k)
            else:
                entry[tag] = value
        
        entry['refs'] = ','.join(entry.get('refs', []))
        return Cnnvd(**entry)
        
    
    async def parse_all_cnnvd(self,path):
        allvul = []
        tree = ET.parse(path)
        root = tree.getroot()
        re_str = r"^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)"

        def handle_other_id(entry,k):
            for t in k:
                if  t.tag.replace(replace_data, '').replace('-', '_') == 'cve_id':
                    entry['cve'] = t.text

        def handle_refs(entry,k):
            for s in k:
                tag = s.tag.replace(replace_data, '').replace('-', '_')
                if tag in ['ref_url', 'ref_source']:
                    url = s.text if s.text and re.match(re_str, s.text) else ''
                    if url:
                        entry['refs'] = entry.get('refs', []) + [url]

        def handle_vul_type(entry,value):
            entry['type'] = value.text

        def handle_severity(entry,value):
            entry['risk_level'] = SEVERITY_DICT.get(value.text, 0)
        
        def handle_vuln_software_list(entry,k):
            pass
        
        def handle_name(entry,k):
            entry['title'] = k.text
            
        def handle_solution(entry,k):
            entry['solution'] = k.text
            
        def handle_descript(entry,k):
            entry['descript'] = k.text
        
        def handle_vuln_id(entry,k):
            entry['cnnvd'] = k.text
        
        def handle_source(entry,k):
            entry['source'] = "CNNVD漏洞库"
        
        def handle_fromat_time(entry,k): 
            entry[k.tag.replace('-', '_')] = k.text          

        handlers = {
            'other_id': handle_other_id,
            'refs': handle_refs,
            'vuln_type': handle_vul_type,
            'severity': handle_severity,
            'vuln_software_list':handle_vuln_software_list,
            'name':handle_name,
            'vuln_descript':handle_descript,
            'vuln-solution':handle_solution,
            'vuln_id':handle_vuln_id,
            'source':handle_source,
            'published': handle_fromat_time,
            'modified': handle_fromat_time,
        }

        for child_of_root in root:
            entry = {}

            for k in child_of_root:
                value = k.text if k.text else ''
                tag = k.tag.replace('-', '_')
                replace_data, _, tag = tag.rpartition('}')
                replace_data = replace_data + "}"
                if tag in handlers:    
                    handlers[tag](entry,k)
                else:
                    entry[tag] = value
           
            entry['refs'] = ','.join(entry.get('refs', []))
        return allvul  

async def run(cnnvd_change):
    import time
    start_time = time.time()
    save_cnnvd = Save_Cnnvd(config_cnnvd.save_path)  
    await save_cnnvd.save_to_db(cnnvd_change)    
    end_time = time.time()

    run_time = end_time - start_time
    logger.info(f"cnnvd解析运行时间为:{run_time}秒") 

