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

# 解析connvd文件，导入数据库
# 查询相同vuln_id,进行重复性校验
# 入库时会check相同vuln_id的其他字段是否相同
class Save_Cnnvd():
    def __init__(self,path):
        self.cnnvd_xml_path = path
        self.name_list = ['编号撤回', '编号已被CVE保留', '编号错误', '编码撤回', '被拒绝的漏洞编号', '编号重复', '编号撤销', 'None', '', '撤销', '撤回', None]
        self.attr_list = ['vuln_solution', 'cve_id', 'name', 'vuln_type', 'refs', 'severity', 'vuln_descript', 'bugtraq_id', 'published', 'modified', 'thrtype']
    
    #unicode中文字符编码范围,判断是否为汉字
    @staticmethod  
    def is_chinese(string):
        for ch in string:
            if u'\u4e00' <= ch <= u'\u9fff':     
                return True
        return False
    
    #对比文件数据和数据库数据更新
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

    async def save_to_db(self,check_list:dict):
        dbm = await SqlManager()
        # check_list_xml = sorted(os.listdir(self.cnnvd_xml_path), reverse=True)
        check_list_xml = sorted([i for i in os.listdir(self.cnnvd_xml_path) if i.endswith('.xml')], reverse=True)
        keys_list = list(check_list.keys())
        check_list_xml = [item for item in check_list_xml if item.split(".")[0] in keys_list]

        for check in check_list_xml:
            try:
                allvul = await self.parse_cnnvd(self.cnnvd_xml_path+'/'+check)
                for vul in allvul:
                    cnnvd_id = str(vul.vuln_id)
                    name = str(vul.name)
                    try:
                        if name in self.name_list:
                            logger.info('筛选失效漏洞:{}:{}'.format(cnnvd_id, name))
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
                                logger.info(f'更新漏洞{cnnvd_id}:{update_info}')
                        else:
                            await dbm.add_cnnvd_vul(vul)
                            await dbm.commit()
                            logger.info(f'新增漏洞:{cnnvd_id}')
                    except Exception as e:
                        logger.error(f'录入错误:{vul.name},{e}')
                        await dbm.rollback()
            except Exception as e:
                logger.error(e)   
        await dbm.close()
        
    
    #解析cnnvd xml文件
    #获取cve_id
    #获取cpe_operator及negate，并统一大小写??????
    #获取vuln_software_list，若vuln_software_list也是entry子节点，cpe也是vuln_software_list的cpe
    #获取refs
    #获取severity,危险等级赋值
    # @staticmethod
    async def parse_cnnvd(self,path):
        allvul = []
        tree = ET.parse(path)
        root = tree.getroot()
        re_str = r"^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)"

        def handle_other_id(entry,k):
            for t in k:
                tag = t.tag.replace(replace_data, '').replace('-', '_')
                value = t.text
                entry[tag] = value

        def handle_vulnerable_configuration(entry,k):
            for t in k:
                if t.tag.replace(replace_data, '').replace('-', '_') == 'cncpe':
                    cncpe = t.attrib
                    entry['cpe_operator'] = cncpe.get('operator', '').upper()
                    entry['cpe_negate'] = cncpe.get('negate', '').lower()
                    for cc in t:
                        if cc.tag.replace(replace_data, '').replace('-', '_') in ["cncpe_terrace","cncpe_software"]:
                            for g in cc:
                                vul_cpe = g.attrib.get('name')
                                if not self.is_chinese(vul_cpe):
                                    vul_cpe = vul_cpe.lower().replace('\\', '')
                                    entry['vuln_software_list'] = entry.get('vuln_software_list', []) + [vul_cpe]

        def handle_refs(entry,k):
            for s in k:
                tag = s.tag.replace(replace_data, '').replace('-', '_')
                if tag in ['ref_url', 'ref_source']:
                    url = s.text if s.text and re.match(re_str, s.text) else ''
                    if url:
                        entry['refs'] = entry.get('refs', []) + [url]

        def handle_vul_type(entry,value):
            entry['vuln_type'] = value.text

        def handle_severity(entry,value):
            entry['severity'] = SEVERITY_DICT.get(value.text, 0)
        
        def handle_vuln_software_list(entry,k):
            pass

        handlers = {
            'other_id': handle_other_id,
            'vulnerable_configuration': handle_vulnerable_configuration,
            'refs': handle_refs,
            'vuln_type': handle_vul_type,
            'severity': handle_severity,
            'vuln_software_list':handle_vuln_software_list,
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
            entry['vuln_software_list'] = ','.join(sorted(entry.get('vuln_software_list', [])))
            allvul.append(Cnnvd(**entry))

        return allvul  

async def run(cnnvd_change):
    import time
    start_time = time.time()
    save_cnnvd = Save_Cnnvd(config_cnnvd.save_path)  
    # await save_cnnvd.parse_cnnvd("./download/cnnvd/test.xml")  
    # await save_cnnvd.parse_cnnvd("./download/cnnvd/2020.xml") 
    await save_cnnvd.save_to_db(cnnvd_change)    
    end_time = time.time()

    run_time = end_time - start_time
    logger.info(f"cnnvd解析运行时间为:{run_time}秒") 

        

if __name__ == '__main__':
    import asyncio
    asyncio.run(run()) 
