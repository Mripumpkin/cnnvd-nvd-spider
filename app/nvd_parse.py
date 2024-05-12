#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/09/01
# 导入需要的模块

#cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
#CPE:2.3:类型:厂商:产品:版本:更新版本:发行版本:界面语言:软件发行版本:目标软件:目标硬件:其他


import os
import re
import datetime 
import json
from db.manager import SqlManager
from config.config import NVD as config_cnnvd
from db.model import Cnnvd 
from cpe import CPE


from log.log import CustomLogger 

logger  = CustomLogger(__name__).get_logger()

# cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
def fmt_cpe(cpe):
    try:
        if 'cpe:/' in cpe or '-->versionstart:' in cpe:    
            return cpe.strip(':::').replace('cpe:2.3:','cpe:/')
        elif 'cpe:2.3:' in cpe:
            return CPE(cpe).as_uri_2_3().strip(':::').replace('cpe:2.3:','cpe:/')
    except Exception as e:
        raise ValueError(f"CPE格式解析错误:{e}:{cpe}")


class Save_Nvd():
    def __init__(self,path):
        self.json_dir = path
        
    async def produce_entries(self,filename):
        with open(filename, 'r') as f:
            result = json.load(f)
            cve_items = result.get('CVE_Items', [])
            for item in cve_items:
                yield item
    
    def parse_entry(slef,item):
        entry = {}
        try:
            cve_id = item['cve']['CVE_data_meta']['ID']
            if not cve_id:
                return None

            configurations = item.get('configurations', {})
            nodes = configurations.get('nodes', [])
            if not isinstance(nodes, list) or not nodes:
                return None

            cpes = []
            cpe_operator = nodes[0].get('operator')
            if not cpe_operator or cpe_operator.upper() == 'AND':
                return None

            cpe_negate = 'false'
            cpe_match = nodes[0].get('cpe_match', [])
            for i in cpe_match:
                cpe = i.get('cpe23Uri', '').lower()
                cpe_versionstart = i.get('versionStartIncluding', '')
                cpe_versionend = i.get('versionEndIncluding', '')
                if cpe and cpe_versionstart and cpe_versionend:
                    cpe = fmt_cpe(cpe) + '-->versionstart:' + cpe_versionstart + '-->versionend:' + cpe_versionend
                elif cpe and not cpe_versionstart and not cpe_versionstart:
                    cpe = fmt_cpe(cpe)
                cpes.append(cpe)

            entry['cve_id'] = cve_id
            entry['cpe_operator'] = cpe_operator
            entry['cpe_negate'] = cpe_negate
            entry['vuln_software_list'] = cpes
        except Exception as e:
            logger.error('Error parsing CVE entry: %s', e, exc_info=True)
            return None
        return entry
        
    async def parser_json(self,path):
        all_CVE = []
        with open(path, 'r+') as f:
            result = json.load(f) 
            cve_items = result.get('CVE_Items', [])  
            for item in cve_items:
                entry = {}
                try:
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    if not cve_id:
                        continue

                    configurations = item.get('configurations', {})
                    nodes = configurations.get('nodes', [])
                    if not isinstance(nodes, list) or not nodes:  
                        continue
                    
                    cpes = []
                    cpe_operator = nodes[0].get('operator')
                    if not cpe_operator or cpe_operator.upper() == 'AND':  
                        continue

                    cpe_negate = 'false'
                    cpe_match = nodes[0].get('cpe_match', [])
                    for i in cpe_match:
                        cpe = i.get('cpe23Uri', '').lower()  
                        cpe_versionstart = i.get('versionStartIncluding', '')
                        cpe_versionend = i.get('versionEndIncluding', '')
                        if cpe and cpe_versionstart and cpe_versionend:
                            cpe = fmt_cpe(cpe) + '-->versionstart:' + cpe_versionstart + '-->versionend:' + cpe_versionend
                        elif cpe and not cpe_versionstart and not cpe_versionstart:
                            cpe = fmt_cpe(cpe)
                        cpes.append(cpe)
                        
                    entry['cve_id'] = cve_id
                    entry['cpe_operator'] = cpe_operator
                    entry['cpe_negate'] = cpe_negate
                    entry['vuln_software_list'] = cpes
                except Exception as e:
                    logger.error('Error parsing CVE entry: %s', e, exc_info=True) 
                else:
                    all_CVE.append(entry)  
        return all_CVE  
    
    def cmpare_dict(self,_vrp_cpes:dict,_nvd_cpes:dict)->dict:
        update_info = {}
        if  _nvd_cpes <= _vrp_cpes: 
            return update_info
        elif  _vrp_cpes <= _nvd_cpes:  
            update_info["vuln_software_list"] = ','.join(_nvd_cpes)
        elif _vrp_cpes and _nvd_cpes:  
            update_info["vuln_software_list"] = ','.join(_vrp_cpes.union(_nvd_cpes))
        return update_info
        
    async def save_to_db(self,check_list:dict):
        exist_cve = {}
        dbm = await SqlManager()
        check_list = list(check_list.keys())
        file_list = [os.path.basename(url).replace(".gz", "") for url in check_list]

        # check_list_json = sorted(os.listdir(self.json_dir), reverse=True)
        list_json = sorted([i for i in os.listdir(self.json_dir) if i.endswith('.json')], reverse=True)
        check_list_json = [item for item in file_list if item in list_json]
        
        for check in check_list_json:
            year = check.rsplit('.', 1)[0].rsplit('-', 1)[1] if re.match(r'\d+', check.rsplit('.', 1)[0].rsplit('-', 1)[1]) else datetime.now().year  
                
            #将cnnvd表中有的某年全部的CVE提取到exist_cve
            alldata = await dbm.get_contains_value_connvd(f'CVE-{year}')
            for i in alldata:         
                cve_id = str(i.cve_id)
                if not cve_id or cve_id == 'None':
                    continue
                elif exist_cve.get(cve_id):
                    logger.info('{} 已经存在'.format(cve_id))
                else:
                    exist_cve[cve_id] = i           
                continue
            logger.info('数据库中存在的 CVE-{} 有{}个'.format(year, len(exist_cve)))
            try:
                async for item in self.produce_entries('{}/{}'.format(self.json_dir, check)):
                    nvd_vul = self.parse_entry(item)
                    if not nvd_vul:
                        continue
                    try:
                        cve_id = str(nvd_vul["cve_id"])
                        if cve_id in exist_cve:
                            tmps = exist_cve.get(cve_id)
                        else:
                            tmps = await dbm.get_connvd_by_cve_id(cve_id)     
                            if not tmps:
                                continue 
                        if "vuln_software_list" not in nvd_vul:
                            continue           
                        _nvd_cpes = set(nvd_vul["vuln_software_list"])
                        _vrp_cpes = set(fmt_cpe(i) for i in (tmps.vuln_software_list.split(',')
                                                                if tmps.vuln_software_list else []))
                        update_info = self.cmpare_dict(_vrp_cpes,_nvd_cpes)
                        if update_info:
                            await dbm.update_cnnvd_vul(tmps.id,update_info)
                            await dbm.commit()
                    except ValueError as v:
                        logger.warning(v)
                    except Exception as e:
                        logger.error(e)
                        await dbm.rollback()
            except Exception as e:
                logger.error(e)
        await dbm.close()
        
async def run(nvd_list):
    import time
    start_time = time.time()
    save_cnnvd = Save_Nvd(config_cnnvd.save_path)  
    await save_cnnvd.save_to_db(nvd_list)  
    end_time = time.time()

    run_time = end_time - start_time
    logger.info(f"更新cnnvd库,添加vuln_software_list信息:{run_time}秒") 
    
    # data = await save_cnnvd.parser_json("./download/nvd/nvdcve-1.1-2020.json")
    # last_time = time.time()

    # run_time = last_time - end_time
    # logger.info(f"常规运行时间为:{run_time}秒") 
    # logger.warning(len(data))

 

if __name__ == '__main__':
    import asyncio
    asyncio.run(run())
 
