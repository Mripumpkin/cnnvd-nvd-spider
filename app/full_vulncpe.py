#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import collections
from concurrent.futures import ThreadPoolExecutor
from db.model import Vulncpe
from db.manager import SqlManager

from log.log import CustomLogger 


logger  = CustomLogger(__name__).get_logger()

class Full_Vulncpe():
    def __init__(self):
        self.dbm = None
        self.limit = 10000
    
    async def get_cnnvd_cpe(self,offset_val, cnnvd_result):
        try:
            cnnvd_tmp = await self.dbm.get_connvd_offset(self.limit,offset_val)       
            for i in cnnvd_tmp:     
                cnnvd_id = str(i.id)        
                vuln_software_list = str(i.vuln_software_list)
                if cnnvd_result.get(cnnvd_id):
                    continue
                else:
                    cnnvd_result[cnnvd_id] = list(set(vuln_software_list.replace(',CPE', '${%cpe%}cpe').replace(',cpe', '${%cpe%}cpe').split('${%cpe%}')))

            logger.info('query cnnvd the {} done'.format(offset_val))
        except Exception as e:
            logger.error('get vrp_cnnvd cpe error:{}'.format(e))
            return


    async def get_vulncpe_cpe(self,offset_val, vulncpe_result):
        try:
            result = await self.dbm.get_cpe_offset(self.limit,offset_val)  
            for i in result:
                id = str(i.id)
                cpe = i.cpe
                if vulncpe_result.get(id):
                    vulncpe_result[id].append(cpe)
                else:
                    vulncpe_result[id] = [cpe]

            logger.info('query vulncpe the {} done'.format(offset_val))            
        except Exception as e:
            logger.error('get vrp_vulcpe error:{}'.format(e))
            return


    async def process_vulncpe(self,id, cpes, vulncpe_result, count):   
        cpes = list(set(cpes))
        commit_flag = False
        try:
            if vulncpe_result.get(id):
                exist_cpes = vulncpe_result.get(id)
                exist_cpes = list(set(exist_cpes))
                for cpe in cpes:
                    if cpe and cpe.startswith('cpe') and cpe not in exist_cpes:
                        vulncpe = {
                            'id': id,
                            'cpe': cpe
                        }
                        await self.dbm.add_cpe(Vulncpe(**vulncpe))
                        commit_flag = True
            else:
                for cpe in cpes:
                    if not cpe or not cpe.startswith('cpe'):
                        continue
                    vulncpe = {
                        'id': id,
                        'cpe': cpe
                    }
                    self.dbm.add_cpe(Vulncpe(**vulncpe))
                    commit_flag = True
            if commit_flag:
                logger.info('insert {} cpe to db ..'.format(id,count,len(vulncpe_result)))
                await self.dbm.commit()
        except Exception as e:
            logger.error('insert {} to db error: {}'.format(id, e))
            await self.dbm.rollback()


    def format_interval_cpe(self,id,cpe):
        if '-->versionstart:' in cpe:
            tmparry = cpe.split('-->')
            tmparry[0] = tmparry[0].strip('cpe:/') if tmparry[0].startswith('cpe:/') else []
            for i in tmparry:
                if i.startswith('versionstart'):
                    tmpstr = i.split(':')
                    cpe_versionstart = tmpstr[1]
                elif i.startswith('versionend'):
                    tmpstr = i.split(':')
                    cpe_versionend = tmpstr[1]
                else:
                    tmpstr = i.split(':')
                    part = tmpstr[0]
                    vendor = tmpstr[1]
                    product = tmpstr[2]                            

            vulncpe = {
                'id': id,
                'cpe': cpe,
                'cpe_versionstart': cpe_versionstart,
                'cpe_versionend': cpe_versionend,
                'part': part,
                'vendor': vendor,
                'product': product,
                'interval': 1
            }

        else:
            vulncpe = {
                'id': id,
                'cpe': cpe,
                'interval': 0
            }        

        return vulncpe    


    async def full_vnlncpe(self):
        self.dbm = await SqlManager()
        
        cnnvd_result, vulncpe_result = collections.OrderedDict(), {}        
        offset_val = 0
        batch_size = 10000
    
        while offset_val <= await self.dbm.connvd_count():
            await self.get_cnnvd_cpe(offset_val, cnnvd_result)
            offset_val += batch_size

        offset_val = 0
        while offset_val <= await self.dbm.cpe_count():
            await self.get_vulncpe_cpe(offset_val, vulncpe_result)
            offset_val += batch_size
        count = 0
        for id, cpes in cnnvd_result.items():          
            cpes = list(set(cpes))
            count += 1
            commit_flag = False
            try:
                if vulncpe_result.get(id):
                    exist_cpes = vulncpe_result.get(id)
                    exist_cpes = list(set(exist_cpes))
                    for cpe in cpes:
                        if cpe and cpe.startswith('cpe') and cpe not in exist_cpes:     
                            vulncpe = self.format_interval_cpe(id,cpe)
                            del vulncpe["id"]
                            await self.dbm.update_cpe_by_id(id,vulncpe)
                            commit_flag = True
                else:
                    for cpe in cpes:
                        if not cpe or not cpe.startswith('cpe'):
                            continue
                        vulncpe = self.format_interval_cpe(id,cpe)
                        await self.dbm.add_cpe(Vulncpe(**vulncpe))
                        commit_flag = True
                if commit_flag:
                    await self.dbm.commit()
            except Exception as e:
                logger.error('insert {} to db error: {}'.format(id, e))
                self.dbm.rollback()
        await self.dbm.close()    
        logger.info('Full_vulncpe all subtasks are done.')      
        
async def run():
    full_vul = Full_Vulncpe()
    await full_vul.full_vnlncpe()


if __name__ == '__main__':
    import asyncio
    asyncio.run(run())
    
    
