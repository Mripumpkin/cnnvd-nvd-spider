#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import collections
from cnnvd import Cnnvd
from sqlalchemy import create_engine,orm
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, Integer, Date, Text, SmallInteger
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from parse import get_vuln_severity
from fullCPE import get_nvd_cpes
from fullCPE import fmtCPE
from sqlalchemy import exists
from concurrent.futures import ThreadPoolExecutor

Base = declarative_base()

######配置入库数据库
thorns_pgsql_host = '192.168.1.211'
thorns_pgsql_port = 61002
thorns_pgsql_db = 'vrp'
thorns_pgsql_passwd = '9vjtl0mug4rnz2pb'
thorns_pgsql_user = 'postgres'
#########################

def connect_DBSession():
    engine = create_engine("postgresql+psycopg2://%s:%s@%s:%s/%s" % (thorns_pgsql_user, thorns_pgsql_passwd, thorns_pgsql_host, thorns_pgsql_port, thorns_pgsql_db))
    return sessionmaker(bind=engine)


def get_cnnvd_cpe(offset_val, cnnvd_result):
    try:
        cnnvd_tmp = session.query(Cnnvd).with_entities(Cnnvd.id,Cnnvd.vuln_software_list).order_by(Cnnvd.id.desc()).limit(50000).offset(offset_val).all()       #with_entities查询指定列;with_entities().dintinct()去重
        for i in cnnvd_tmp:     
            cnnvd_id = str(i.id)            #vrp_cnnvd中id
            vuln_software_list = str(i.vuln_software_list)
            if cnnvd_result.get(cnnvd_id):
                print('重复数据: {}'.format(cnnvd_id))
            else:
                cnnvd_result[cnnvd_id] = list(set(vuln_software_list.replace(',CPE', '${%cpe%}cpe').replace(',cpe', '${%cpe%}cpe').split('${%cpe%}')))

        print('query cnnvd the {} done'.format(offset_val))
    except Exception as e:
        print('get vrp_cnnvd cpe error:{}'.format(e))
        import pdb;pdb.set_trace()


def get_vulncpe_cpe(offset_val, vulncpe_result):
    try:
        result = session.query(Vulncpe).order_by(Vulncpe.id.desc()).limit(50000).offset(offset_val).all()
        for i in result:
            id = str(i.id)
            cpe = i.cpe
            if vulncpe_result.get(id):
                vulncpe_result[id].append(cpe)
            else:
                vulncpe_result[id] = [cpe]

        print('query vulncpe the {} done'.format(offset_val))            
    except Exception as e:
        print('get vrp_vulcpe error:{}'.format(e))
        import pdb;pdb.set_trace()


def process_vulncpe(id, cpes, vulncpe_result, count, session):   
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
                    session.add(Vulncpe(**vulncpe))
                    commit_flag = True
        else:
            for cpe in cpes:
                if not cpe or not cpe.startswith('cpe'):
                    continue
                vulncpe = {
                    'id': id,
                    'cpe': cpe
                }
                session.add(Vulncpe(**vulncpe))
                commit_flag = True
        if commit_flag:
            print('insert {} cpe to db ..'.format(id,count,len(cnnvd_result)))
            session.commit()
    except Exception as e:
        print('insert {} to db error: {}'.format(id, e))
        session.rollback()


def format_interval_cpe(id,cpe):
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

class Vulncpe(Base):
    def __init__(self, **entries):
        self.__dict__.update(entries)
    
    __tablename__ = 'vrp_vulcpe'
    id = Column(Integer, primary_key=True)
    cpe = Column(String(255), primary_key=True)
    cpe_versionstart = Column(String(64))         #区间cpe开始版本
    cpe_versionend = Column(String(64))           #区间cpe结束版本
    part = Column(String(16))                     #cpe类型，a：应用，o：操作系统
    vendor = Column(String(255))                   #厂商名
    product = Column(String(255))                  #产品名
    interval = Column(SmallInteger)                 #cpe区间判断，0:否；1:是
    
    

if __name__ == '__main__':
    DBSession = connect_DBSession()
    session = DBSession()

    cnnvd_result, vulncpe_result = collections.OrderedDict(), {}        #对字典对象中元素的排序
    offset_val = 0
    batch_size = 50000
    # 创建线程池
    with ThreadPoolExecutor(max_workers=20) as executor:
        while offset_val <= session.query(func.count(Cnnvd.id)).scalar():
            executor.submit(get_cnnvd_cpe, offset_val, cnnvd_result)
            offset_val += batch_size

        offset_val = 0
        while offset_val <= session.query(func.count(Vulncpe.id)).scalar():
            executor.submit(get_vulncpe_cpe, offset_val, vulncpe_result)
            offset_val += batch_size
    # 所有数据获取任务完成后，继续执行处理任务
    print('#' * 30)
    print(len(cnnvd_result), len(vulncpe_result))       #cnnvd_result->vrp_cnnvd; vulncpe_result->vrp_vulncpe
    print('Fetching data from pgsql_server are done. Next step process vulncpe.')    
    count = 0
    for id, cpes in cnnvd_result.items():           #以列表的形式返回可遍历的元组数组[('a', 1), ('b', 2), ('c', 3)]
        cpes = list(set(cpes))
        count += 1
        commit_flag = False
        try:
            if vulncpe_result.get(id):
                exist_cpes = vulncpe_result.get(id)
                exist_cpes = list(set(exist_cpes))
                for cpe in cpes:
                    if cpe and cpe.startswith('cpe') and cpe not in exist_cpes:     #检查字符串是否是以指定子字符串开头，返回bool值
                        vulncpe = format_interval_cpe(id,cpe)
                        session.add(Vulncpe(**vulncpe))
                        commit_flag = True
            else:
                for cpe in cpes:
                    if not cpe or not cpe.startswith('cpe'):
                        continue
                    vulncpe = format_interval_cpe(id,cpe)
                    session.add(Vulncpe(**vulncpe))
                    commit_flag = True
            if commit_flag:
                print('insert {} cpe to db ..  {}/{}'.format(id, count, len(cnnvd_result)))
                session.commit()
        except Exception as e:
            print('insert {} to db error: {}'.format(id, e))
            session.rollback()
    #TODO:删除cnnvd表里面没有的值
    session.close()    
    print('Full_vulncpe all subtasks are done.')        