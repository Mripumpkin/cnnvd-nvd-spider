#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: ID3055
# database manager模块
# 封装了一些常用的数据库操作
# 并读取统一的数据库配置

from db.base import BaseDBManager
from db.model import Cnnvd,Vulncpe
from sqlalchemy.sql import func
from common.async_tool import async_func
from collections.abc import Mapping


class SqlManager(BaseDBManager):
    async def get_cnnvd_vul_by_vulnid(self, vuln_id):
        query = self.session.query(Cnnvd.id,Cnnvd.cve,Cnnvd.title,Cnnvd.type,Cnnvd.risk_level,Cnnvd.descript)
        query = query.filter(Cnnvd.cnnvd == vuln_id)
        
        # 使用 async_func 执行查询并获取结果
        res = await async_func(query.first)
        return res

    async def get_all_vul(self,create_time=None,end_time=None):
        query = self.session.query(Cnnvd.uuid,Cnnvd.cnnvd,Cnnvd.cnvd,Cnnvd.cve,Cnnvd.title,Cnnvd.type,Cnnvd.risk_level,Cnnvd.solution,Cnnvd.refs,Cnnvd.source,Cnnvd.thrtype,Cnnvd.vuln_software_list,Cnnvd.modified,Cnnvd.published,Cnnvd.cvss3,Cnnvd.cwe,Cnnvd.cpe,Cnnvd.cvss3_vector,Cnnvd.cvss2,Cnnvd.cvss2_vector,Cnnvd.access_impact,Cnnvd.descript)
        if create_time:
            query = query.filter(Cnnvd.create_time >= create_time)
        if end_time:
            query = query.filter(Cnnvd.create_time <= end_time)
        res = await async_func(query.all)
        return res
    
    async def count_all_vul(self):
        query = self.session.query(func.count(Cnnvd.id))
        total_rows = await async_func(query.scalar)
        return total_rows

    async def get_vul_chunk(self, chunk_size, offset):
        query = self.session.query(Cnnvd.id, Cnnvd.cve, Cnnvd.title, Cnnvd.type, Cnnvd.risk_level, Cnnvd.descript)
        data = await async_func(query.limit(chunk_size).offset(offset).all)
        return data
    
    async def add_cnnvd_vul(self,data):
        await async_func(self.session.add, data)
        
    async def add_connvd_all_vul(self,all_data):
        await async_func(self.session.bulk_save_objects,all_data)
        
    async def update_connvd_all_vul(self,model:Mapping,all_data:list):
        await async_func(self.session.bulk_update_mappings,model,all_data)

    async def update_cnnvd_vul(self, id, info):
        query = self.session.query(Cnnvd).filter(Cnnvd.id == id)
        await async_func(query.update, info)

    async def get_connvd_count(self,create_time=None,end_time=None):
        query = self.session.query(Cnnvd.id)
        if create_time:
            query = query.filter(Cnnvd.create_time >= create_time)
        if end_time:
            query = query.filter(Cnnvd.create_time <= end_time)
        lines = await async_func(query.count)
        return lines
    
    async def get_contains_value_connvd(self,value):
        query = self.session.query(Cnnvd.id,Cnnvd.cve,Cnnvd.cwe,Cnnvd.cpe,Cnnvd.cvss2,Cnnvd.cvss2_vector,Cnnvd.cvss3,Cnnvd.cvss3_vector,Cnnvd.refs).filter(Cnnvd.cve.contains(value))
        res = await async_func(query.all)
        return res
    
    async def get_connvd_by_cve_id(self,cve_id):
        # 'cpe', 'cve', 'cwe', 'cvss2', 'cvss2_vector', 'cvss3', 'cvss3_vector','refs'
        query = self.session.query(Cnnvd.id,Cnnvd.cve,Cnnvd.cwe,Cnnvd.cpe,Cnnvd.cvss2,Cnnvd.cvss2_vector,Cnnvd.cvss3,Cnnvd.cvss3_vector,Cnnvd.refs).filter(Cnnvd.cve == cve_id)
        res = await async_func(query.first)
        return res
    
    async def get_connvd_offset(self,limit,offset_val,create_time=None,end_time=None):
        query = self.session.query(Cnnvd.uuid,Cnnvd.cnnvd,Cnnvd.cnvd,Cnnvd.cve,Cnnvd.title,Cnnvd.type,Cnnvd.risk_level,Cnnvd.solution,Cnnvd.refs,Cnnvd.source,Cnnvd.thrtype,Cnnvd.vuln_software_list,Cnnvd.modified,Cnnvd.published,Cnnvd.cvss2,Cnnvd.cvss3,Cnnvd.cwe,Cnnvd.cpe,Cnnvd.cvss2_vector,Cnnvd.cvss3_vector,Cnnvd.access_impact,Cnnvd.descript)
        if create_time:
            query = query.filter(Cnnvd.create_time >= create_time)
        if end_time:
            query = query.filter(Cnnvd.create_time <= end_time)
        query = query.limit(limit).offset(offset_val)
        res = await async_func(query.all)
        return res
    
    async def get_all_uuid(self):
        query = self.session.query(Cnnvd.uuid)
        res = await async_func(query.all)
        return res

    ######################## cpe ################################
    async def get_cpe_offset(self,limit,offset_val):
        query = self.session.query(Vulncpe.id,Vulncpe.cpe).order_by(Vulncpe.id.desc()).limit(limit).offset(offset_val)
        res = await async_func(query.all)
        return res

    async def cpe_count(self):
        query = self.session.query(func.count(Vulncpe.id))
        res = await async_func(query.scalar)
        return res
    
    async def add_cpe(self,data):
        await async_func(self.session.add, data)
        
    async def update_cpe_by_id(self, id, info):
        query = self.session.query(Vulncpe).filter(Vulncpe.id == id)
        await async_func(query.update, info)