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
# from config.config import config


class SqlManager(BaseDBManager):
    async def get_cnnvd_vul_by_vulnid(self, vuln_id):
        query = self.session.query(Cnnvd)
        query = query.filter(Cnnvd.vuln_id == vuln_id)
        
        # 使用 async_func 执行查询并获取结果
        res = await async_func(query.first)
        return res

    async def add_cnnvd_vul(self,data):
        await async_func(self.session.add, data)


    async def update_cnnvd_vul(self, id, info):
        query = self.session.query(Cnnvd).filter(Cnnvd.id == id)
        await async_func(query.update, info)

    async def get_connvd_count(self):
        _query = self.session.query(Cnnvd.id)
        lines = await async_func(_query.count)
        return lines
    
    async def get_contains_value_connvd(self,value):
        query = self.session.query(Cnnvd.id,Cnnvd.cve_id,Cnnvd.vuln_software_list).filter(Cnnvd.cve_id.contains(value))
        res = await async_func(query.all)
        return res
    
    async def get_connvd_by_cve_id(self,id):
        query = self.session.query(Cnnvd.id,Cnnvd.vuln_software_list).filter(Cnnvd.cve_id == id)
        res = await async_func(query.first)
        return res
    
    async def get_connvd_offset(self,limit,offset_val):
        query = self.session.query(Cnnvd.id,Cnnvd.vuln_software_list).order_by(Cnnvd.id.desc()).limit(limit).offset(offset_val)
        res = await async_func(query.all)
        return res
    
    async def connvd_count(self):
        query = self.session.query(func.count(Cnnvd.id))
        res = await async_func(query.scalar)
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