#!/usr/bin/env python
#coding:utf-8
from sqlalchemy import Column, String, Integer, Date, Text, SmallInteger
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()

class Cnnvd(Base):
    def __init__(self, **entries):
        self.__dict__.update(entries)
    
    __tablename__ = 'vrp_cnnvd'
    
    # Table structure
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    name = Column(String(255))
    vuln_id = Column(String(64))
    published = Column(Date)
    modified = Column(Date)
    source = Column(Text)
    severity = Column(String(64))
    vuln_type = Column(String(64))
    thrtype = Column(String(64))
    refs = Column(Text)
    vuln_software_list = Column(Text)
    cpe_operator = Column(String(16))
    cpe_negate = Column(String(16))
    cve_id = Column(String(64))
    bugtraq_id = Column(String(64))
    vuln_descript = Column(Text)
    vuln_solution = Column(Text)
    ptag = Column(SmallInteger, default=0)
    stag = Column(SmallInteger)
    exp_id = Column(Integer)
    etag = Column(SmallInteger, default=0)
    exp_type = Column(Text)
    exp_url = Column(Text)
    exp_info = Column(Text)
    createtime = Column(Date)
    
class Vulncpe(Base):
    def __init__(self, **entries):
        self.__dict__.update(entries)
    
    __tablename__ = 'vrp_vulcpe'
    id = Column(Integer, primary_key=True)
    cpe = Column(String(255), primary_key=True)
    cpe_versionstart = Column(String(64))          #区间cpe开始版本
    cpe_versionend = Column(String(64))            #区间cpe结束版本
    part = Column(String(16))                      #cpe类型，a：应用，o：操作系统
    vendor = Column(String(255))                   #厂商名
    product = Column(String(255))                  #产品名
    interval = Column(SmallInteger)                #cpe区间判断，0:否；1:是
