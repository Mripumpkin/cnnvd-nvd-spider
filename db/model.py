#!/usr/bin/env python
#coding:utf-8
from sqlalchemy import Column, String, Integer, Date, Text, SmallInteger,DateTime,Sequence
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.schema import PrimaryKeyConstraint

Base = declarative_base()
class Cnnvd(Base):
    def __init__(self, **entries):
        self.__dict__.update(entries)
    
    __tablename__ = 'knowledge_cnnvd'
    # __tablename__ = 'knowledge_cnnvd'
        
    id = Column(Integer, Sequence('knowledge_cnnvd_id_seq'), primary_key=True)
    uuid = Column(Text)
    cve = Column(String(255))
    cnvd = Column(Text)
    cnnvd = Column(Text)
    title = Column(Text)
    type = Column(String(100))
    solution = Column(Text)
    descript = Column(Text)
    risk_level = Column(String(128))
    source = Column(Text)
    thrtype = Column(Text)
    refs = Column(Text)
    vuln_software_list = Column(Text)
    published = Column(Date)
    modified = Column(Date)
    is_del = Column(Integer, default=0)
    
    
    cvss2 = Column(String(30))
    cvss3 = Column(String(30))
    cwe = Column(String(100))
    cpe = Column(Text)
    cvss2_vector = Column(String(255))
    cvss3_vector = Column(String(255))
    access_impact = Column(String(512))
    
    up_time = Column(DateTime, default=func.now())
    create_time = Column(DateTime, default=func.now())
    
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
