#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
from sqlalchemy import create_engine
from sqlalchemy_utils import create_database, database_exists
from log.log import CustomLogger 
from config.config import config
from .model import Base

logger  = CustomLogger(__name__).get_logger()

# 连接到数据库引擎
def connect_to_database(url):
    engine = create_engine(
        url,
        echo=True
    )
    return engine

# 创建表格
def create_tables(engine):
    Base.metadata.create_all(engine)
    print("数据库表格已成功创建")
    
def creat_base():
    try:
        engine = connect_to_database(config.db_config_sqlalchemy)
        
        if not database_exists(engine.url):
            create_database(engine.url)
            logger.warning("数据库创建成功")
        else:
            logger.warning("数据库已存在")
        
        # 创建表格
        create_tables(engine)
    except Exception as e:
        logger.error(f"数据库创建异常：{e}")
        return

if __name__ == "__main__":  
    creat_base()
