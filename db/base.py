#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: ID3055
# database manager模块
import traceback

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from config.config import config
from common.async_tool import Aobject,async_func
from log.log import CustomLogger 

logger  = CustomLogger(__name__).get_logger()

class BaseDBManager(Aobject):
    async def __init__(self, db_config=config.db_config_sqlalchemy):
        self.engine = create_engine(db_config, echo=False, poolclass=NullPool, implicit_returning=False)
        # 创建DBSession类型:
        self.DBSession = sessionmaker(bind=self.engine)
        self.session = self.DBSession()
  
    async def rollback(self):
        await async_func(self.session.rollback)

    async def commit(self):
        await async_func(self.session.commit)

    async def close(self):
        await async_func(self.session.close)

    async def dispose(self):
        try:
            await async_func(self.session.close)
            await async_func(self.engine.dispose)
        except Exception:
            logger.error(f"[SQLALCHEMY] db dispose error: {traceback.format_exc()}")

    async def raw(self, sql, ret=False):
        def run(sql, ret=False):
            res = None
            with self.engine.connect() as conn:
                res_proxy = conn.execute(sql)
                if ret:
                    res = res_proxy.fetchall()
            return res

        return await async_func(run, sql, ret)


if __name__ == '__main__':
    import asyncio
    async def test():
        dbm = await BaseDBManager()
        try:
            result = await dbm.raw("SELECT * FROM vrp_cnnvd", ret=True)
            logger.info("Connection successful!")
            logger.info("Result:", result)
        except Exception as e:
            logger.error("Connection failed:", e)
        finally:
            await dbm.close()
    asyncio.run(test())
