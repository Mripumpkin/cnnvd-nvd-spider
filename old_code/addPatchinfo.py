#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import urllib.request
import re
import threading
import queue

from bs4 import BeautifulSoup
from cnnvd import Cnnvd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
######配置入库数据库
thorns_pgsql_host = '14.18.28.12'
thorns_pgsql_port = 5432
thorns_pgsql_db = 'vrp'
thorns_pgsql_passwd = 'b7c90975e592c440636957aa70ce60e0'
thorns_pgsql_user = 'cnnvd'
#########################

def connect_DBSession():
    engine = create_engine("postgresql+psycopg2://%s:%s@%s:%s/%s" % (thorns_pgsql_user, thorns_pgsql_passwd, thorns_pgsql_host, thorns_pgsql_port, thorns_pgsql_db))
    return sessionmaker(bind=engine)


class myThread (threading.Thread):
    def __init__(self, q, DBSession, name, queueLock):
        threading.Thread.__init__(self)
        self.q = q
        self.DBSession = DBSession
        self.name = name
        self.queueLock = queueLock

    def run(self):
        session = self.DBSession()
        self.modify(session)
        session.close()
    
    def getPatchinfo(self, vuln_id):
        url = "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=" + vuln_id
        res = urllib.request.urlopen(url, timeout=2).read()
        soup = BeautifulSoup(res,"html.parser",from_encoding="utf-8")
        patchinfo = soup.find('a',href=re.compile(r"/web/xxk/bdxqById.tag\?id"))
        if patchinfo:
            return 'http://cnnvd.org.cn' + patchinfo.attrs.get('href')
        else:
            return ''

    def modify(self, session):
        i = 0
        while not q.empty():
            self.queueLock.acquire()
            vul = q.get()
            self.queueLock.release()
            if not vul.patchinfo:
                try:
                    vul.patchinfo = self.getPatchinfo(vul.vuln_id)
                except:
                    continue
                session.commit()
            print(self.name + ' doing...' + str(i))
            i += 1


if __name__ == '__main__':
        DBSession = connect_DBSession()
        q = queue.Queue()
        session = DBSession()
        queueLock = threading.Lock()
        print("start to add patchinfo...")
        allvul = session.query(Cnnvd).all()
        session.close()
        for vul in allvul:
            q.put(vul)
        threads = []
        try:
            for i in range(30):
                thread = myThread(q, DBSession, i, queueLock)
                thread.start()
                threads.append(thread)
        except Exception as e:
            print(e)
        
