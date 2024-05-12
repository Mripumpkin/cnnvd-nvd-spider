#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/09/01
# 导入需要的模块

#cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
#CPE:2.3:类型:厂商:产品:版本:更新版本:发行版本:界面语言:软件发行版本:目标软件:目标硬件:其他

import re
import hashlib
import os
import pickle
import json
import os
import requests
from copy import deepcopy
from pyquery.pyquery import PyQuery
from cnnvd import Cnnvd
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cpe import CPE
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# proxies = {'https': 'http://127.0.0.1:18080'}
proxies = {}

#####配置入库数据库
thorns_pgsql_host = '127.0.0.1'
thorns_pgsql_port = 55432
# ##REMOTE DB
# thorns_pgsql_host = '43.136.96.72'
# thorns_pgsql_port = '28064'
thorns_pgsql_db = 'vrp'
thorns_pgsql_passwd = 'Vrp2P&sd*#2)@1#21'
thorns_pgsql_user = 'postgres'
#########################


def connect_DBSession():
    engine = create_engine("postgresql+psycopg2://%s:%s@%s:%s/%s" % (thorns_pgsql_user, thorns_pgsql_passwd, thorns_pgsql_host, thorns_pgsql_port, thorns_pgsql_db))
    return sessionmaker(bind=engine)


def get_md5(data):
    if isinstance(data, str):
        data = data.encode('utf8')
    return hashlib.md5(data).hexdigest()


def fmtCPE(cpe):
    try:
        if 'cpe:/' in cpe:      #在vrp_cpes中cpe以'cpe:/'存在，从xml获取入库，已经格式化好了
            return cpe.strip(':::').replace('cpe:2.3:','cpe:/')
        elif 'cpe:2.3:' in cpe:     #在NVD_cpes中cpe以'cpe:2.3:'存在，从json文件获取
            return CPE(cpe).as_uri_2_3().strip(':::').replace('cpe:2.3:','cpe:/')
        elif '-->versionstart:' in cpe:
            return  cpe.strip(':::').replace('cpe:2.3:','cpe:/')
        
    except Exception as e:
        print('format {} error:{}'.format(cpe, e))
        import pdb;pdb.set_trace()


def insertCPE2db(DBSession, all_CVE):
    session = DBSession()
    count = 0
    length = len(all_CVE)
    print('start')
    for vul in all_CVE:
        count += 1
        print('insert2db...' + str(count) + '/' + str(length))
        try:
            tmps = session.query(Cnnvd).filter(Cnnvd.cve_id == vul.cve_id).first()
            if not tmps or not vul.vuln_software_list:
                continue
               
            # 格式化两个CPE, 转化成 CPE 2.3 URI（统一资源标识符）
            _NVD_cpes = vul.vuln_software_list if vul.vuln_software_list else []
            for i in deepcopy(_NVD_cpes):
                try:
                    if '*:*:*:*:*:*:*:*' in i:
                        _NVD_cpes.remove(i)
                        _NVD_cpes = get_nvd_cpes(vul.cve_id)
                        if _NVD_cpes:
                            print('额外获取{}的CPE：{}'.format(vul.cve_id, _NVD_cpes))
                except Exception as e:
                    print('获取 {} 额外CPE失败: {}'.format(vul.cve_id, e))
            
            _vrp_cpes = tmps.vuln_software_list.split(',') if tmps.vuln_software_list else []
            vrp_cpes = set()
            NVD_cpes = set()
            for i in _vrp_cpes:
                vrp_cpes.add(fmtCPE(i))
            for i in _NVD_cpes:
                NVD_cpes.add(fmtCPE(i))
            mark1 = vrp_cpes.issubset(NVD_cpes)     # vrp cpe 属于 nvd cpe的子集
            mark2 = NVD_cpes.issubset(vrp_cpes)     # nvd cpe 属于 vrp cpe的子集
            # print('vrp_cpes: {}'.format(vrp_cpes))
            # print('nvd_cpes: {}'.format(NVD_cpes))
            # continue
            if mark1 and mark2:     # nvd和cnnvd的cpe相同
                continue
            elif mark2:
                continue
            elif mark1:             # nvd的cpe包含了cnnvd的cpe，用nvd的cpe覆盖cnnvd的cpe
                tmps.vuln_software_list = ','.join(list(NVD_cpes))
            elif not mark1 and not mark2 and not vrp_cpes:          # 不全等，并且不为空
                tmps.vuln_software_list = ','.join(vrp_cpes.union(NVD_cpes))
            else:
                continue
            session.commit()
            print('update cve:{} cpe is successful'.format(vul.cve_id))
        except Exception as e:
            print(e)
            # print(vul.__dict__)
            # session.rollback()
    session.close()
    return True


def parser_cve(nvd_file):
    all_CVE = []
    with open(nvd_file, 'r+') as f:
        result = json.loads(f.read())               #json.loads将字符串转为Python对象
        CVE_Items = result.get('CVE_Items')
        # print(len(CVE_Items))
        for item in CVE_Items:
            entry = {}
            try:
                cve_id = item['cve']['CVE_data_meta']['ID']         #获取json中的cve
                if not cve_id:
                    continue
                    
                configurations = item.get('configurations')
                nodes = configurations.get('nodes') if configurations.get('nodes') else []
                if not isinstance(nodes, list) or len(nodes) == 0:
                    continue
                    
                cpe_operator = nodes[0].get('operator')         # 取nodes[0]只处理某产品的cpe，不处理使用此产品的中间件/OS的cpe
                if not cpe_operator:
                    continue
                    
                cpes = []
                if cpe_operator.upper() == 'AND':
                    continue
                else:
                    cpe_negate = 'false'                    # 对应原来的逻辑，只处理OR。即命中一条cpe，即认为有漏洞
                    cpe_match = nodes[0].get('cpe_match') if nodes[0].get('cpe_match') else []
                    for i in cpe_match:
                        cpe = i.get('cpe23Uri')
                        cpe_versionstart = i.get('versionStartIncluding')
                        cpe_versionend = i.get('versionEndIncluding')
                        if cpe and cpe_versionstart and cpe_versionend:
                            cpe = cpe.lower()
                            cpetmp = fmtCPE(cpe) + '-->versionstart:' + cpe_versionstart + '-->versionend:' + cpe_versionend
                            cpes.append(cpetmp)
                        elif cpe and not cpe_versionstart and not cpe_versionend:
                            cpe = cpe.lower()
                            cpes.append(cpe)                            
                        
                entry['cve_id'] = cve_id
                entry['cpe_operator'] = cpe_operator
                entry['cpe_negate'] = cpe_negate
                entry['vuln_software_list'] = cpes
            except Exception as e:
                print(e)
            finally:
                if entry:
                    all_CVE.append(Cnnvd(**entry))
    return all_CVE


def params_cache(func):
    cache_path = '{}/.cache'.format(os.getcwd())
    if not os.path.exists(cache_path):
        os.mkdir(cache_path)

    def wrapper(self, *args, **kwargs):
        if isinstance(self, str):
            cache_str = str(func.__name__) + str(self) + str(args) + str(kwargs)
        else:
            cache_str = str(func.__name__) + str(args) + str(kwargs)
        cache_name = get_md5(cache_str)
        cache_data_path = os.path.join(cache_path, cache_name)
        if os.path.exists(cache_data_path):
            with open(cache_data_path, 'rb') as fr:
                data = pickle.load(fr)
            return data
        result = func(self, *args, **kwargs)
        if result:
            with open(cache_data_path, 'wb+') as fw:
                pickle.dump(result, fw)     # TODO Iterator support
            return result
    return wrapper

@params_cache
def get_nvd_cpes(cve_id):
    cpe_result = []
    headers = {
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        'Accpet': '*/*',
    }
    url = 'https://nvd.nist.gov/vuln/detail/{}'.format(cve_id)
    resp = requests.get(url, headers=headers, timeout=15, verify=False, proxies=proxies)
    doc = PyQuery(resp.text, parser='html')
    items = doc('#cveTreeJsonDataHidden')
    for item in items.items():
        vuln_result = item.attr('value')
        if isinstance(vuln_result, str):
            vuln_result = json.loads(vuln_result)
        for result in vuln_result:
            for cpes_list in result['containers'][0]['cpes']:
                for i in cpes_list.get('rangeCpes') or []:
                    cpe = i.get('cpe23Uri')
                    cpe_result.append(str(cpe))
                for i in cpes_list.get('matchCpes') or []:
                    cpe = i.get('cpe23Uri')
                    cpe_result.append(str(cpe))
    return list(set(cpe_result))

if __name__ == '__main__':
    DBSession = connect_DBSession()
    session = DBSession()

    exist_cve = {}
    filter_json = []
    error_json = []
    nvd_json_path = './CPEinfo'
    check_list_json = []
    for i in os.listdir(nvd_json_path):
        if '.json' in i and i not in filter_json and i not in error_json:
            check_list_json.append(i)
    check_list_json = sorted(check_list_json, reverse=True)
    print(check_list_json)
    
    for check in check_list_json:
        yeas = check.rsplit('.', 1)[0].rsplit('-', 1)[1] if re.match(r'\d+', check.rsplit('.', 1)[0].rsplit('-', 1)[1]) else datetime.now().year        #指定分隔符对字符串进行分割并返回一个列表,从字符串最后面开始分割
        for i in session.query(Cnnvd).filter(Cnnvd.cve_id.contains('CVE-{}'.format(yeas))):         #将cnnvd表中有的某年全部的CVE提取到exist_cve
            cve_id = str(i.cve_id)
            if not cve_id or cve_id == 'None':
                continue
            elif exist_cve.get(cve_id):
                print('{} 已经存在'.format(cve_id))
            else:
                # exist_cve[cve_id] = {ii: getattr(i, ii) for ii in dir(i) if ii[:1] != '_'}
                exist_cve[cve_id] = i           # 取cnnvd表中所有cve_id到exist_cve中
            continue
        print('数据库中存在的 CVE-{} 有{}个'.format(yeas, len(exist_cve)))
        try:
            print('parse ', check)
            allcve = parser_cve('{}/{}'.format(nvd_json_path, check))               #将json文件中的cve提取到变量
            count = 0
            for vul in allcve:
                count += 1
                try:
                    cve_id = str(vul.cve_id)
                    if cve_id in exist_cve:
                        tmps = exist_cve.get(cve_id)
                    else:
                        tmps = session.query(Cnnvd).filter(Cnnvd.cve_id == vul.cve_id).first()      #若json中的cve不在exist_cve，到数据库中核实;tmps为ORM操作返回的类对象
                        if not tmps:
                            continue
                            
                    if not vul.vuln_software_list:
                        continue
        
                    # 格式化两个CPE, 转化成 CPE 2.3 URI（统一资源标识符）,josn获得的cpe和nvd查询的相同，暂时不进get_nvd_cpes()
                    _NVD_cpes = vul.vuln_software_list if vul.vuln_software_list else []        #从json文件中获取的cpe
                    for i in _NVD_cpes:
                        try:
                            if '*:*:*:*:*:*:*:*' in i:
                                _NVD_cpes = get_nvd_cpes(vul.cve_id)
                                print(_NVD_cpes)
                                if _NVD_cpes:
                                    print('额外获取{}的CPE：{}'.format(vul.cve_id, _NVD_cpes))
                                    _NVD_cpes = []
                                break
                        except Exception as e:
                            print('获取 {} 额外CPE失败: {}'.format(vul.cve_id, e))
        
                    _vrp_cpes = tmps.vuln_software_list.split(',') if tmps.vuln_software_list else []       #从数据库中获取相同cve_id库中已有的的cpe
                    vrp_cpes = set()            #创建空集合
                    NVD_cpes = set()
                    for i in _vrp_cpes:
                        vrp_cpes.add(fmtCPE(i))
                    for i in _NVD_cpes:
                        NVD_cpes.add(fmtCPE(i))
                    mark1 = vrp_cpes.issubset(NVD_cpes)  # 判断 vrp cpe 属于 nvd cpe的子集
                    mark2 = NVD_cpes.issubset(vrp_cpes)  # 判断 nvd cpe 属于 vrp cpe的子集
                    if mark1 and mark2:  # nvd和cnnvd的cpe相同或都为空集
                        continue
                    elif mark2:
                        continue
                    elif mark1:  # nvd的cpe包含了cnnvd的cpe，用nvd的cpe覆盖cnnvd的cpe
                        tmps.vuln_software_list = ','.join(list(NVD_cpes))
                    elif not mark1 and not mark2 and vrp_cpes and NVD_cpes:  # 不全等，并且都不为空
                        tmps.vuln_software_list = ','.join(vrp_cpes.union(NVD_cpes))        #取vrp_cpes和NVD_cpes并集且去掉重复元素
                    else:
                        continue
                    session.commit()
                    print('update cve:{} cpe is successful .. {}/{}'.format(vul.cve_id, count, len(allcve)))
                except Exception as e:
                    print(e)
                    session.rollback()
        except Exception as e:
            print(e)
        
    session.close()