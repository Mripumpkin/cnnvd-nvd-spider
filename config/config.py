import os

SCHEDULER_TIME = 1
SCHEDULER_UNIT = {"s":"seconds","m":"minutes","h":"hours","d":"days","w":"weeks","mon":"month"}
SCHEDULER_WEEK = {"m":"monday","tu":"tuesday","w":"wednesday","ts":"thursday","f":"friday","sa":"saturday","su":"sunday"}
SPECIFIC_TIME = "23:30"
TASK_TIME= {"day":25,"hour":0,"minute":0}

CHANGE_CNNVD_LINK_NVD = {"2024年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz", "2023年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz", "2022年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.gz", "2021年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.gz", "2020年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz", "2019年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz", "2018年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz", "2017年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz", "2016年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz", "2015年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz", "2014年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz", "2013年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz", "2012年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz", "2011年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz", "2010年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz", "2009年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz", "2008年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz", "2007年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz", "2006年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz", "2005年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz", "2004年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz", "2003年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz", "2002年":"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz"}

BEFOREJUNE = "before-June"
BEFOREALL = "all"
MONTHUPDATE = "mouth-update"

APP_HOST = "0.0.0.0"
APP_PORT = "8090"

class NVD(object):
    all_url = {
        "base_url": "https://nvd.nist.gov",
        "detail_url": "https://nvd.nist.gov/vuln/detail/",
        "zip_url":"https://nvd.nist.gov/vuln/data-feeds"
    }
    save_path = "./download/nvd"  
class CNNVD(object):
    base_url = "https://www.cnnvd.org.cn/web"
    save_path = "./download/cnnvd"
    all_url = {
        "captcha_url": f"{base_url}/verificationCode/getBase64Image",
        "login_url":   f"{base_url}/login",
        "xml_list_url": f"{base_url}/vulDataDownload/getPageList",
        "download_url":  f"{base_url}/vulDataDownload/download",
    }
    login_info = {
        'username': "",
        'password': "",   
    }

class Config(object):  # 默认配置
    DEBUG = False
    def __getitem__(self, key):
        return self.__getattribute__(key)

class ProductionConfig(Config):  
    PGSQL_SERVER = os.getenv('CVM_PGSQL_SERVER_HOST') or '127.0.0.1'
    PGSQL_PORT = os.getenv('CVM_PGSQL_SERVER_PORT') or '5432'
    PGSQL_USER = os.getenv('CVM_PGSQL_SERVER_USER') or 'postgres'
    PGSQL_DATABASE = os.getenv('CVM_PGSQL_SERVER_DATABASE') or 'vrp'
    PGSQL_PASSWORD = os.getenv('CVM_PGSQL_SERVER_PASSWORD') or ''
    db_config = dict(
        host=PGSQL_SERVER,
        port=PGSQL_PORT,
        user=PGSQL_USER,
        password=PGSQL_PASSWORD,
        database=PGSQL_DATABASE,
    )

    db_config_sqlalchemy = 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
        db_config['user'],
        db_config['password'],
        db_config['host'],
        db_config['port'],
        db_config['database'])


# 数据库配置(开发)
class DevelopmentConfig(Config):
    PGSQL_SERVER = os.getenv('CVM_PGSQL_SERVER_HOST') or '127.0.0.1'
    PGSQL_PORT = os.getenv('CVM_PGSQL_SERVER_PORT') or '5432'


    PGSQL_USER = os.getenv('CVM_PGSQL_SERVER_USER') or ''
    PGSQL_DATABASE = os.getenv('CVM_PGSQL_SERVER_DATABASE') or 'vrp'
    PGSQL_PASSWORD = os.getenv('CVM_PGSQL_SERVER_PASSWORD') or ''
    db_config = dict(
        host=PGSQL_SERVER,
        port=PGSQL_PORT,
        user=PGSQL_USER,
        password=PGSQL_PASSWORD,
        database=PGSQL_DATABASE,
    )

    db_config_sqlalchemy = 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
        db_config['user'],
        db_config['password'],
        db_config['host'],
        db_config['port'],
        db_config['database'])

mapping = {
    'dev': DevelopmentConfig,
    'pro': ProductionConfig,
    'default': ProductionConfig
}

import sys

num = len(sys.argv) -1 
if num < 1 or num > 2:
    env = "pro"
else:
    env = sys.argv[1]  

APP_ENV = os.environ.get('APP_ENV', env).lower()
print(f"采用环境: {APP_ENV} (开发:dev|生产:pro|excel:excel|默认(生产):default)")

if APP_ENV in mapping:
    config = mapping[APP_ENV]()
else:
    config = mapping['pro']()
