import os

SCHEDULER_TIME = 4
SCHEDULER_UNIT = {"s":"seconds","m":"minutes","h":"hours","d":"days","w":"weeks","mon":"months"}
SCHEDULER_WEEK = {"m":"monday","tu":"tuesday","w":"wednesday","ts":"thursday","f":"friday","sa":"saturday","su":"Sunday"}
SPECIFIC_TIME = "11:30"
# 设置要下载的URL和保存路径
class NVD(object):
    all_url = {
        "base_url": "https://nvd.nist.gov",
        "detail_url": "https://nvd.nist.gov/vuln/detail/",
        "zip_url":"https://nvd.nist.gov/vuln/data-feeds"
    }
    save_path = "./download/nvd"  # 设置保存路径

class CNNVD(object):
    # 获取验证码图片的URL
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
    
# 环境映射关系
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
print(f"采用环境: {APP_ENV} (开发:dev|生产:pro|默认(生产):default)")

# django runserver 需要系统参数
if APP_ENV in mapping:
    config = mapping[APP_ENV]()
else:
    config = mapping['pro']()
