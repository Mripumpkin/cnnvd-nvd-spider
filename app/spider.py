import requests
import shutil
import io
from datetime import datetime
import os
import re
import gzip
from bs4 import BeautifulSoup
import hashlib
import pickle
import time
from pyquery.pyquery import PyQuery
import base64
import ddddocr
import json
from config.config  import CNNVD,NVD
from log.log import CustomLogger 
from functools import wraps

logger  = CustomLogger(__name__).get_logger()

def get_md5(data):
    if isinstance(data, str):
        data = data.encode('utf8')
    return hashlib.md5(data).hexdigest()

def retry(func):
    max_attempts=3
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        attempts = 0
        while attempts < max_attempts:
            try:
                result = func(self, *args, **kwargs)
                return result
            except Exception as e:
                logger.warning(f"{e}，剩余尝试次数{max_attempts-attempts-1}")
                attempts += 1
                time.sleep(2)
        logger.error("获取失败，已达到最大尝试次数")
    return wrapper

#爬虫本地缓存
def params_cache(func):
    cache_path = '{}/.cache'.format(os.getcwd())
    if not os.path.exists(cache_path):
        os.mkdir(cache_path)
    
    @wraps(func)
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

class CustomError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class Spider_Cnnvd(): 
    def __init__(self,all_url:dict,login_info:dict,save_path:str):
        self.captcha_url = all_url["captcha_url"]
        self.login_url = all_url["login_url"]
        self.download_url = all_url["download_url"]
        self.xml_list_url = all_url["xml_list_url"]
        self.session = requests.Session()
        self.username = login_info['username']
        self.password = login_info['password']
        self.headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
        }
        self.Token = ""
        self.download_file_info = {}
        self.save_path = save_path

    # 发送GET请求获取验证码图片的Base64编码
    @retry
    def get_captcha(self):
        try:
            ocr = ddddocr.DdddOcr()
            response =  self.session.get(url=self.captcha_url,headers=self.headers)
            if response.status_code == 200:
                captcha_info = response.json()
                if captcha_info["code"] != 200:
                    massage = captcha_info["massage"]
                    raise CustomError(f"Cnnvd获取验证码图片失败:{massage}")
                    
                captcha = captcha_info["data"]
                image_data_base64_cleaned = captcha["image"]
                image_base64 = image_data_base64_cleaned.split(",")[1]
                res = ocr.classification(image_base64)
                if len(res) != 4:
                    raise CustomError(f"Cnnvd验证码解析错误:{res}")
                captcha["captcha_code"] = res
                return captcha
        except Exception as e:
            raise CustomError(f"Cnnvd获取验证码图片失败,状态码:{response.status_code}")
    
    # 将图像保存到本地文件系统
    def save_png(self,image_data,path="image",file_name="image.png"):
        image_data_base64_cleaned = image_data.split(",")[1]
        image_data_decoded = base64.b64decode(image_data_base64_cleaned)
        with open(f'{path}/{file_name}', 'wb') as f:
            f.write(image_data_decoded)
    
    def save_xml(self,xml_data,path="xml",file_name="cnnvd.xml"):
        with open(f'{path}/{file_name}', 'wb') as f:
            f.write(xml_data)
                
    #获取token
    @retry
    def login(self):
        image_data = self.get_captcha()
        data = {
            "username": self.username,
            "password": hashlib.md5(self.password.encode()).hexdigest(),
            "code": image_data['captcha_code'],
            "verifyToken": image_data['verifyToken'],
        }
        response =  self.session.post(url=self.login_url,data=json.dumps(data),headers=self.headers)
        if response.status_code == 200:
            user_Info = response.json()
            if user_Info["code"] != 200:
                massage = user_Info["message"]
                raise CustomError(f"Cnnvd登录失败:{massage}")
            self.Token = user_Info["data"]["token"]
        else:
            raise CustomError(f"Cnnvd登录失败,状态码:{response.status_code}")
    
    def check_file_changes(func):
        
        cache_path = '{}/.cache'.format(os.getcwd())
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)
            
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # 调用原始函数获取新的爬取数据
            func(self, *args, **kwargs)
            # 检查是否存在缓存文件
            cache_file = f"{cache_path}/cnnvd.json"
            if os.path.exists(cache_file):
                new_download_file_info = {}
                with open(cache_file, "r",encoding="utf-8") as f:
                    cached_data = json.load(f)
                del cached_data["当月"]
                for info in self.xml_list_Info["data"]["records"]:
                    new_download_file_info[info["timeName"]] = info
                    if info["timeName"] in cached_data:
                        if cached_data[info["timeName"]]["updateTime"] != info["updateTime"]:
                            self.download_file_info[info["timeName"]] = info
                    else:
                        self.download_file_info[info["timeName"]] = info
                with open(cache_file, "w") as f:
                    json.dump(new_download_file_info, f)
            else:
                for info in self.xml_list_Info["data"]["records"]:
                    self.download_file_info[info["timeName"]] = info
                with open(cache_file, "w",) as f:
                    json.dump(self.download_file_info, f,ensure_ascii=False)
                
        return wrapper
    
    #获取下载文件
    @check_file_changes
    def get_xml_list_info(self):        
        data = {
            "pageIndex": 1,
            "pageSize": 100,
        }
        try:
            response =  self.session.post(url=self.xml_list_url,data=json.dumps(data),headers=self.headers)
            if response.status_code == 200:
                xml_list_Info = response.json()
                if xml_list_Info["code"] != 200:
                    massage = xml_list_Info["message"]
                    raise CustomError(f"获取Cnnvd_xml文件信息失败:{massage}")
                self.xml_list_Info = xml_list_Info
        except Exception as e:
            raise CustomError(f"获取Cnnvd_xml文件信息失败,状态码:{response.status_code}")
        
    async def download_single_xml(self,file_name,download_file_info):
        self.headers["Token"] = self.Token
        data = {
            "downloadFileType": 1,
            "id": download_file_info["id"],
        }
        response = self.session.post(url=self.download_url,data=json.dumps(data),headers=self.headers)
        if response.status_code == 200:
            xml_data = response.content
            self.save_xml(xml_data=xml_data,path=self.save_path, file_name=file_name)
            logger.info(f"CNNVD-XML:{file_name}文件下载完成")
        else:
            try:
                self.login()
                await self.download_single_xml(file_name,download_file_info["id"])
            except Exception as e:
                logger.error(e)
                logger.warning(f"CNNVD-XML:{file_name}文件下载失败")
                
            
    async def download_xml(self):
        try:
            self.get_xml_list_info()
            if not self.download_file_info:
                return self.download_file_info
            self.login()
            for file_name,id in self.download_file_info.items():
                file_name = file_name + "_new.xml"
                await self.download_single_xml(file_name,id)
            return self.download_file_info
        except CustomError as e:
            logger.error(e)
        except Exception as e:
            logger.error(e)
      
    
class Spider_Nvd():
    def __init__(self,all_url:dict,save_path:str):
        self.base_url = all_url["base_url"]
        self.detail_url = all_url["detail_url"]
        self.zip_url = all_url["zip_url"]
        self.save_path = save_path
        self.zip_links = {}
        self.proxies = {}
        self.headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
        }
            
    def check_changes(func):
        cache_path = '{}/.cache'.format(os.getcwd())
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)            
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # 调用原始函数获取新的爬取数据
            func(self, *args, **kwargs)
            # 检查是否存在缓存文件
            to_remve = []
            cache_file = f"{cache_path}/nvd.json"
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                del cached_data["https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"]
                for key,value in self.zip_links.items():
                    if key in cached_data and cached_data[key] == value:
                        to_remve.append(key)
            with open(cache_file, "w") as f:
                json.dump(self.zip_links, f)
            for key in to_remve:
                del self.zip_links[key]
                
        return wrapper

    @retry
    @check_changes
    def get_zip_links(self):
        try:
            response = requests.get(url=self.zip_url, timeout=5, headers=self.headers)
            if response.status_code != 200:
                raise CustomError(f"获取Nvd下载url失败,状态码:{response.status_code}")
            # 解析响应的HTML内容
            soup = BeautifulSoup(response.text, 'html.parser')
            desc_rows = soup.find_all('tr', class_='xml-feed-desc-row')
            for desc_row in desc_rows:
                time_td = desc_row.find_all('td', rowspan='3')
                if len(time_td) > 1:
                    time_str = time_td[1].get_text(strip=True)  
                    value = datetime.strptime(time_str, "%m/%d/%Y; %I:%M:%S %p %z").strftime("%Y%m%d")
                    data_row = desc_row.find_next_sibling('tr', class_='xml-feed-data-row')
                    if data_row:
                        a_tags = data_row.find_all('a')
                        for a_tag in a_tags:
                            if a_tag and 'href' in a_tag.attrs:
                                key = a_tag['href']  
                                if ".xml.gz" not in key and "nvdcpematch" not in key and ".json.zip" not in key:
                                    key = self.base_url + key
                                    self.zip_links[key] = value  
        except Exception as e:
            raise CustomError(f"获取Nvd下载链接url失败:{e}")
    
    #下载json文件并解压
    async def download_json_gz(self,url):
        try:
            file_name = os.path.basename(url).replace('.gz', '')
            # 拼接保存路径
            save_path = os.path.join(self.save_path, file_name)
            response = requests.get(url = url, timeout=5, headers=self.headers)
            if response.status_code == 200:
                gz_content = io.BytesIO(response.content)
                with gzip.open(gz_content, 'rb') as gz_ref:
                    with open(save_path, 'wb') as f:
                        shutil.copyfileobj(gz_ref, f)
            else:
                logger.error(f"Nvd-json文件下载失败,状态码: {response.status_code}")
        except Exception as e:
            logger.error(e)

    #文件重命名
    def rename_file(self):
        timestamp = datetime.now().strftime("%Y%m%d")
        file_or_dir = os.listdir(self.save_path)
        if file_or_dir:  
            old_file_name = self.save_path + "/" + file_or_dir[0]
            new_file_name = f"{timestamp}-{file_or_dir[0]}"
            new_file_path = os.path.join(self.save_path, new_file_name)
            os.rename(old_file_name, new_file_path)
            return new_file_path
        else:
            logger.error("Nvd-json文件不存在")
    
    async def download_json(self):
        try:
            self.get_zip_links()
            for key in self.zip_links:
                await self.download_json_gz(key)
                logger.info(f"Nvd-json文件下载完成:{key}")   
            return self.zip_links  
        except Exception as e:
            logger.error(e)
        
    #获取cpe详细信息     
    @params_cache
    def get_nvd_cpes_detail(self,cve_id):
        cpe_result = []
        url = f'{self.detail_url}/{cve_id}'
        resp = requests.get(url, headers=self.headers, timeout=15, verify=False, proxies=self.proxies)
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

async def run():
    spider_c = Spider_Cnnvd(CNNVD.all_url,CNNVD.login_info,CNNVD.save_path)
    cnnvd_change = await spider_c.download_xml()
    spider_n = Spider_Nvd(NVD.all_url,NVD.save_path)
    nvd_change = await spider_n.download_json()
    logger.warning(cnnvd_change)
    logger.warning(nvd_change)


if __name__ == "__main__":
    import asyncio
    asyncio.run(run())



