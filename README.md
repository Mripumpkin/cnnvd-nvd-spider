# Cnnvd-Nvd parser Project

[TOC]
1. CNNVD开源漏洞XML，但XML文件中存在未编码的字符影响解析，格式化处理XML文件
2. 解析CNNVD的XML文件并入库，如果数据库中有该条漏洞数据(不处理cpe相关的3个字段)，就不入库
3. 使用NVD的漏洞json文件补全CNNVD的XML中缺少的cpe
4. 将cpe与cnnvd表中相同的id相对应
5. CNNVD  XML:url **[cnnvd xml](https://www.cnnvd.org.cn/home/dataDownLoad)**
6. NVD Json:url **[nvd json](https://nvd.nist.gov/vuln/data-feeds)**

## 文件说明
1. spider.py cnnvd和nvd数据爬虫
2. format_xml.py, 格式化处理XML文件中的未编码字符，使其可正常解析
3. cnnvd_parse.py, 解析及同步 cnnvd漏洞库
4. nvd_parse.py, 解析及同步 nvd漏洞库，根据cve编号，从nvd库获取并补齐vrp_cnnvd表中的cpe

## 使用说明
1. 执行python -m main 运行任务
2. config文件可设置计划任务时间
3. 日志在当前目录logs文件下
4. :warning:**cnnvd爬虫需要申请cnnvd账号，账号密码在config.py上设置**
5. :warning:**每次运行前必须备份原数据表(vrp_cnnvd/vrp_vulcpe)**
6. format_xml.py:格式化处理XML文件中的未编码字符，使其可正常解析
7. cnnvd_parse.py:对cnnvd的xml格式文件解析入库、更新
8. nvd_parse.py:对nvd的JSON格式文件cpe解析，对比cnnvd的cve_id后入库、补全
9. :warning:**执行python -m db.create_db 创建数据库**
