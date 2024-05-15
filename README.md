# CNNVD-NVD Spider And Parser 

## CNNVD-NVD 数据爬取及解析
1. CNNVD开源漏洞XML文件，但XML文件中存在未编码的字符影响解析，格式化处理XML文件
2. 解析CNNVD的XML文件并入库，如果数据库中有该条漏洞数据(不处理cpe相关的3个字段)，就不入库
3. 使用NVD的漏洞json文件补全CNNVD的XML中缺少的cpe等其他信息
4. 将NVD与CNNVD通过CVE编号相关联，补全漏洞信息
5. CNNVD XML: **[CNNVD XML](https://www.cnnvd.org.cn/home/dataDownLoad)**
6. NVD JSON: **[NVD JSON](https://nvd.nist.gov/vuln/data-feeds)**

## 文件说明
1. spider.py: 下载CNNVD XML文件和NVD JSON文件
2. format_xml.py: 格式化处理XML文件中的未编码字符，使其可正常解析
3. cnnvd_parse.py: 解析及同步CNNVD漏洞库
4. nvd_parse.py: 解析及同步CNNVD漏洞库，根据CVD编号，从NVD JSON文件获取CPE等相关信息并补齐

## 使用说明
1. :info:**执行python -m main 运行**
2. :info:**config文件可设置计划任务时间**
3. :warning:**数据库选择为为PostgreSQL**
4. :warning:**CNNVD爬虫需要申请CONNVD账号，账号密码在config.py上设置**
5. :warning:**每次运行前必须备份原数据表**
6. :warning:**CNNVD XML文件爬取后，需要格式化处理XML文件中的未编码字符，使CONNVD XML其可正常解析，否则会报错**
7. :warning:**执行python -m db.create_db 创建数据库**
