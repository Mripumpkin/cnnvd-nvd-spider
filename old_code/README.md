# Nvdparser Project

[TOC]

---
1. 23/08/31CNNVD开源漏洞XML，但XML文件中存在未编码的字符影响解析，格式化处理XML文件
2. 解析CNNVD的XML文件并入库，如果数据库中有该条漏洞数据(不处理cpe相关的3个字段)，就不入库
3. 使用NVD的漏洞json文件补全CNNVD的XML中缺少的cpe
4. 将cpe与cnnvd表中相同的id相对应
5. CNNVD  XML下载地址：**[cnnvd xml](https://www.cnnvd.org.cn/home/dataDownLoad)**
6. NVD Json文件下载链接：**[nvd json](https://nvd.nist.gov/vuln/data-feedshttps://nvd.nist.gov/vuln/data-feeds)**

## 文件说明

1. format_xml.py, 格式化处理XML文件中的未编码字符，使其可正常解析
2. parser.py, 同步cnnvd漏洞库
3. fullCPE.py, 根据cve编号，从nvd库获取并补齐vrp_cnnvd表中的cpe
4. full_vulncpe.py, 将cpe与cnnvd表中相同的id相对应，添加对应关系到vrp_vulcpe表中

## 使用说明

1. 下载并解压 **[cnnvd xml](https://www.cnnvd.org.cn/home/dataDownLoad)** 到xml目录。（已开源）
2. 下载 **[nvd json](https://nvd.nist.gov/vuln/data-feedshttps://nvd.nist.gov/vuln/data-feeds)** 数据并解压到CPEinfo目录，CPE与CVE的对应关系（如：https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip）
3. :warning:**每次运行前必须备份原数据表(vrp_cnnvd/vrp_vulcpe)**
`pg_dump -U postgres -d vrp -t vrp_vulcpe -f /var/lib/postgresql/data/tmp/vrp_vulcpe.sql`
`pg_dump -U postgres -d vrp -t vrp_cnnvd -f /var/lib/postgresql/data/tmp/vrp_cnnvd.sql`
4. 格式化处理XML文件中的未编码字符，使其可正常解析，运行 `python3 format_xml.py`
5. 对cnnvd的xml格式文件解析入库、更新：修改parser.py上的数据库配置信息，运行`python3 parser.py`
6. 对nvd的JSON格式文件cpe解析入库、补全：修改fullCPE.py上的数据库配置信息，运行`python3 fullCPE.py`
7. 对vrp_vulncpe表进行补全修改full_vulncpe.py上的数据库配置信息，运行`python3 full_vulncpe.py`（未做重复入库处理）
8. 每次运行时间都比较长，请耐心等待

## 留存问题记录：

1. 此项目只录入数据库中未记录到的cnnvd_id，若cnnvd漏洞编号已经被分配（未公开细节），后续cnnvd进行更新时，无法处理。此项也适用于NVD的cpe补充
2. addPatchinfo.py补充cnnvd漏洞信息，请求方式改变已弃用
3. cnnvd_deduplicate.py去除cnnvdcpe重复项，待研究

## 更新记录 
> - update:2023/09/22
>   - nvd parse增加区间cpe入库 cpe:/a:::-->versionstart:1.1-->versionend:1.9
>   - vrp_vulcpe新增字段处理区间cpe，新增处理区间cpe方法
> - update:2023/09/05
>   - multhread_fullvulncpe.py多线程实现get_cnnvd_cpe/get_vulncpe_cpe，已实现，已更新到full_vulncpe.py  
>   - format_xml.py实现格式化处理XML文件中未编码的字符


## 数据库变动记录
> - :dog:update:2023/09/22
>   - vrp_cnnvd count(*)  **221,405**  |  *440M*
>   - vrp_vulcpe count(*) **45,861,141**  | *3404M*
> - :alien:update:2023/09/06
>   - vrp_cnnvd count(*)  **221,405**  |  *401M*
>   - vrp_vulcpe count(*) **37,931,997**  | *2733M*
> - :cat:update:2023/05/01
>   - vrp_cnnvd count(*)  **210,557**  | *340M*
>   - vrp_vulcpe count(*) **37,596,336**   | *2708M*
>

## Git Log
```
* 851c68d (HEAD -> dev, tag: v2.1.2-rc-20230922, origin/dev) feat✨: 区间cpe解析入库&vrp_vulcpe新增字段
* fc6e4d8 fix🐛: nvd parse缺少区间cpe&nvd/cnnvd cpe比较提交
* da0c2d9 (tag: v2.1.1-rc-20230907) fix🐛: parse 编号撤回入库&update README
* 0d03fe5 fix🐛: parse xml空字段覆盖库中的值&update README
* 615f23e (master) fix🐛: fix func process_vulncpe多线程处理报错
* df5bf4c feat✨: format_xml格式化处理XML&多线程cpe补全
* 5b01d06 init
```
## 数据库操作
```sql
pg_dump -U postgres -d vrp -t vrp_cnnvd -f /var/lib/postgresql/data/tmp/vrp_cnnvd.sql
pg_dump -U postgres -d vrp -t vrp_vulcpe -f /var/lib/postgresql/data/tmp/vrp_vulcpe.sql
cd master/database/main/tmp
psql -U postgres -d vrp < /var/lib/postgresql/data/tmp/vrp_cnnvd.sql
psql -U postgres -d vrp < /var/lib/postgresql/data/tmp/vrp_vulcpe.sql
select pg_size_pretty(pg_total_relation_size('vrp_cnnvd'));
select count(*) from vrp_cnnvd;
SELECT * FROM vrp_cnnvd vc WHERE name LIKE  '%编号%';
SELECT *  FROM vrp_cnnvd vc WHERE name LIKE '%撤%';
TRUNCATE TABLE 用于删除表的数据，但不删除表结构;
DROP TABLE 删除表，但是这个命令会连表的结构一起删除;
```