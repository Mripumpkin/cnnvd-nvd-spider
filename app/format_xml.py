#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/31
# 导入需要的模块ls

import re
import os
from log.log import CustomLogger
from config.config import CNNVD

logger  = CustomLogger(__name__).get_logger()

FIRST_TAG = ['<name>','<vuln-descript>','<vuln-solution>','<vuln-id>','<published>','<modified>','<severity>','<vuln-type>','<cve-id>','<source>','<bugtraq-id>']
LINE_TAG = ['<?xml version="1.0" encoding="UTF-8"?>',
            '<cnnvd cnnvd_xml_version="*.*" pub_date="****-**-**" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
            '<entry>', '</entry>', '<other-id>', '</other-id>', '</cnnvd>','<source></source>', '<bugtraq-id></bugtraq-id>', '<vuln-solution></vuln-solution>']

#(?<=<[^>]*>)(.*?)(?=<\/[^>]*>) python re 无法处理任意长度标签的零宽断言
def format_linexml_text(linexml_text):
    try:
        xml_str = linexml_text[0]
        if not xml_str:
            return ""

        # 替换特殊字符
        xml_str = xml_str.replace('&', '&amp;') \
                         .replace('<', '&lt;') \
                         .replace('>', '&gt;') \
                         .replace('"', '&quot;') \
                         .replace("'", '&apos;')

        return xml_str
    except Exception as e:
        logger.error("format_linexml_text error: %s", e)
        return ""



def format_linexml(line):          #处理每行XML获取标签文本
    
    def format_tag(tag)->str:  
        per_tag = tag[1:-1]
        r_str = f'(?<=<{per_tag}>)(.*?)(?=<\/{per_tag}>)'
        pattern = rf'{r_str}'
        match = re.findall(pattern,line,re.DOTALL) 
        if match:
            encode_match = format_linexml_text(match)
            encode_line = f'<{per_tag}>' + encode_match + f'</{per_tag}>'
            return str(encode_line)
        elif match == '':
            encode_line = f'<{per_tag}></{per_tag}>'
            return str(encode_line)
    
    try:
        if line and isinstance(line,str) :
            first_tag = ''
            start_tag = '<'
            end_tag = '>'
            start_index = line.find(start_tag)
            end_index = line.find(end_tag, start_index + 1)
            if start_index != -1 and end_index != -1:
                first_tag = line[start_index:end_index+1]          
            if first_tag in FIRST_TAG:
                return format_tag(first_tag)            
        else:
            logger.warning("format_linexml line error,line: {},{}".format(line,type(line)))
            import pdb;pdb.set_trace()

    except Exception as e:     
        logger.error("format_linexml:{}".format(e))

async def process_and_generate_xml(file_path):
    try:
        with open(file_path, 'r+', encoding='utf-8') as file:
            lines = file.readlines()  # 读取所有行

            file.seek(0)  # 将文件指针移回文件开头

            for line_tmp in lines:
                line = line_tmp.strip()  # 剔除行尾换行符
                if line in LINE_TAG:
                    file.write(line_tmp)  # 写入包含行尾换行符的行
                elif line == '':
                    pass
                else:
                    encoded_line = format_linexml(line)
                    if encoded_line:
                        file.write('\t' + encoded_line + '\n')
            file.truncate()  # 截断文件，删除多余内容（如果新内容长度小于旧内容长度）
    except Exception as e:
        logger.error(f"Error processing file: {e}")
 
    
async def run():
    dir = CNNVD.save_path
    list_xml = sorted(os.listdir(dir), reverse=True)
    list_xml = sorted([i for i in os.listdir(dir) if i.endswith('.xml')], reverse=True)
    
    async def process_single_xml(check:str):
        check_file = dir + "/" + check
        new_file = dir + "/" + check.split("_new")[0]  + ".xml"
        await process_and_generate_xml(check_file)
        os.rename(check_file,new_file)    
    
    for check in list_xml:
        if "_new" not in check:
            continue
        logger.info(f"格式化文件:{check}")
        await process_single_xml(check=check)
    

if __name__ == '__main__':
    import asyncio    
    asyncio.run(run())




