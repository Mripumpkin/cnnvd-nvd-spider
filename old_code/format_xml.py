#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/31
# 导入需要的模块

import os
import sys
import re
import xml.etree.cElementTree as ET    #解析XML文件

#(?<=<[^>]*>)(.*?)(?=<\/[^>]*>) python re 无法处理任意长度标签的零宽断言

def format_linexml_text(linexml_text):        #处理标签文本特殊字符
    try:
        xml_str = linexml_text[0]
        if not xml_str:
            return ""        
        if '&' in xml_str or '<' in xml_str or '>' in xml_str or '"' in xml_str or "'" in xml_str:
            xml_str = xml_str.replace('&', '&amp;')
            xml_str = xml_str.replace('<', '&lt;')
            xml_str = xml_str.replace('>', '&gt;')
            xml_str = xml_str.replace('"', '&quot;')
            xml_str = xml_str.replace("'", '&apos;')    

        # import pdb;pdb.set_trace()
        return xml_str
    except Exception as e :
        print("format_linexml_text error:{}".format(e))


def format_linexml(line):          #处理每行XML获取标签文本
    try:
        if line and isinstance(line,str) :
            # reg = r'<\/[^>]*>'
            # last_tag = re.findall(reg,line,re.DOTALL)
            first_tag = ''
            start_tag = '<'
            end_tag = '>'
            start_index = line.find(start_tag)
            end_index = line.find(end_tag, start_index + 1)
            if start_index != -1 and end_index != -1:
                first_tag = line[start_index:end_index+1]
            # import pdb;pdb.set_trace()            
            if first_tag in ['<name>','<vuln-descript>','<vuln-solution>','<vuln-id>','<published>','<modified>','<severity>','<vuln-type>','<cve-id>','<source>','<bugtraq-id>']:
                if first_tag == '<name>':
                    pattern = r'(?<=<name>)(.*?)(?=<\/name>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<name>' + encode_match +'</name>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<name></name>'
                        return str(encode_line)
                    
                if first_tag == '<vuln-descript>':
                    pattern = r'(?<=<vuln-descript>)(.*?)(?=<\/vuln-descript>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<vuln-descript>' + encode_match +'</vuln-descript>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<vuln-descript></vuln-descript>'
                        return str(encode_line)                

                if first_tag == '<vuln-solution>':
                    pattern = r'(?<=<vuln-solution>)(.*?)(?=<\/vuln-solution>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<vuln-solution>' + encode_match +'</vuln-solution>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<vuln-solution></vuln-solution>'
                        return str(encode_line)

                if first_tag == '<vuln-id>':
                    pattern = r'(?<=<vuln-id>)(.*?)(?=<\/vuln-id>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<vuln-id>' + encode_match +'</vuln-id>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<vuln-id></vuln-id>'
                        return str(encode_line)
                    
                if first_tag == '<published>':
                    pattern = r'(?<=<published>)(.*?)(?=<\/published>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<published>' + encode_match +'</published>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<published></published>'
                        return str(encode_line)

                if first_tag == '<modified>':
                    pattern = r'(?<=<modified>)(.*?)(?=<\/modified>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<modified>' + encode_match +'</modified>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<modified></modified>'
                        return str(encode_line)
                    
                if first_tag == '<severity>':
                    pattern = r'(?<=<severity>)(.*?)(?=<\/severity>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<severity>' + encode_match +'</severity>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<severity></severity>'
                        return str(encode_line)
                
                if first_tag == '<vuln-type>':
                    pattern = r'(?<=<vuln-type>)(.*?)(?=<\/vuln-type>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<vuln-type>' + encode_match +'</vuln-type>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<vuln-type></vuln-type>'
                        return str(encode_line)
                    
                if first_tag == '<cve-id>':
                    pattern = r'(?<=<cve-id>)(.*?)(?=<\/cve-id>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<cve-id>' + encode_match +'</cve-id>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<cve-id></cve-id>'
                        return str(encode_line)

                if first_tag == '<source>':
                    pattern = r'(?<=<source>)(.*?)(?=<\/source>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<source>' + encode_match +'</source>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<source></source>'
                        return str(encode_line)
                    
                if first_tag == '<bugtraq-id>':
                    pattern = r'(?<=<bugtraq-id>)(.*?)(?=<\/bugtraq-id>)'
                    match = re.findall(pattern,line,re.DOTALL) 
                    if match:
                        encode_match = format_linexml_text(match)
                        encode_line = '<bugtraq-id>' + encode_match +'</bugtraq-id>'
                        return str(encode_line)
                    elif match == '':
                        encode_line = '<bugtraq-id></bugtraq-id>'
                        return str(encode_line)
        else:
            print("format_linexml line error,line: {},{}".format(line,type(line)))
            import pdb;pdb.set_trace()

    except Exception as e:
        print("format_linexml:{}".format(e))


def xmlfile_test(path):             #xml文件格式检测
    count = 0
    tree = ET.parse(path)
    root = tree.getroot()
    while count <= 5 :
        for child in root:
            print(child.tag)
            for k in child:
                print(k.tag,k.text)
                count = count + 1
            # import pdb;pdb.set_trace()


def process_and_generate_xml(input_file, output_file):          #Error.xml读取写入到format.xmdl
    try:
        with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
            for line_tmp in infile:
                line = line_tmp.replace('\n','').strip()
                if line and line in ['<?xml version="1.0" encoding="UTF-8"?>','<cnnvd cnnvd_xml_version="*.*" pub_date="****-**-**" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">','<entry>','</entry>','<other-id>','</other-id>','</cnnvd>','<source></source>','<bugtraq-id></bugtraq-id>','<vuln-solution></vuln-solution>']:                    # 对每一行元素内容进行格式化处理
                    outfile.write(line)
                    # print(line)

                elif line == '':
                    # outfile.write(line)
                    pass

                else:
                    # print(line)
                    encoded_line = format_linexml(line)
                    # print('encoded_line: {}'.format(encoded_line))
                    outfile.write(encoded_line)

    except Exception as e:
        print("process_and_generate_xml error:{}".format(e))
        import pdb;pdb.set_trace()


# for xml_text test   
xml_text = [
    '<vuln-descript>WordPress是WordPress（Wordpress）基金会的一套使用PHP语言开发的博客平台。攻击者可通过</style><script>alert(/XSS-aaa/)</script> 执行客户端代码。</vuln-descript>',
    '<name>WordPress plugin WP Cerber Security, Anti-spam & Malware Scan 安全漏洞</name>',
    '<vuln-id>CNNVD-202301-044</vuln-id>',
    '<published>2023-01->02</published>',
    '<modified>2023-01-10</modified>',
    '<severity>中危</severity>',
    '<source></source>',
    '<bugtraq-id>do<cker>toshiba&</bugtraq-id>'
]


if __name__ == '__main__':

    check_list_xml = []
    format_xml_path = 'xml_bak'                      #需要格式化处理XML文件的文件夹位置
    for i in os.listdir(format_xml_path):            #listdir返回指定的文件夹包含的文件或文件夹的名字的列表
        if '.xml' in i :
            check_list_xml.append(i)                #check_list_xml为所有要解析的xml 
    check_list_xml = sorted(check_list_xml, reverse=True)        #对所选对象排序sorted(iterable, key=None, reverse=False);reverse = True降序,reverse =False升序（默认）
    print(check_list_xml)

    for check in check_list_xml:
        print('format xml {} start'.format(check))
        try:
            input_xml_file = 'xml_bak/'+check
            output_xml_file = 'xml_bak/format_'+check
            process_and_generate_xml(input_xml_file, output_xml_file)                   # 处理并写入新的XML文件
            print('format xml {} finished'.format(check))

        except Exception as e:
            print("format someone xml error:{}".format(e))



    # # xmlline_str test
    # for line in xml_text:
    #     print("init line:{}".format(line))
    #     print(format_linexml(line))
    #     import pdb;pdb.set_trace()
