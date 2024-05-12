#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: samsepi0l
# time: 2023/08/10
# 导入需要的模块

import collections
from cnnvd import Cnnvd
from full_vulncpe import Vulncpe, connect_DBSession


if __name__ == '__main__':
    DBSession = connect_DBSession()
    session = DBSession()
    cnnvd_result, vulncpe_result = collections.OrderedDict(), {}

    for i in session.query(Cnnvd).with_entities(Cnnvd.id, Cnnvd.vuln_id, Cnnvd.vuln_software_list).order_by(Cnnvd.id.desc()).all():
        cnnvd_id = str(i.id)
        vuln_software_list = str(i.vuln_software_list)
        if cnnvd_result.get(cnnvd_id):
            print('重复数据: {}'.format(cnnvd_id))
        else:
            cnnvd_result[cnnvd_id] = list(set(vuln_software_list.replace(',cpe', '${%cpe%}cpe').split('${%cpe%}')))
    print('query cnnvd done')

    result = session.query(Vulncpe).all()
    for i in result:
        id = str(i.id)
        cpe = i.cpe
        if vulncpe_result.get(id) and cpe not in vulncpe_result[id]:
            vulncpe_result[id].append(cpe)
        else:
            vulncpe_result[id] = [cpe]
            
    print(len(cnnvd_result), len(vulncpe_result))
    count = 0
    for id, cpes in cnnvd_result.items():
        try:
            commit_flag = False
            if not vulncpe_result.get(id) and len(cpes) != 0:
                # print('{} must be insert'.format(id))
                count += 1
                # for cpe in cpes:
                #     if not cpe:
                #         continue
                #     vulncpe = {
                #         'id': id,
                #         'cpe': cpe
                #     }
                #     session.add(Vulncpe(**vulncpe))
                #     commit_flag = True
                # if commit_flag:
                #     session.commit()
        except Exception as e:
            print(e)
            session.rollback()
    session.close()
    print(count)
            