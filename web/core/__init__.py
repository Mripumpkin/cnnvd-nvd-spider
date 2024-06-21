#!usr/bin/env python
# -*- coding:utf-8 _*-
"""
# author: fyh
# time: 2024/5/21
"""

# 导入蓝图
from flask import Blueprint

cnnvd_blue = Blueprint('cnnvd', __name__, url_prefix="/cnnvd", template_folder="templates", static_folder="static")

from . import views
