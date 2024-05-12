
import os


cache_path = f"{os.getcwd()}/.cache"
download_path = f"{os.getcwd()}/download/cnnvd"
nvd_path = f"{os.getcwd()}/download/nvd"

# 创建缓存文件夹
os.makedirs(cache_path, exist_ok=True)

# 创建下载文件夹和其子文件夹
os.makedirs(download_path, exist_ok=True)
os.makedirs(nvd_path, exist_ok=True)
