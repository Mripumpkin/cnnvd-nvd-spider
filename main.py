from app.spider import Spider_Cnnvd,Spider_Nvd
from app.format_xml import run as format_xml
from app.cnnvd_parse import run as cnnvd_parse
from app.nvd_parse import run as nvd_parse
from log.log import CustomLogger
import asyncio

from common.scheuled_tool import ScheduledTask

logger  = CustomLogger(__name__).get_logger()

from config.config import CNNVD,NVD,SCHEDULER_TIME,SCHEDULER_UNIT,env

# spider.py:下载cnnvd xml文件和nvd json文件
# format_xml.py: 格式化cnnvd xml文件
# cnnvd_parse.py: connvd解析入库
# nvd_parse.py: 解析nvd，更新cvnnd.cpe
async def main_task():
    spider_c = Spider_Cnnvd(CNNVD.all_url, CNNVD.login_info, CNNVD.save_path)
    spider_n = Spider_Nvd(NVD.all_url, NVD.save_path)
    
    cnnvd_change_task = asyncio.create_task(spider_c.download_xml())
    nvd_change_task = asyncio.create_task(spider_n.download_json())
    
    cnnvd_change, nvd_change = await asyncio.gather(cnnvd_change_task, nvd_change_task)
    
    if cnnvd_change:
        await format_xml()
        await cnnvd_parse(cnnvd_change)
    
    if nvd_change:
        await nvd_parse(nvd_change)

if __name__ == "__main__":
    import sys
    import time
    start_time = time.time()
    original_stdout = sys.stdout
    class NullWriter:
        def write(self, text):
            pass
    
    if 'pro' in sys.argv or env == "pro":
        sys.stdout = NullWriter()
        Task = ScheduledTask(task_func=main_task, interval=SCHEDULER_TIME, unit=SCHEDULER_UNIT["h"])
        asyncio.run(Task.run_schedule())
    else:
        asyncio.run(main_task())
        
    end_time = time.time()
    run_time = end_time - start_time
    logger.warning(f"总运行时间为:{run_time}秒") 

    

