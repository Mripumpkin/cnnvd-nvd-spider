from app.spider import Spider_Cnnvd,Spider_Nvd
from app.format_xml import run as format_xml
from app.cnnvd_parse import run as cnnvd_parse
from app.nvd_parse import run as nvd_parse
from app.full_vulncpe import run as full_vulncpe
from log.log import CustomLogger
import asyncio

from common.scheuled_tool import ScheduledTask

logger  = CustomLogger(__name__).get_logger()

from config.config import CNNVD,NVD,SCHEDULER_TIME,SCHEDULER_UNIT

# spider:下载cnnvd xml文件和nvd json文件
# format_xm: 格式化cnnvd xml文件
# cnnvd_parse: connvd解析入库
# nvd_parse: 解析nvd，更新cvnnd.cpe
async def task():
    spider_c = Spider_Cnnvd(CNNVD.all_url,CNNVD.login_info,CNNVD.save_path)
    cnnvd_change = await spider_c.download_xml()
    spider_n = Spider_Nvd(NVD.all_url,NVD.save_path)
    nvd_change = await spider_n.download_json()
    if cnnvd_change:
        await format_xml()
        await cnnvd_parse(cnnvd_change)
    if cnnvd_change or nvd_change:
        await nvd_parse(nvd_change)

if __name__ == "__main__":
    import sys
    original_stdout = sys.stdout
    class NullWriter:
        def write(self, text):
            pass
    if 'pro' in sys.argv:
        sys.stdout = NullWriter()
        
    Task = ScheduledTask(task_func=task,interval=SCHEDULER_TIME,unit=SCHEDULER_UNIT["s"])
    asyncio.run(Task.run_schedule())

    # # 最后，恢复原始的标准输出流
    # sys.stdout = original_stdout
    

