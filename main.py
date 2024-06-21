from app.spider import Spider_Cnnvd,Spider_Nvd
from app.format_xml import run as format_xml
from app.cnnvd_parse import run as cnnvd_parse
from app.nvd_parse import run as nvd_parse
from app.generate_excel import g_excel
from web.run import app
from log.log import CustomLogger
import asyncio

from common.scheuled_tool import ScheduledTask

logger  = CustomLogger(__name__).get_logger()

from config.config import CNNVD,NVD,CHANGE_CNNVD_LINK_NVD,SCHEDULER_TIME,TASK_TIME,SCHEDULER_WEEK,SPECIFIC_TIME,env
from config.config import APP_HOST,APP_PORT
# spider.py:下载cnnvd xml文件和nvd json文件
# format_xml.py: 格式化cnnvd xml文件
# cnnvd_parse.py: connvd解析入库
# nvd_parse.py: 解析nvd，更新cvnnd.cpe
# generate_excel.py: 生成/更新excel文件
async def main_task():
    spider_c = Spider_Cnnvd(CNNVD.all_url, CNNVD.login_info, CNNVD.save_path)
    spider_n = Spider_Nvd(NVD.all_url, NVD.save_path)
    
    cnnvd_change_task = asyncio.create_task(spider_c.download_xml())
    nvd_change_task = asyncio.create_task(spider_n.download_json())
    
    cnnvd_change, nvd_change = await asyncio.gather(cnnvd_change_task, nvd_change_task)
    
    if cnnvd_change:
        await format_xml()
        await cnnvd_parse(cnnvd_change)
    
        for key in cnnvd_change.keys():
            if key in CHANGE_CNNVD_LINK_NVD:
                add_change = CHANGE_CNNVD_LINK_NVD[key]
                if add_change not in nvd_change:
                    nvd_change[add_change] = "change"
    
    if nvd_change:
        await nvd_parse(nvd_change)
    await g_excel()   

if __name__ == "__main__":
    import sys
    import time
    from multiprocessing import Process
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    start_time = time.time()
    original_stdout = sys.stdout
    class NullWriter:
        def write(self, text):
            pass   
        def flush(self):
            pass
        
    if 'pro' in sys.argv or env == "pro":
        def run_flask():
            import logging
            log = logging.getLogger('werkzeug')
            log.disabled = True
            app.run(APP_HOST,APP_PORT,debug=True,use_reloader=False)
        
        def run_main_task():
            sys.stdout = NullWriter()
            scheduler = AsyncIOScheduler()
            scheduler.add_job(main_task, 'cron', day=TASK_TIME["day"], hour=TASK_TIME["hour"], minute=TASK_TIME["minute"])
            scheduler.start()
            logger.warning("Scheduler started, job will run at every 25th of the month at 00:00 AM.")
            try:
                asyncio.get_event_loop().run_forever()
            except (KeyboardInterrupt, SystemExit):
                pass
            
        def run_main_week_task():
            async def main():
                sys.stdout = NullWriter()
                Task = ScheduledTask(task_func=main_task, interval=SCHEDULER_TIME, unit=SCHEDULER_WEEK["su"],spesice_time=SPECIFIC_TIME)
                await asyncio.gather(Task.run_schedule())
            asyncio.run(main())
            
        flask_process = Process(target=run_flask)
        main_task_process = Process(target=run_main_task)
        flask_process.daemon = True
        main_task_process.daemon = True
        main_task_process.start()
        flask_process.start()
        flask_process.join()
        main_task_process.join()
    elif 'dev' in sys.argv:
        asyncio.run(main_task())
    elif 'excel' in sys.argv:
        asyncio.run(g_excel())
        
    end_time = time.time()
    run_time = end_time - start_time
    logger.warning(f"总运行时间为:{run_time}秒") 


    

