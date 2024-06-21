import pandas as pd
from io import BytesIO
from db.manager import SqlManager
import datetime
import os
from openpyxl import load_workbook
from config.config import BEFOREALL,BEFOREJUNE,MONTHUPDATE
from log.log import CustomLogger
logger  = CustomLogger(__name__).get_logger()

DOWNLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'download/excel')

async def generate_excel(start_time=None,end_time=None,filename=BEFOREALL):
    
    excel_file_path = os.path.join(DOWNLOAD_FOLDER, f'cnnvd-nvd-{filename}.xlsx')
    if filename == BEFOREJUNE and os.path.exists(excel_file_path):
        return
    dbm = await SqlManager()
    count = await dbm.get_connvd_count(start_time,end_time)
    batch_size = 10000
    sheet_name = 'Sheet1'
    start_row = 0
    try:
        with pd.ExcelWriter(excel_file_path, engine='openpyxl', mode='w') as writer:
            header_written = False
            for offset in range(0, count, batch_size):
                data = await dbm.get_connvd_offset(limit=batch_size, offset_val=offset, create_time=start_time, end_time=end_time)
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name=sheet_name, startrow=start_row, index=False, header=not header_written)
                start_row += len(df)
                header_written = True
    except Exception as e:
        logger.error(e)

    
    
async def g_excel():
    logger.info("开始生成/更新excel文件")
    today = datetime.date.today()
    last_month = today.replace(day=25) - datetime.timedelta(days=25)
    this_month = today.replace(day=25)
    create_time_start = datetime.datetime.combine(last_month, datetime.time.min)
    create_time_end = datetime.datetime.combine(this_month, datetime.time.max)
    
    before_june_month = datetime.datetime(2024, 6, 1)
    june_end = before_june_month.replace(day=25, hour=23, minute=59, second=59, microsecond=999999)
    await generate_excel()
    await generate_excel(end_time=june_end,filename=BEFOREJUNE)
    await generate_excel(create_time_start,create_time_end,MONTHUPDATE)
    logger.info("excel文件生成/更新完成")