import pandas as pd
from io import BytesIO
from . import cnnvd_blue
from flask import Flask, request, jsonify
from db.manager import SqlManager
import os
import datetime
from log.log import CustomLogger

logger = CustomLogger(__name__).get_logger()

DOWNLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), 'download/excel')

@cnnvd_blue.route("/generate", methods=['GET'])
async def generate_excel():
    days = request.args.get("days", default="", type=str)
    create_time = None
    file_name = "all"
    if days:
        file_name = f"before-{days}"
        create_time = datetime.datetime.combine(datetime.datetime.now() - datetime.timedelta(days=int(days)), datetime.time.min)
   
    try:
        dbm = await SqlManager()

        # 获取数据总数
        total_records = await dbm.get_connvd_count(create_time)
        logger.info(f"Excel文件正在生成:{total_records}")
        batch_size = 10000  # 每批处理的记录数
        
        # 文件路径
        excel_file_path = os.path.join(DOWNLOAD_FOLDER, f'cnnvd-nvd-{file_name}.xlsx')
        sheet_name = 'Sheet1'
        start_row = 0

        with pd.ExcelWriter(excel_file_path, engine='openpyxl', mode='w') as writer:
            header_written = False
            for offset in range(0, total_records, batch_size):
                data = await dbm.get_connvd_offset(limit=batch_size, offset_val=offset, create_time=create_time)
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name=sheet_name, startrow=start_row, index=False, header=not header_written)
                start_row += len(df)
                header_written = True

        logger.info("Excel文件生成成功")
        return jsonify({"message": "Excel file generated successfully"}), 200

    except Exception as e:
        logger.error(e)
        return jsonify({"message": "Excel file generation failed!"}), 400

    finally:
        await dbm.close()
