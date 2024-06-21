from flask import Flask, render_template, send_from_directory
import os
from .core import cnnvd_blue
from log.log import CustomLogger
logger  = CustomLogger(__name__).get_logger()

app = Flask(__name__)
app.register_blueprint(cnnvd_blue)

# 设置下载文件夹路径（相对路径）
DOWNLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(__file__))), 'download')
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/')
def index():
    # 获取下载文件夹下的所有文件和文件夹
    items = os.listdir(DOWNLOAD_FOLDER)
    # 分别保存文件和文件夹的列表
    files = []
    folders = []
    for item in items:
        # 构造完整的路径
        item_path = os.path.join(DOWNLOAD_FOLDER, item)
        if os.path.isdir(item_path):
            folders.append(item)
        else:
            files.append(item)
    return render_template('index.html', files=files, folders=folders)

@app.route('/<folder>')
def open_folder(folder):
    folder_path = os.path.join(app.config['DOWNLOAD_FOLDER'], folder)
    items = os.listdir(folder_path)
    files = []
    folders = []
    for item in items:
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            folders.append(item)
        else:
            files.append(item)
    if folder == "excel":
        custom_sort_order = {'all': 0, 'update': 1, 'june': 2, '7': 3, '30': 4, '60': 5, '90': 6}
        files = sorted(files, key=lambda x: custom_sort_order.get(x.split('-')[-1].split('.')[0].lower(), float('inf')))
    else:
        files.sort()
    return render_template('folder.html', files=files, folders=folders, folder=folder)

@app.route('/download/<path:filename>')
def download_file(filename):
    download_folder = app.config['DOWNLOAD_FOLDER']
    file_path = os.path.join(download_folder, filename)
    if os.path.exists(file_path):
        return send_from_directory(download_folder, filename, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == '__main__':
    app.run("0.0.0.0","8090",debug=True)
