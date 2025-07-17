from flask import Flask, request, redirect, session, send_from_directory, jsonify, abort
from flask_cors import CORS
import os
import json
import re
import threading
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_2024'
CORS(app)

BASE_DIR = '/storage/emulated/0/Download/users/' #这里默认在这个目录
USER_FILE = os.path.join(BASE_DIR, 'users.json')
os.makedirs(BASE_DIR, exist_ok=True)

FORBIDDEN_FILENAMES = ['users.json', 'app.py', 'config.py', '.env']
EXTENSION_CATEGORIES = {
    '图片': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'],
    '文档': ['.txt', '.md', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
    '视频': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv'],
    '音频': ['.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma'],
    '压缩包': ['.zip', '.rar', '.7z', '.tar', '.gz'],
}
delete_progress = {}

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def init_user_dirs(username):
    user_root = os.path.join(BASE_DIR, username)
    os.makedirs(user_root, exist_ok=True)
    for folder in ['图片', '文档', '视频', '音频', '压缩包', '其他']:
        os.makedirs(os.path.join(user_root, folder), exist_ok=True)

def format_file_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024, 2)}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{round(size_bytes / (1024 * 1024), 2)}MB"
    else:
        return f"{round(size_bytes / (1024 * 1024 * 1024), 2)}GB"

def categorize_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    for category, extensions in EXTENSION_CATEGORIES.items():
        if ext in extensions:
            return category
    return '其他'

def is_admin():
    return session.get('username') == 'shuo'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify(error="未登录"), 401
        return f(*args, **kwargs)
    return decorated

def get_target_user(folder_user=None):
    if is_admin() and folder_user:
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', folder_user):
            abort(400, "用户名非法")
        return folder_user
    if 'username' not in session:
        abort(401, "未登录")
    return session['username']

def validate_user_path(user_dir, target_path):
    try:
        abs_user_dir = os.path.abspath(user_dir)
        abs_target = os.path.abspath(target_path)
        return abs_target.startswith(abs_user_dir)
    except Exception:
        return False

def delete_files_async(paths, task_id):
    total = len(paths)
    completed = 0
    delete_progress[task_id] = {"progress": 0, "status": "running", "message": ""}

    for path in paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    for file in files:
                        os.remove(os.path.join(root, file))
                    for dir in dirs:
                        os.rmdir(os.path.join(root, dir))
                os.rmdir(path)
            completed += 1
            progress = int((completed / total) * 100)
            delete_progress[task_id]["progress"] = progress
        except Exception as e:
            delete_progress[task_id] = {
                "progress": progress,
                "status": "error",
                "message": f"删除失败: {str(e)}"
            }
            return

    delete_progress[task_id] = {
        "progress": 100,
        "status": "finished",
        "message": f"成功删除 {completed}/{total} 个文件"
    }
    threading.Timer(600, lambda: delete_progress.pop(task_id, None)).start()

@app.before_request
def block_sensitive():
    forbidden_files = [os.path.abspath(os.path.join(BASE_DIR, f)) for f in FORBIDDEN_FILENAMES]
    full_path = os.path.abspath(os.path.join(BASE_DIR, request.path.strip('/')))
    if any(full_path == f for f in forbidden_files):
        abort(403, "禁止访问敏感文件")

@app.route('/')
def root():
    if 'username' not in session:
        return redirect('/index.html')  # 登录页面改为 index.html
    return redirect('/home.html')       # 登录成功后的主页

@app.route('/index.html', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return send_from_directory('./', 'index.html')
    data = request.json or request.form
    if not data or not all(k in data for k in ['username', 'password', 'captcha']):
        return jsonify(error="请提供用户名、密码和验证码"), 400

    # 验证验证码
    captcha = data['captcha']
    if not session.get('captcha') or captcha.lower() != session['captcha'].lower():
        return jsonify(error="验证码错误"), 400
    if (datetime.now().timestamp() - session.get('captcha_time', 0)) > 300:  # 5分钟有效期
        return jsonify(error="验证码已过期"), 400

    # 清除验证码
    session.pop('captcha', None)
    session.pop('captcha_time', None)

    users = load_users()
    username = data['username']
    if username in users and users[username] == data['password']:
        session['username'] = username
        return jsonify(message="登录成功")
    return jsonify(error="用户名或密码错误"), 401

@app.route('/current_user')
@login_required
def current_user():
    return jsonify({"username": session['username'], "is_admin": is_admin()})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not all(k in data for k in ['username', 'password', 'captcha']):
        return jsonify(error="请提供用户名、密码和验证码"), 400

    # 验证验证码
    captcha = data['captcha']
    if not session.get('captcha') or captcha.lower() != session['captcha'].lower():
        return jsonify(error="验证码错误"), 400
    if (datetime.now().timestamp() - session.get('captcha_time', 0)) > 300:  # 5分钟有效期
        return jsonify(error="验证码已过期"), 400

    # 清除验证码
    session.pop('captcha', None)
    session.pop('captcha_time', None)

    users = load_users()
    username = data['username']
    if username in users and users[username] == data['password']:
        session['username'] = username
        return jsonify(message="登录成功")
    return jsonify(error="用户名或密码错误"), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or not all(k in data for k in ['username', 'password', 'captcha']):
        return jsonify(error="请提供用户名、密码和验证码"), 400

    # 验证验证码
    captcha = data['captcha']
    if not session.get('captcha') or captcha.lower() != session['captcha'].lower():
        return jsonify(error="验证码错误"), 400
    if (datetime.now().timestamp() - session.get('captcha_time', 0)) > 300:  # 5分钟有效期
        return jsonify(error="验证码已过期"), 400

    # 清除验证码
    session.pop('captcha', None)
    session.pop('captcha_time', None)

    username = data['username']
    password = data['password']
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return jsonify(error="用户名需为3-20位字母、数字或下划线"), 400
    if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password) or not re.search(r'[^a-zA-Z0-9]', password):
        return jsonify(error="密码需含大小写字母、数字、符号，且长度≥8位"), 400
    users = load_users()
    if username in users:
        return jsonify(error="用户名已存在"), 409
    users[username] = password
    save_users(users)
    init_user_dirs(username)
    return jsonify(message="注册成功")

@app.route('/admin/users')
@login_required
def admin_users():
    if not is_admin():
        abort(403, "无权限")
    return jsonify(users=list(load_users().keys()))

@app.route('/admin/user_files/<username>')
@login_required
def admin_user_files(username):
    if not is_admin():
        abort(403, "无权限")
    users = load_users()
    if username not in users:
        abort(404, "用户不存在")
    user_root = os.path.join(BASE_DIR, username)
    files = []
    for root, dirs, filenames in os.walk(user_root):
        rel_root = os.path.relpath(root, user_root)
        for d in dirs:
            files.append({"path": os.path.join(rel_root, d), "is_dir": True, "size": ""})
        for f in filenames:
            if f.lower() in FORBIDDEN_FILENAMES:
                continue
            fpath = os.path.join(root, f)
            files.append({"path": os.path.join(rel_root, f), "is_dir": False, "size": format_file_size(os.path.getsize(fpath))})
    return jsonify(files=files)

@app.route('/category_files')
@login_required
def category_files():
    folder_user = request.args.get('user')
    username = get_target_user(folder_user)
    user_root = os.path.join(BASE_DIR, username)

    categories = {k: [] for k in EXTENSION_CATEGORIES.keys()}
    categories['其他'] = []

    for category in categories.keys():
        category_dir = os.path.join(user_root, category)
        if not os.path.exists(category_dir):
            continue
        for file in os.listdir(category_dir):
            fpath = os.path.join(category_dir, file)
            if os.path.isfile(fpath) and file.lower() not in FORBIDDEN_FILENAMES:
                categories[category].append({
                    "path": os.path.join(category, file),
                    "size": format_file_size(os.path.getsize(fpath))
                })
    return jsonify(categories)

@app.route('/batch_delete', methods=['POST'])
@login_required
def batch_delete():
    data = request.json
    if not data or not data.get('paths'):
        return jsonify(error="请选择要删除的文件"), 400
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_root = os.path.join(BASE_DIR, username)
    paths = [os.path.join(user_root, p) for p in data['paths']]
    for path in paths:
        if not validate_user_path(user_root, path) or not os.path.exists(path):
            return jsonify(error=f"路径非法或不存在: {os.path.relpath(path, user_root)}"), 400
    task_id = f"{username}_{datetime.now().timestamp()}"
    threading.Thread(target=delete_files_async, args=(paths, task_id), daemon=True).start()
    return jsonify(task_id=task_id)

@app.route('/delete_progress/<task_id>')
@login_required
def get_delete_progress(task_id):
    progress = delete_progress.get(task_id, {"progress": 0, "status": "not_found", "message": "任务不存在"})
    return jsonify(progress)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    folder = request.form.get('folder', '').strip('/')
    folder_user = request.form.get('user')
    username = get_target_user(folder_user)
    user_root = os.path.join(BASE_DIR, username)

    # 如果在自定义文件夹中上传，直接保存，不分类
    if folder and folder != '':
        target_dir = os.path.join(user_root, folder)
        if not validate_user_path(user_root, target_dir):
            return jsonify(error="非法路径"), 403
        os.makedirs(target_dir, exist_ok=True)

    uploaded = 0
    files = request.files.getlist('file')
    for file in files:
        if file.filename:
            safe_name = re.sub(r'[\\/:"*?<>|]', '_', file.filename)
            if safe_name.lower() in FORBIDDEN_FILENAMES:
                continue

            if folder and folder != '':
                # 自定义目录，直接保存
                save_path = os.path.join(target_dir, safe_name)
            else:
                # 根目录上传，按扩展名自动分类
                category = categorize_file(safe_name)
                target_dir = os.path.join(user_root, category)
                os.makedirs(target_dir, exist_ok=True)
                save_path = os.path.join(target_dir, safe_name)

            file.save(save_path)
            uploaded += 1
    return jsonify(message=f"成功上传 {uploaded} 个文件")

@app.route('/files/<path:category>')
@login_required
def list_files(category):
    folder_user = request.args.get('user')
    username = get_target_user(folder_user)
    user_root = os.path.join(BASE_DIR, username)
    target_dir = os.path.join(user_root, category)

    if not validate_user_path(user_root, target_dir) or not os.path.exists(target_dir):
        return jsonify([])

    files = []
    for entry in os.scandir(target_dir):
        files.append({
            'name': entry.name,
            'path': os.path.relpath(entry.path, user_root),
            'is_dir': entry.is_dir(),
            'size': format_file_size(entry.stat().st_size) if entry.is_file() else ''
        })
    return jsonify(files)

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    data = request.json
    if not data or not all(k in data for k in ['parent_folder', 'foldername']):
        return jsonify(error="参数缺失"), 400
    parent_folder = data['parent_folder']
    foldername = re.sub(r'[\\/:"*?<>|]', '_', data['foldername'])
    username = get_target_user(data.get('user'))
    user_root = os.path.join(BASE_DIR, username)
    target_path = os.path.join(user_root, parent_folder, foldername)
    if not validate_user_path(user_root, target_path):
        return jsonify(error="非法路径"), 403
    try:
        os.makedirs(target_path, exist_ok=False)
        return jsonify(message="文件夹创建成功")
    except FileExistsError:
        return jsonify(error="文件夹已存在"), 409

@app.route('/create_file', methods=['POST'])
@login_required
def create_file():
    data = request.json
    if not data or not all(k in data for k in ['parent_folder', 'filename']):
        return jsonify(error="参数缺失"), 400
    parent_folder = data['parent_folder']
    filename = re.sub(r'[\\/:"*?<>|]', '_', data['filename'])
    if filename.lower() in FORBIDDEN_FILENAMES:
        return jsonify(error="禁止使用敏感文件名"), 403
    username = get_target_user(data.get('user'))
    user_root = os.path.join(BASE_DIR, username)
    target_path = os.path.join(user_root, parent_folder, filename)
    if not validate_user_path(user_root, target_path):
        return jsonify(error="非法路径"), 403
    if os.path.exists(target_path):
        return jsonify(error="文件已存在"), 409
    with open(target_path, 'w', encoding='utf-8') as f:
        f.write(data.get('content', ''))
    return jsonify(message="文件创建成功")

@app.route('/download/<path:filepath>')
@login_required
def download(filepath):
    username = get_target_user(request.args.get('user'))
    user_root = os.path.join(BASE_DIR, username)
    abs_path = os.path.join(user_root, filepath)
    if not validate_user_path(user_root, abs_path):
        abort(403)
    directory = os.path.dirname(abs_path)
    filename = os.path.basename(abs_path)
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/read_file', methods=['POST'])
@login_required
def read_file():
    data = request.json
    if not data or not all(k in data for k in ['folder', 'filename']):
        return jsonify(error="参数缺失"), 400
    folder = data['folder']
    filename = data['filename']
    if filename.lower() in FORBIDDEN_FILENAMES:
        return jsonify(error="禁止访问敏感文件"), 403
    username = get_target_user(data.get('user'))
    user_root = os.path.join(BASE_DIR, username)
    target_path = os.path.join(user_root, folder, filename)
    if not validate_user_path(user_root, target_path) or not os.path.isfile(target_path):
        return jsonify(error="文件不存在"), 404
    try:
        with open(target_path, 'r', encoding='utf-8') as f:
            return jsonify(content=f.read())
    except UnicodeDecodeError:
        return jsonify(error="无法读取二进制文件"), 400

@app.route('/save_file', methods=['POST'])
@login_required
def save_file():
    data = request.json
    if not data or not all(k in data for k in ['folder', 'filename', 'content']):
        return jsonify(error="参数缺失"), 400
    folder = data['folder']
    filename = data['filename']
    if filename.lower() in FORBIDDEN_FILENAMES:
        return jsonify(error="禁止访问敏感文件"), 403
    content = data['content']
    username = get_target_user(data.get('user'))
    user_root = os.path.join(BASE_DIR, username)
    target_path = os.path.join(user_root, folder, filename)
    if not validate_user_path(user_root, target_path):
        return jsonify(error="非法路径"), 403
    with open(target_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return jsonify(message="保存成功")

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify(message="退出成功")

@app.route('/<path:path>')
def static_file(path):
    if any(f in path for f in FORBIDDEN_FILENAMES):
        abort(403)
    return send_from_directory('./', path)

def get_directory_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except Exception:
                pass
    return total

@app.route('/storage_info')
@login_required
def storage_info():
    username = session['username']
    user_root = os.path.join(BASE_DIR, username)
    used_size_bytes = get_directory_size(user_root)
    total_size_bytes = 250 * 1024 * 1024 * 1024  # 每个用户配额 250GB
    free_size_bytes = total_size_bytes - used_size_bytes
    if free_size_bytes < 0:
        free_size_bytes = 0
    return jsonify({
        'used': format_file_size(used_size_bytes),
        'free': format_file_size(free_size_bytes),
        'total': format_file_size(total_size_bytes)
    })

@app.route('/store_captcha', methods=['POST'])
def store_captcha():
    data = request.json
    if not data or 'captcha' not in data:
        return jsonify(error="请提供验证码"), 400
    session['captcha'] = data['captcha']
    session['captcha_time'] = datetime.now().timestamp()  # 记录生成时间
    return jsonify(message="验证码已存储")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)