from flask import Flask, request, redirect, session, send_from_directory, jsonify, abort
from flask_cors import CORS
import os
import json
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app)

BASE_DIR = '/storage/7392-1BFD/mycloud'
USER_FILE = os.path.join(BASE_DIR, 'users.json')

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f)

def init_user_dirs(username):
    for folder in ['图片', '文档', '视频', '其他']:
        os.makedirs(os.path.join(BASE_DIR, username, folder), exist_ok=True)

def is_admin():
    return session.get('username') == 'shuo'

def get_target_user(folder_user=None):
    """
    获取操作目录所属用户：
    - 普通用户只能操作自己的目录
    - 管理员可指定任意用户目录，若未指定默认是自己
    """
    if is_admin() and folder_user:
        # 仅允许合法用户名，防止路径穿越
        if not re.match(r'^\w+$', folder_user):
            abort(400, "用户名非法")
        return folder_user
    # 普通用户或未指定时，默认操作当前登录用户
    if 'username' not in session:
        abort(401, "未登录")
    return session['username']

@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/index.html')
    return redirect('/home.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    users = load_users()
    if data['username'] in users and users[data['username']] == data['password']:
        session['username'] = data['username']
        return jsonify(message="登录成功")
    return jsonify(error="用户名或密码错误")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not re.search(r'[A-Z]', data['password']) or not re.search(r'[a-z]', data['password']) \
       or not re.search(r'\d', data['password']) or not re.search(r'[^a-zA-Z0-9]', data['password']):
        return jsonify(error="密码强度不足，需含大写、小写、数字、符号")
    users = load_users()
    if data['username'] in users:
        return jsonify(error="用户名已存在")
    users[data['username']] = data['password']
    save_users(users)
    init_user_dirs(data['username'])
    return jsonify(message="注册成功")

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect('/index.html')
    folder = request.form.get('folder', '其他')
    folder_user = request.form.get('user')  # 管理员指定用户
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    os.makedirs(user_dir, exist_ok=True)
    for file in request.files.getlist('file'):
        file.save(os.path.join(user_dir, file.filename))
    return jsonify(message="上传成功")

@app.route('/delete', methods=['POST'])
def delete():
    if 'username' not in session:
        return redirect('/index.html')
    data = request.json
    folder = data.get('folder', '其他')
    filename = data.get('filename')
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    path = os.path.join(user_dir, filename)
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except Exception:
            return jsonify(error="文件夹必须为空才能删除")
    else:
        os.remove(path)
    return jsonify(message="删除成功")

@app.route('/create_folder', methods=['POST'])
def create_folder():
    if 'username' not in session:
        return redirect('/index.html')
    data = request.json
    folder = data.get('folder', '其他')
    foldername = data.get('foldername')
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder, foldername)
    os.makedirs(user_dir, exist_ok=True)
    return jsonify(message="新建成功")

@app.route('/create_file', methods=['POST'])
def create_file():
    if 'username' not in session:
        return redirect('/index.html')
    data = request.json
    folder = data.get('folder', '其他')
    filename = data.get('filename')
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    path = os.path.join(user_dir, filename)
    open(path, 'w', encoding='utf-8').close()
    return jsonify(message="新建成功")

@app.route('/files/<path:folder>')
def list_files(folder):
    if 'username' not in session:
        return redirect('/index.html')
    folder_user = request.args.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    os.makedirs(user_dir, exist_ok=True)
    files = []
    for name in os.listdir(user_dir):
        path = os.path.join(user_dir, name)
        files.append({
            'name': name,
            'is_dir': os.path.isdir(path),
            'size': f"{round(os.path.getsize(path)/1024,2)}KB" if os.path.isfile(path) else ''
        })
    return jsonify(files)

@app.route('/files')
def all_files():
    if 'username' not in session:
        return redirect('/index.html')
    folder_user = request.args.get('user')
    username = get_target_user(folder_user)
    result = {}
    for cat in ['图片', '文档', '视频', '其他']:
        user_dir = os.path.join(BASE_DIR, username, cat)
        os.makedirs(user_dir, exist_ok=True)
        files = []
        for name in os.listdir(user_dir):
            path = os.path.join(user_dir, name)
            files.append({
                'name': name,
                'is_dir': os.path.isdir(path),
                'size': f"{round(os.path.getsize(path)/1024, 2)}KB" if os.path.isfile(path) else ''
            })
        result[cat] = files
    return jsonify(result)

@app.route('/download/<path:folder>/<filename>')
def download(folder, filename):
    if 'username' not in session:
        return redirect('/index.html')
    folder_user = request.args.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    return send_from_directory(user_dir, filename, as_attachment=True)

@app.route('/read_file', methods=['POST'])
def read_file():
    if 'username' not in session:
        return redirect('/index.html')
    data = request.json
    folder = data.get('folder')
    filename = data.get('filename')
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    target_path = os.path.join(user_dir, filename)
    try:
        with open(target_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify(content=content)
    except Exception as e:
        return jsonify(error=str(e))

@app.route('/save_file', methods=['POST'])
def save_file():
    if 'username' not in session:
        return redirect('/index.html')
    data = request.json
    folder = data.get('folder')
    filename = data.get('filename')
    content = data.get('content')
    folder_user = data.get('user')
    username = get_target_user(folder_user)
    user_dir = os.path.join(BASE_DIR, username, folder)
    target_path = os.path.join(user_dir, filename)
    try:
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify(message="保存成功")
    except Exception as e:
        return jsonify(error=str(e))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify(message="退出成功")

@app.route('/category/<path:subpath>')
def category_page(subpath):
    return send_from_directory('./', 'category.html')

@app.route('/<path:path>')
def static_file(path):
    return send_from_directory('./', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)