import os
from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
from config import Config

from models import db, User, Post  # 從 models.py 拿 db 以及 User、Post

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)   # 綁定 db 與 app

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # 未登入跳轉頁面
login_manager.login_message_category = 'info'

# 其餘程式碼照原本寫就好...


from models import User, Post

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 允許上傳圖片格式
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('請填寫所有欄位', 'danger')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('密碼不一致', 'danger')
            return redirect(url_for('register'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('帳號已存在', 'danger')
            return redirect(url_for('register'))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('註冊成功，請登入', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('登入成功！', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('登入失敗，請檢查帳號密碼', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('你已登出', 'info')
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def post_create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        file = request.files.get('image')

        if not title or not content:
            flash('標題與內容不可為空', 'danger')
            return redirect(url_for('post_create'))

        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        elif file:
            flash('圖片格式不正確，只允許png/jpg/jpeg/gif', 'danger')
            return redirect(url_for('post_create'))

        post = Post(title=title, content=content, image_file=filename, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('發文成功！', 'success')
        return redirect(url_for('index'))

    return render_template('post_create.html')

if __name__ == '__main__':
    app.run(debug=True)
