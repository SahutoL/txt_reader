from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re, os

load_dotenv()
print(os.getenv('DATABASE_URL'))
print(os.environ.get('SECRET_KEY'))
print(os.getcwd())


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('パスワード', validators=[DataRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('パスワード確認', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('登録')

class LoginForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    submit = SubmitField('ログイン')

class UploadForm(FlaskForm):
    file = FileField('ファイル', validators=[DataRequired(), FileAllowed(['txt'], 'テキストファイルのみ！')])
    submit = SubmitField('アップロード')

class EditForm(FlaskForm):
    filename = StringField('ファイル名', validators=[DataRequired()])
    content = TextAreaField('内容', validators=[DataRequired()])
    submit = SubmitField('保存')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('登録が完了しました！ログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('ログインに失敗しました。ユーザー名またはパスワードを確認してください。', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = file.filename
        content = file.read().decode('utf-8')
        new_file = File(filename=filename, content=content, owner=current_user)
        db.session.add(new_file)
        db.session.commit()
        flash('ファイルがアップロードされました！', 'success')
        return redirect(url_for('dashboard'))
    return render_template('upload.html', form=form)

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user:
        abort(403)
    form = EditForm(obj=file)
    if form.validate_on_submit():
        file.filename = form.filename.data
        file.content = form.content.data
        db.session.commit()
        flash('ファイルが更新されました！', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit.html', form=form, file=file)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user:
        abort(403)
    db.session.delete(file)
    db.session.commit()
    flash('ファイルが削除されました！', 'success')
    return redirect(url_for('dashboard'))

def parse_content(content):
    content = re.sub(r'\{([^|]+)\|([^}]+)\}', r'<ruby>\1<rt>\2</rt></ruby>', content)
    content = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', content)
    content = content.replace('\n', '<br>')
    return content

@app.route('/read/<int:file_id>')
@login_required
def read(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user:
        abort(403)
    parsed_content = parse_content(file.content)
    return render_template('read.html', content=parsed_content, file=file)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
