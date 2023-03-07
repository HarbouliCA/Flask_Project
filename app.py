from flask import current_app
from wtforms import StringField, SubmitField, BooleanField
from flask import Flask, render_template, request, redirect, url_for, flash
from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from email_validator import validate_email, EmailNotValidError
from flask_wtf.csrf import CSRFProtect
import uuid
from flask_security import UserMixin, RoleMixin
from datetime import datetime
from flask_security import UserMixin
import os
from flask_bcrypt import Bcrypt


app = Flask(__name__)

# Specify the absolute path to the database file
#database_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    with current_app.app_context():
        return User.query.get(id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    active= db.Column(db.Boolean, default=True, nullable=False)
    fs_uniquifier = db.Column(db.String(64), unique=True)

    def get_id(self):
        return self.id 


class RegisterFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")


    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username = username.data).first()
        
        if existing_user_name:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    remember = BooleanField('Remember Me')
                            
    submit = SubmitField("Login")


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginFrom()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember= form.remember.data)
            user.authenticated = True
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterFrom()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html', form = form)


#with app.app_context():
#    db.create_all()
#    print('created')


if __name__ == '__main__':

    app.run(debug=True)
