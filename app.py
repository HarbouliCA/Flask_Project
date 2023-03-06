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

app = Flask(__name__)

# Specify the absolute path to the database file
#database_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False, unique = True)

#with app.app_context():
#    db.create_all()
#    print('created')


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
        raise ValidationError('That username already exists. Please choose a different one.')


class LoginFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Login")




@app.route('/')
def home():
    
    return render_template('index.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginFrom()
    return render_template('login.html', form = form)


@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterFrom()
    return render_template('register.html', form = form)




if __name__ == '__main__':

    app.run(debug=True)
