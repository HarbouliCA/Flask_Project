from app import db
from flask import current_app
from wtforms import StringField, SubmitField, BooleanField
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError, NumberRange 
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from email_validator import validate_email, EmailNotValidError
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime
from flask_security import UserMixin
import os
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField
from wtforms.validators import DataRequired
from wtforms.fields import StringField, SubmitField, BooleanField, IntegerField
from datetime import datetime
from flask_bcrypt import generate_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)


app = Flask(__name__)

# Specify the absolute path to the database file
app.root_path = os.path.dirname(os.path.abspath(__file__))
database_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    with app.app_context():
        # add your code that needs the application context here
        # for example, you can add the admin role like this:      
        return User.query.get(int(id))

class Family(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    pere_name = db.Column(db.String(100), nullable=False)
    maman_name = db.Column(db.String(100), nullable=False)
    cin = db.Column(db.String(20), nullable=True)
    Accord_P_Education_parental = db.Column(db.Boolean, default=False, nullable=True)
    Education_Non_Formelle = db.Column(db.Boolean, default=False, nullable=True)
    lutte_contre_Travail_des_enfants = db.Column(db.Boolean, default=False, nullable=True)
    Projet_Sabab_Mutasamih = db.Column(db.Boolean, default=False, nullable=True)
    CIDEAL_Maroc = db.Column(db.Boolean, default=False, nullable=True)
    Attestation_scolaire = db.Column(db.Boolean, default=False, nullable=True)
    Photos = db.Column(db.Boolean, default=False, nullable=True)
    photocopie_CIN_parents = db.Column(db.Boolean, default=False, nullable=True)
    Acte_de_naissance = db.Column(db.Boolean, default=False, nullable=True)
    CIN_du_jeune = db.Column(db.Boolean, default=False, nullable=True)
    children_id = db.Column(db.Integer, db.ForeignKey('children.id'))
    children = db.relationship('Children', backref='family')

class Children(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20), nullable=True)
    sex = db.Column(db.String(10), nullable=False)
    Date_naissance = db.Column(db.Date, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    Quartier = db.Column(db.String(100), nullable=False)
    Adresse = db.Column(db.String(100), nullable=False)
    situation_familliale = db.Column(db.String(100), nullable=True)
    Fonction_pere = db.Column(db.String(100), nullable=True)
    Fonction_mere = db.Column(db.String(100), nullable=True)
    Fraterie = db.Column(db.String(100), nullable=True)
    Problemes_sante = db.Column(db.String(100), nullable=True)
    Niveau_scolaire = db.Column(db.String(100), nullable=True)
    date_arret_etudes = db.Column(db.Date, nullable=True)
    Experience_professionnelle = db.Column(db.String(100), nullable=True)
    Demande = db.Column(db.String(100), nullable=True)
    Insertion_scolaire = db.Column(db.Boolean, default=False, nullable=True)
    Insertion_salariale = db.Column(db.Boolean, default=False, nullable=True)
    Auto_emploi = db.Column(db.Boolean, default=False, nullable=True)
    Entry_date = db.Column(db.Date, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'))



user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))




def hash_password(password):
    hashed_password = generate_password_hash(password).decode('utf-8')
    return hashed_password


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    active= db.Column(db.Boolean, default=True, nullable=False)
    fs_uniquifier = db.Column(db.String(64), unique=True)
    childs = db.relationship('Children', backref='author', lazy=True)
    roles = db.relationship('Role', secondary= user_roles, lazy='joined',
                             backref=db.backref('users', lazy=True))



    def get_id(self):
        return self.id 
    
    def set_password(self, password):
        self.password = hash_password(password)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()
