from flask import current_app, abort, Response
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin, AnonymousUserMixin
from flask_security import Security, SQLAlchemyUserDatastore, RoleMixin
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError, NumberRange, Optional
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from email_validator import validate_email, EmailNotValidError
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime
from flask_bcrypt import Bcrypt, generate_password_hash
from wtforms import DateField, SelectField, PasswordField, SelectMultipleField, SelectFieldBase
from wtforms.fields import StringField, SubmitField, BooleanField, IntegerField
from flask_bootstrap import Bootstrap
from functools import wraps
import sqlite3
import plotly.graph_objs as go
import plotly.offline as opy
import plotly.express as px
import os
from azure.storage.blob import BlobServiceClient
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import uuid
from flask_wtf.file import FileField
from azure.storage.blob import BlobClient
import csv
import io

app = Flask(__name__)

# Specify the absolute path to the database file
app.root_path = os.path.dirname(os.path.abspath(__file__))
database_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

##


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
    pere_name = db.Column(db.String(100), nullable=True)
    maman_name = db.Column(db.String(100), nullable=True)
    cin = db.Column(db.String(20), nullable=True)
    Accord_P_Education_parental = db.Column(db.Boolean, default=False, nullable=True)
    Education_Non_Formelle = db.Column(db.Boolean, default=False, nullable=True)
    lutte_contre_Travail_des_enfants = db.Column(db.Boolean, default=False, nullable=True)
    Projet_Sabab_Mutasamih = db.Column(db.Boolean, default=False, nullable=True)
    CIDEAL_Maroc = db.Column(db.Boolean, default=False, nullable=True)
    Attestation_scolaire = db.Column(db.String(100), nullable=True)
    Photos = db.Column(db.String(100), nullable=True)
    photocopie_CIN_parents = db.Column(db.String(100), nullable=True)
    Acte_de_naissance = db.Column(db.String(100), nullable=True)
    CIN_du_jeune = db.Column(db.String(100), nullable=True)
    children_id = db.Column(db.Integer, db.ForeignKey('children.id'))
    child = db.relationship('Children', backref='parent_family')
  
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
    family = db.relationship('Family', backref='associated_child', lazy=True, cascade="all, delete-orphan")



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

    def has_roles(self, *roles):
        return any(role in [r.name for r in self.roles] for role in roles)


    def get_id(self):
        return self.id 
    
    def set_password(self, password):
        self.password = hash_password(password)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

def create_roles():
    with app.app_context():
        admin_role = Role(name='admin')
        # create some roles
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin')
            db.session.add(admin_role)

        manager_role = Role.query.filter_by(name='manager').first()
        if not manager_role:
            manager_role = Role(name='manager')
            db.session.add(manager_role)

        basic_role = Role.query.filter_by(name='basic').first()
        if not basic_role:
            basic_role = Role(name='basic')
            db.session.add(basic_role)

        # create a default admin user
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', password=bcrypt.generate_password_hash('password').decode('utf-8'))
            db.session.add(admin_user)

        # add roles to admin user
        if admin_role not in admin_user.roles:
            admin_user.roles.append(admin_role)
        if manager_role not in admin_user.roles:
            admin_user.roles.append(manager_role)
        db.session.commit()

# Register the function to run after the application context is pushed
app.before_first_request(create_roles)


def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if isinstance(current_user, AnonymousUserMixin):
                # user is not logged in, return 401 response
                abort(401)

            if not current_user.has_roles(*roles):
                abort(403)  # HTTP status code for "Forbidden"
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper



# Define a decorator for the admin role
def admin_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'admin' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


# Define a decorator for the manager role
def manager_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'manager' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


# Define a decorator for the basic role
def basic_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'basic' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


#comment


# Register the function to run after the application context is pushed
app.before_first_request(create_roles)


def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if isinstance(current_user, AnonymousUserMixin):
                # user is not logged in, return 401 response
                abort(401)

            if not current_user.has_roles(*roles):
                abort(403)  # HTTP status code for "Forbidden"
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper



# Define a decorator for the admin role
def admin_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'admin' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


# Define a decorator for the manager role
def manager_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'manager' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


# Define a decorator for the basic role
def basic_role_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if 'basic' not in [r.name for r in current_user.roles]:
            return app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


class AddChildForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    contact = StringField('Contact', validators=[Optional()])
    sex = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    Date_naissance = DateField('Birthdate', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0)])
    Quartier = StringField('Quartier', validators=[DataRequired()])
    Adresse = StringField('Address', validators=[DataRequired()])
    situation_familliale = StringField('Family situation', validators=[DataRequired()])
    Fonction_pere = StringField("Father's profession", validators=[DataRequired()])
    Fonction_mere = StringField("Mother's profession", validators=[DataRequired()])
    Fraterie = StringField('Number of siblings', validators=[DataRequired()])
    Problemes_sante = StringField('Health problems', validators=[DataRequired()])
    Niveau_scolaire = StringField('Education level', validators=[DataRequired()])
    date_arret_etudes = DateField('Date stopped studying', validators=[Optional()])
    Experience_professionnelle = StringField('Work experience', validators=[Optional()])
    Demande = StringField('Job request', validators=[DataRequired()])
    Entry_date = DateField('Entry_date', validators=[DataRequired()])
    Insertion_scolaire = BooleanField('School insertion')
    Insertion_salariale = BooleanField('Work insertion')
    Auto_emploi = BooleanField('Self-employment')
    
    submit = SubmitField('Add Child')

       
@app.route('/add_child', methods=['GET', 'POST'])
@role_required('admin', 'manager')
@login_required
def add_child():
    form = AddChildForm()
    if form.validate_on_submit():
        child = Children(name=form.name.data,
                      contact=form.contact.data,
                      sex=form.sex.data,
                      Date_naissance=form.Date_naissance.data,
                      age=form.age.data,
                      Quartier=form.Quartier.data,
                      Adresse=form.Adresse.data,
                      situation_familliale=form.situation_familliale.data,
                      Fonction_pere=form.Fonction_pere.data,
                      Fonction_mere=form.Fonction_mere.data,
                      Fraterie=form.Fraterie.data,
                      Problemes_sante=form.Problemes_sante.data,
                      Niveau_scolaire=form.Niveau_scolaire.data,
                      date_arret_etudes=form.date_arret_etudes.data,
                      Experience_professionnelle=form.Experience_professionnelle.data,
                      Demande=form.Demande.data,
                      Insertion_scolaire=form.Insertion_scolaire.data,
                      Insertion_salariale=form.Insertion_salariale.data,
                      Auto_emploi=form.Auto_emploi.data,
                      Entry_date=form.Entry_date.data)

        user = User.query.get(current_user.id)
        user.childs.append(child)
        db.session.commit()

        flash('Child added successfully', 'success')
        return redirect(url_for('add_family', child_id=child.id))

    return render_template('add_child.html', title='Add Child Information', form=form)



@app.route('/view_children')
@login_required
def view_children():
    search_query = request.args.get('q', '', type=str)
    job_query = request.args.get('job', '', type=str)
    birthdate_query = request.args.get('birthdate', '')
    entry_from_query = request.args.get('entry_from', '')
    entry_to_query = request.args.get('entry_to', '')
    
    children_query = Children.query
    
    if search_query:
        children_query = children_query.filter(Children.name.ilike(f'%{search_query}%'))

    if job_query:
        children_query = children_query.filter(Children.Demande.ilike(f'%{job_query}%'))
    
    if birthdate_query:
        birthdate = datetime.strptime(birthdate_query, '%Y-%m-%d').date()
        children_query = children_query.filter(Children.Date_naissance == birthdate)


    if entry_from_query and entry_to_query:
        entry_from_date = datetime.strptime(entry_from_query, '%Y-%m-%d').date()
        entry_to_date = datetime.strptime(entry_to_query, '%Y-%m-%d').date()
        children_query = children_query.filter(Children.Entry_date.between(entry_from_date, entry_to_date))

    
    children = children_query.all()
   
    return render_template('view_children.html', children=children, search_query=search_query, job_query=job_query, birthdate_query=birthdate_query, entry_from_query=entry_from_query, entry_to_query=entry_to_query)





@app.route('/edit_child/<int:id>', methods=['GET', 'POST'])
@role_required('admin', 'manager')
@login_required
def edit_child(id):
    child = Children.query.get(id)
    if child is None:
        flash('Child not found.', 'danger')
        return redirect(url_for('view_children'))
    
    form = AddChildForm(obj=child)

    if form.validate_on_submit():
        form.populate_obj(child)
        db.session.commit()
        flash('Child updated successfully.', 'success')
        return redirect(url_for('view_children'))
    else:
        # populate form fields with current child data
        form.name.data = child.name
        form.contact.data = child.contact
        form.sex.data = child.sex
        form.Date_naissance.data = child.Date_naissance
        form.age.data = child.age
        form.Quartier.data = child.Quartier
        form.Adresse.data = child.Adresse
        form.situation_familliale.data = child.situation_familliale
        form.Fonction_pere.data = child.Fonction_pere
        form.Fonction_mere.data = child.Fonction_mere
        form.Fraterie.data = child.Fraterie
        form.Problemes_sante.data = child.Problemes_sante
        form.Niveau_scolaire.data = child.Niveau_scolaire
        form.date_arret_etudes.data = child.date_arret_etudes
        form.Experience_professionnelle.data = child.Experience_professionnelle
        form.Demande.data = child.Demande
        form.Insertion_scolaire.data = child.Insertion_scolaire
        form.Insertion_salariale.data = child.Insertion_salariale
        form.Auto_emploi.data = child.Auto_emploi
        form.Entry_date.data = child.Entry_date
        
    return render_template('edit_child.html', form=form, child=child)

@app.route('/delete_child/<int:id>', methods=['POST'])
@role_required('admin', 'manager')
@login_required
def delete_child(id):
    child = Children.query.get(id)
    if child is None:
        flash('Child not found.', 'danger')
        return redirect(url_for('view_children'))

    # Delete files associated with the child from the blob storage
    family = child.family[0]
    for field_name, field in family.__dict__.items():
        if field_name.endswith('_file_path') and field:
            print(field) # add this line to print the value of field
            blob_client = container_client.get_blob_client(field.split('/')[-1])
            print(f"Deleting blob {field.split('/')[-1]}")
            try:
                blob_client.delete_blob()
            except Exception as e:
                print(e)

    # Delete child's files from the blob storage
    for field_name, field in child.__dict__.items():
        if field_name.endswith('_file_path') and field:
            blob_client = container_client.get_blob_client(field.split('/')[-1])
            print(f"Deleting blob {field.split('/')[-1]}")
            try:
                blob_client.delete_blob()
            except Exception as e:
                print(e)

    db.session.delete(child)
    db.session.commit()
    flash('Child deleted successfully.', 'success')
    return redirect(url_for('view_children'))


class RegisterFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    # new field for role selection
    roles = SelectMultipleField('Roles', choices=[], coerce=int)

    def __init__(self, *args, **kwargs):
        super(RegisterFrom, self).__init__(*args, **kwargs)
        self.roles.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username = username.data).first()
        
        if existing_user_name:
            raise ValidationError(
                'That username already exists. Please choose a different one.', 'danger')


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
    # get current user's username
    username = current_user.username
    
    # count number of children by gender
    gender_counts = Children.query.with_entities(Children.sex, db.func.count()).group_by(Children.sex).all()
    
    # count number of children by demande category
    demande_counts = Children.query.with_entities(
        Children.Demande,
        db.func.count()
        ).group_by(Children.Demande).all()
    
    # prepare data for chart
    demande_labels = [result[0] for result in demande_counts]
    demande_counts = [result[1] for result in demande_counts]
    # create Plotly chart
    demande_chart = go.Figure(data=[go.Bar(x=demande_labels, y=demande_counts)])
    demande_chart.update_layout(title='Number of Children by Demande Category',
                            xaxis_title='Demande Category',
                            yaxis_title='Number of Children')
    
    # generate HTML for chart
    demande_chart = opy.plot(demande_chart, auto_open=False, output_type='div')
    
    # count number of children by age group
    age_counts = Children.query.with_entities(
        db.case(
            
                (Children.age <= 16, '0-16'),
                (Children.age <= 12, '17-18'),
                (Children.age > 18, '18+'),
                else_='18+'
        ).label('age_group'),
        db.func.count()
    ).group_by('age_group').all()

    # prepare data for charts
    gender_labels = [result[0].capitalize() for result in gender_counts]
    gender_counts = [result[1] for result in gender_counts]

    age_labels = [result[0] for result in age_counts]
    age_counts = [result[1] for result in age_counts]

    # create Plotly charts
    gender_chart = go.Figure(data=[go.Bar(x=gender_labels, y=gender_counts)])
    gender_chart.update_layout(title='Number of Children by Gender',
                               xaxis_title='Gender',
                               yaxis_title='Number of Children')

    age_chart = go.Figure(data=[go.Bar(x=age_labels, y=age_counts)])
    age_chart.update_layout(title='Number of Children by Age Group',
                             xaxis_title='Age Group',
                             yaxis_title='Number of Children')
  

    # count number of children by school insertion, work insertion, and self-employment
    school_counts = Children.query.filter_by(Insertion_scolaire=True).count()
    work_counts = Children.query.filter_by(Insertion_salariale=True).count()
    self_employment_counts = Children.query.filter_by(Auto_emploi=True).count()

    request_labels = ['School Insertion', 'Work Insertion', 'Self-Employment']
    request_counts = [school_counts, work_counts, self_employment_counts]

    request_chart = go.Figure(data=[go.Bar(x=request_labels, y=request_counts)])
    request_chart.update_layout(title='Number of Children by Request Type',
                                 xaxis_title='Request Type',
                                 yaxis_title='Number of Children')

 # generate HTML for charts
    gender_chart = opy.plot(gender_chart, auto_open=False, output_type='div')
    age_chart = opy.plot(age_chart, auto_open=False, output_type='div')
    request_chart = opy.plot(request_chart, auto_open=False, output_type='div')

    # pass charts and user to template
    return render_template('dashboard.html',
                           gender_chart=gender_chart,
                           age_chart=age_chart,
                           demande_chart=demande_chart,
                           request_chart = request_chart,
                           user=username)


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



@app.route('/register', methods=['GET', 'POST'])
@role_required('admin')
def register():
    form = RegisterFrom()
    if form.validate_on_submit():
        hashed_password = hash_password(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)

        # Assign selected roles to the new user
        selected_role_ids = form.roles.data
        selected_roles = Role.query.filter(Role.id.in_(selected_role_ids)).all()
        new_user.roles.extend(selected_roles)

        db.session.add(new_user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)



class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    roles = SelectField('Role', coerce=int)
    submit = SubmitField('Save Changes')

    def __init__(self, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        self.roles.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(user_id):
    user = User.query.get(user_id)
    form = EditUserForm(obj=user)

    # Populate roles field with available roles
    roles = [(role.id, role.name) for role in Role.query.all()]
    form.roles.choices = roles  # Change this line

    if form.validate_on_submit():
        # Get the selected role object
        selected_role = Role.query.get(form.roles.data)  # Change this line
        
        # Update the user object
        user.username = form.username.data
        user.set_password(form.password.data)
        user.roles = [selected_role]  # Assign the selected role object to roles
        
        db.session.commit()
        flash('User updated successfully.')
        return redirect('/user_management')
    return render_template('edit_user.html', form=form)



@app.template_filter('hide_password')
def hide_password(password):
    return '*' * len(password)

@app.route('/delete_user/<int:user_id>')
@role_required('admin')
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect('/user_management')

@app.route('/user_management')
@role_required('admin')
def user_management():
    users = User.query.all()
    return render_template('user_management.html', users=users)



class FamilyForm(FlaskForm):
    pere_name = StringField('Pere Name', validators=[Length(max=100)])
    maman_name = StringField('Maman Name', validators=[ Length(max=100)])
    cin = StringField('CIN', validators=[Length(max=20)])
    Accord_P_Education_parental = BooleanField('Accord Parental pour l\'Education')
    Education_Non_Formelle = BooleanField('Education Non Formelle')
    lutte_contre_Travail_des_enfants = BooleanField('Lutte contre Travail des enfants')
    Projet_Sabab_Mutasamih = BooleanField('Projet Shabab Mutasamih')
    CIDEAL_Maroc = BooleanField('CIDEAL Maroc')
    Attestation_scolaire = FileField('Attestation Scolaire')
    Photos = FileField('Photos', default=False)
    photocopie_CIN_parents = FileField('Photocopie CIN des Parents')
    Acte_de_naissance = FileField('Acte de Naissance')
    CIN_du_jeune = FileField('CIN du Jeune')
    submit = SubmitField('Save')


@app.route('/view_family/<int:child_id>')
@login_required
def view_family(child_id):
    child = Children.query.get_or_404(child_id)
    family = Family.query.filter_by(children_id=child.id).first()
    form = FamilyForm()
    return render_template('view_family.html', child=child, family=family, form=form)



####
os.environ['AZURE_CONNECTION_STRING'] = 'INPUT CONNECTION STRING'
connection_string = os.environ['AZURE_CONNECTION_STRING']
blob_service_client = BlobServiceClient.from_connection_string(connection_string)
account_name = 'dplake22'
container_name = 'darnapp'
container_client = blob_service_client.get_container_client(container_name)
# Create a BlobClient object

####


@app.route('/add_family', methods=['GET', 'POST'])
@role_required('admin', 'manager')
@login_required
def add_family():
    child_id = request.args.get('child_id')
    form = FamilyForm()
    if form.validate_on_submit():
        family = Family(pere_name=form.pere_name.data, maman_name=form.maman_name.data, cin=form.cin.data,
                        Accord_P_Education_parental=form.Accord_P_Education_parental.data,
                        Education_Non_Formelle=form.Education_Non_Formelle.data,
                        lutte_contre_Travail_des_enfants=form.lutte_contre_Travail_des_enfants.data,
                        Projet_Sabab_Mutasamih=form.Projet_Sabab_Mutasamih.data, CIDEAL_Maroc=form.CIDEAL_Maroc.data,
                        Attestation_scolaire=None, Photos=None,
                        photocopie_CIN_parents=None, Acte_de_naissance=None, CIN_du_jeune=None,
                        children_id=child_id)

        # Handle file uploads and store file paths in Azure Blob Storage
        for field_name, field in form.data.items():
            if isinstance(field, FileStorage):
                file = field
                if file.filename != '':
                    try:

                        # Delete the old file if it exists
                        if getattr(family, field_name):
                            blob_client = container_client.get_blob_client(getattr(family, field_name).split('/')[-1])
                            blob_client.delete_blob()
                    except:
                        pass

                    # Upload the new file
                    filename = secure_filename(file.filename)
                    blob_client = container_client.get_blob_client(f"{field}/{filename}")
                    blob_client.upload_blob(file, overwrite=True)
                    setattr(family, field_name, f"https://{account_name}.blob.core.windows.net/{container_name}/{field}/{filename}")

        # Save the changes to the database
        db.session.add(family)
        db.session.commit()

        flash('Your family information has been updated!', 'success')
        return redirect(url_for('view_family', child_id=child_id))
    
    return render_template('add_family.html', form=form)


@app.route('/edit_family/<int:child_id>', methods=['GET', 'POST'])
@role_required('admin', 'manager')
@login_required
def edit_family(child_id):
    child = Children.query.get(child_id)
    if child is None:
        flash('Child not found.', 'danger')
        return redirect(url_for('view_family', child_id=child_id))

    family = child.family[0]
    if family is None:
        flash('Family not found.', 'danger')
        return redirect(url_for('view_family', child_id=child_id))

    form = FamilyForm()

    if request.method == 'GET':
        form.process(obj=family)
    if form.validate_on_submit():
        # Handle file uploads and update file paths in Azure Blob Storage
        file_fields = ['Attestation_scolaire', 'Photos', 'photocopie_CIN_parents', 'Acte_de_naissance', 'CIN_du_jeune']
        for field_name in file_fields:
            field = getattr(form, field_name)
            file = field.data
            if file and file.filename != '':
                try:
                    # Delete the old file if it exists
                    if getattr(family, field_name):
                        blob_client = container_client.get_blob_client(getattr(family, field_name).split('/')[-1])
                        blob_client.delete_blob()
                except:
                    pass

                # Upload the new file
                filename = secure_filename(file.filename)
                blob_client = container_client.get_blob_client(f"{field_name}/{filename}")
                blob_client.upload_blob(file, overwrite=True)
                setattr(family, field_name, f"https://{account_name}.blob.core.windows.net/{container_name}/{field_name}/{filename}")

        # Save the changes to the database for other fields
        fields_to_update = [
            'pere_name', 'maman_name', 'cin', 'Accord_P_Education_parental', 'Education_Non_Formelle',
            'lutte_contre_Travail_des_enfants', 'Projet_Sabab_Mutasamih', 'CIDEAL_Maroc'
        ]
        for field_name in fields_to_update:
            setattr(family, field_name, getattr(form, field_name).data)

        db.session.commit()
        flash('Family updated successfully.', 'success')
        return redirect(url_for('view_family', child_id=child_id))


    return render_template('edit_family.html', form=form, family=family, child_id=child_id)



@app.route('/download_children', methods=['GET'])
@login_required
def download_children():
    search_query = request.args.get('q', '', type=str)
    job_query = request.args.get('job', '', type=str)
    birthdate_query = request.args.get('birthdate', '')
    entry_from_query = request.args.get('entry_from', '')
    entry_to_query = request.args.get('entry_to', '')

    # Initialize the query for the children table
    children = db.session.query(Children)

    if search_query:
        children = children.filter(Children.name.ilike(f'%{search_query}%'))

    if job_query:
        children = children.filter(Children.Demande.ilike(f'%{job_query}%'))

    if birthdate_query:
        birthdate_query = datetime.strptime(birthdate_query, '%Y-%m-%d').date()
        children = children.filter(Children.Date_naissance == birthdate_query)

    if entry_from_query and entry_to_query:
        entry_from_query = datetime.strptime(entry_from_query, '%Y-%m-%d').date()
        entry_to_query = datetime.strptime(entry_to_query, '%Y-%m-%d').date()
        children = children.filter(Children.Entry_date.between(entry_from_query, entry_to_query))

    children = children.all()

    def generate():
        data = io.StringIO()
        writer = csv.writer(data)

        # Write the header
        writer.writerow(['Name', 'Contact', 'Sex', 'Birthdate', 'Age', 'Quartier', 'Adresse', 'Family situation', 'Father\'s profession', 'Mother\'s profession', 'Number of siblings', 'Health problems', 'Education level', 'Date stopped studying', 'Work experience', 'Job request', 'School insertion', 'Work insertion', 'Self-employment', 'Entry Date'])
        yield data.getvalue()
        data.seek(0)
        data.truncate(0)

        # Write the data
        for child in children:
            writer.writerow([child.name, child.contact, child.sex, child.Date_naissance, child.age, child.Quartier, child.Adresse, child.situation_familliale, child.Fonction_pere, child.Fonction_mere, child.Fraterie, child.Problemes_sante, child.Niveau_scolaire, child.date_arret_etudes, child.Experience_professionnelle, child.Demande, child.Insertion_scolaire, child.Insertion_salariale, child.Auto_emploi, child.Entry_date])
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)

    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=children.csv'})





if __name__ == '__main__':
    
    app.run(debug=True)
