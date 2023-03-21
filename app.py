from flask import current_app, abort
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError, NumberRange 
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from email_validator import validate_email, EmailNotValidError
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime
import os
from flask_bcrypt import Bcrypt, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField
from wtforms.validators import DataRequired
from wtforms.fields import StringField, SubmitField, BooleanField, IntegerField
from datetime import datetime
from flask_bootstrap import Bootstrap
from functools import wraps
import sqlite3
import plotly.graph_objs as go
import plotly.offline as opy

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


from functools import wraps
from flask import abort

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
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

#with app.app_context():
#    db.create_all()
#    print('created')

class AddChildForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    contact = StringField('Contact', validators=[DataRequired()])
    sex = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    birthdate = DateField('Birthdate', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0)])
    quartier = StringField('Quartier', validators=[DataRequired()])
    adresse = StringField('Address', validators=[DataRequired()])
    situation_familliale = StringField('Family situation', validators=[DataRequired()])
    fonction_pere = StringField("Father's profession", validators=[DataRequired()])
    fonction_mere = StringField("Mother's profession", validators=[DataRequired()])
    fraterie = StringField('Number of siblings', validators=[DataRequired()])
    problemes_sante = StringField('Health problems', validators=[DataRequired()])
    niveau_scolaire = StringField('Education level', validators=[DataRequired()])
    date_arret_etudes = DateField('Date stopped studying', validators=[DataRequired()])
    experience_professionnelle = StringField('Work experience', validators=[DataRequired()])
    demande = StringField('Job request', validators=[DataRequired()])
    insertion_scolaire = BooleanField('School insertion')
    insertion_salariale = BooleanField('Work insertion')
    Auto_emploi = BooleanField('Self-employment')
    Entry_date = DateField('Entry_date', validators=[DataRequired()])
    submit = SubmitField('Add Child')

#class PositiveIntegerField(IntegerField):
#    def pre_validate(self, form):
#        if self.data is not None and self.data < 0:
#            raise ValidationError('Age must be a positive integer')
        
@app.route('/add_child', methods=['GET', 'POST'])
@manager_role_required
@login_required
def add_child():
    form = AddChildForm()
    if form.validate_on_submit():
        child = Children(name=form.name.data,
                      contact=form.contact.data,
                      sex=form.sex.data,
                      Date_naissance=form.birthdate.data,
                      age=form.age.data,
                      Quartier=form.quartier.data,
                      Adresse=form.adresse.data,
                      situation_familliale=form.situation_familliale.data,
                      Fonction_pere=form.fonction_pere.data,
                      Fonction_mere=form.fonction_mere.data,
                      Fraterie=form.fraterie.data,
                      Problemes_sante=form.problemes_sante.data,
                      Niveau_scolaire=form.niveau_scolaire.data,
                      date_arret_etudes=form.date_arret_etudes.data,
                      Experience_professionnelle=form.experience_professionnelle.data,
                      Demande=form.demande.data,
                      Insertion_scolaire=form.insertion_scolaire.data,
                      Insertion_salariale=form.insertion_salariale.data,
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
    search_query = request.args.get('q', '')
    birthdate_query = request.args.get('birthdate', '')
    entry_from_query = request.args.get('entry_from', '')
    entry_to_query = request.args.get('entry_to', '')
    
    children_query = Children.query
    
    if search_query:
        children_query = children_query.filter(Children.name.ilike(f'%{search_query}%'))
    
    if birthdate_query:
        birthdate = datetime.strptime(birthdate_query, '%Y-%m-%d').date()
        children_query = children_query.filter(Children.Date_naissance == birthdate)


    if entry_from_query and entry_to_query:
        entry_from_date = datetime.strptime(entry_from_query, '%Y-%m-%d').date()
        entry_to_date = datetime.strptime(entry_to_query, '%Y-%m-%d').date()
        children_query = children_query.filter(Children.Entry_date.between(entry_from_date, entry_to_date))

    
    children = children_query.all()
   
    return render_template('view_children.html', children=children, search_query=search_query, birthdate_query=birthdate_query, entry_from_query=entry_from_query, entry_to_query=entry_to_query)





@app.route('/edit_child/<int:id>', methods=['GET', 'POST'])
@manager_role_required
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
        form.birthdate.data = child.Date_naissance
        form.age.data = child.age
        form.quartier.data = child.Quartier
        form.adresse.data = child.Adresse
        form.situation_familliale.data = child.situation_familliale
        form.fonction_pere.data = child.Fonction_pere
        form.fonction_mere.data = child.Fonction_mere
        form.fraterie.data = child.Fraterie
        form.problemes_sante.data = child.Problemes_sante
        form.niveau_scolaire.data = child.Niveau_scolaire
        form.date_arret_etudes.data = child.date_arret_etudes
        form.experience_professionnelle.data = child.Experience_professionnelle
        form.demande.data = child.Demande
        form.insertion_scolaire.data = child.Insertion_scolaire
        form.insertion_salariale.data = child.Insertion_salariale
        form.Auto_emploi.data = child.Auto_emploi
        form.Entry_date.data = child.Entry_date
        
    return render_template('edit_child.html', form=form, child=child)


@app.route('/delete_child/<int:id>', methods=['POST'])
@manager_role_required
@login_required
def delete_child(id):
    child = Children.query.get(id)
    if child is None:
        flash('Child not found.', 'danger')
        return redirect(url_for('view_children'))

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
            
                (Children.age <= 6, '0-6'),
                (Children.age <= 12, '7-12'),
                (Children.age <= 18, '13-18'),
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
        flash(f'{user.username}. You are logged in')
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
@admin_role_required
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


class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        form.populate_obj(user)
        user.set_password(form.password.data)
        db.session.commit()
        flash('User updated successfully.')
        return redirect('/user_management')
    return render_template('edit_user.html', form=form)

@app.template_filter('hide_password')
def hide_password(password):
    return '*' * len(password)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect('/user_management')

@app.route('/user_management')
def user_management():
    users = User.query.all()
    return render_template('user_management.html', users=users)



class FamilyForm(FlaskForm):
    pere_name = StringField('Father Name', validators=[DataRequired()])
    maman_name = StringField('Mother Name', validators=[DataRequired()])
    cin = StringField('CIN')
    Accord_P_Education_parental = BooleanField('Accord Parental pour l\'Education')
    Education_Non_Formelle = BooleanField('Education Non Formelle')
    lutte_contre_Travail_des_enfants = BooleanField('Lutte contre Travail des enfants')
    Projet_Sabab_Mutasamih = BooleanField('Projet Sabab Mutasamih')
    CIDEAL_Maroc = BooleanField('CIDEAL Maroc')
    Attestation_scolaire = BooleanField('Attestation Scolaire')
    Photos = BooleanField('Photos')
    photocopie_CIN_parents = BooleanField('Photocopie CIN des Parents')
    Acte_de_naissance = BooleanField('Acte de Naissance')
    CIN_du_jeune = BooleanField('CIN du Jeune')

@app.route('/view_family/<int:child_id>')
def view_family(child_id):
    child = Children.query.get_or_404(child_id)
    family = Family.query.filter_by(children_id=child.id).first()
    form = FamilyForm()
    return render_template('view_family.html', child=child, family=family, form=form)

@app.route('/add_family', methods=['GET', 'POST'])
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
                        Attestation_scolaire=form.Attestation_scolaire.data, Photos=form.Photos.data,
                        photocopie_CIN_parents=form.photocopie_CIN_parents.data,
                        Acte_de_naissance=form.Acte_de_naissance.data, CIN_du_jeune=form.CIN_du_jeune.data,
                        children_id=child_id)
        db.session.add(family)
        db.session.commit()
        flash('Your family information has been added!', 'success')
        return redirect(url_for('view_children', child_id=child_id))
    return render_template('add_family.html', title='Add Family Information', form=form)





if __name__ == '__main__':
    
    app.run(debug=True)
