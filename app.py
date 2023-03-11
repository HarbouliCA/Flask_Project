from flask import current_app
from wtforms import StringField, SubmitField, BooleanField
from flask import Flask, render_template, request, redirect, url_for, flash
<<<<<<< HEAD
=======
from flask import Flask, render_template, redirect, url_for
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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
<<<<<<< HEAD
=======
from flask_security import UserMixin, RoleMixin
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
from datetime import datetime
from flask_security import UserMixin
import os
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField
from wtforms.validators import DataRequired
from wtforms.fields import StringField, SubmitField, BooleanField, IntegerField
from datetime import datetime

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
<<<<<<< HEAD
    with app.app_context():
        # add your code that needs the application context here
        # for example, you can add the admin role like this:      
        return User.query.get(int(id))

=======
    with current_app.app_context():
        return User.query.get(id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    active= db.Column(db.Boolean, default=True, nullable=False)
    fs_uniquifier = db.Column(db.String(64), unique=True)
    childs = db.relationship('Children', backref='author', lazy=True)

    def get_id(self):
        return self.id 
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f


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
<<<<<<< HEAD
    parent = db.relationship('User', backref=db.backref('children', lazy=True))

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

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

=======
    

>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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

class PositiveIntegerField(IntegerField):
    def pre_validate(self, form):
        if self.data is not None and self.data < 0:
            raise ValidationError('Age must be a positive integer')
        
@app.route('/add_child', methods=['GET', 'POST'])
<<<<<<< HEAD
@manager_role_required
=======
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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
<<<<<<< HEAD

        user = User.query.get(current_user.id)
        user.childs.append(child)
        db.session.commit()

        flash('Child added successfully', 'success')
        return redirect(url_for('view_children'))

=======
        db.session.add(current_user)
        db.session.merge(current_user)
        current_user.childs.append(child)
        db.session.commit()
        flash('Child added successfully', 'success')
        return redirect(url_for('view_children'))
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
    return render_template('add_child.html', form=form)



<<<<<<< HEAD
=======


>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
@app.route('/view_children')
@login_required
def view_children():
    search_query = request.args.get('q', '')
    birthdate_query = request.args.get('birthdate', '')
    entry_from_query = request.args.get('entry_from', '')
    entry_to_query = request.args.get('entry_to', '')
    
<<<<<<< HEAD
    children_query = Children.query
=======
    children_query = Children.query.filter(Children.parent_id == current_user.id)
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
    
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
<<<<<<< HEAD
    
=======
    print(children)  # add this line to print the children data
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
    return render_template('view_children.html', children=children, search_query=search_query, birthdate_query=birthdate_query, entry_from_query=entry_from_query, entry_to_query=entry_to_query)





@app.route('/edit_child/<int:id>', methods=['GET', 'POST'])
<<<<<<< HEAD
@manager_role_required
=======
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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

    return render_template('edit_child.html', form=form, child=child)


@app.route('/delete_child/<int:id>', methods=['POST'])
<<<<<<< HEAD
@manager_role_required
=======
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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
<<<<<<< HEAD
    username = current_user.username
    return render_template('dashboard.html', user=username)
=======
    return render_template('dashboard.html')
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f


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
<<<<<<< HEAD
@admin_role_required
=======
>>>>>>> 64a048947061f5592351f3de926614a733e27f0f
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





if __name__ == '__main__':
    
    app.run(debug=True)
