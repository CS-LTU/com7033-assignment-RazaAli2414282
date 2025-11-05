# app.py
"""
Stroke Prediction Web Application
Author: Raza Ali
Description:
This Flask application allows users to register, login, and predict stroke risk
based on demographic, medical history, and lifestyle factors.
"""

from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from config import Config
from pymongo import MongoClient

# Connect to local MongoDB
client = MongoClient('mongodb://localhost:27017/')
db_mongo = client['stroke_app']         # Database
patients_collection = db_mongo['patients']  # Collection


# ----------------- App Initialization -----------------
app = Flask(__name__)
app.config.from_object(Config)  # Load secret key, database URI, etc.

# Initialize database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Redirect unauthorized users to login
login_manager.login_message_category = "info"

# ----------------- Models -----------------
class User(db.Model, UserMixin):
    """
    User model for authentication.
    Fields:
        - username: unique username
        - email: unique email
        - password_hash: hashed password for security
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """Hash and store password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches the hash."""
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login session management."""
    return User.query.get(int(user_id))

# ----------------- Forms -----------------
class RegistrationForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    """Form for user login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StrokeForm(FlaskForm):
    """Form to input patient data for stroke prediction."""
    gender = SelectField('Gender', choices=[('Male','Male'),('Female','Female'),('Other','Other')])
    age = FloatField('Age', validators=[DataRequired()])
    hypertension = SelectField('Hypertension', choices=[('0','No'),('1','Yes')])
    heart_disease = SelectField('Heart Disease', choices=[('0','No'),('1','Yes')])
    ever_married = SelectField('Ever Married', choices=[('Yes','Yes'),('No','No')])
    work_type = SelectField('Work Type', choices=[('Private','Private'),('Self-employed','Self-employed'),
                                                  ('Govt_job','Govt_job'),('Children','Children'),('Never_worked','Never_worked')])
    Residence_type = SelectField('Residence Type', choices=[('Urban','Urban'),('Rural','Rural')])
    avg_glucose_level = FloatField('Average Glucose Level', validators=[DataRequired()])
    bmi = FloatField('BMI', validators=[DataRequired()])
    smoking_status = SelectField('Smoking Status', choices=[('formerly smoked','Formerly smoked'),
                                                            ('never smoked','Never smoked'),
                                                            ('smokes','Smokes'),
                                                            ('unknown','Unknown')])
    submit = SubmitField('Predict')

# ----------------- Routes -----------------
@app.route('/')
def home():
    """Home page route."""
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user and hash password
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)  # Log user in
            flash('Login successful!', 'success')
            return redirect(url_for('predict'))
        else:
            flash('Login failed. Check username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Logout current user."""
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():
    """Stroke prediction route."""
    form = StrokeForm()
    prediction = None

    if form.validate_on_submit():
        # Dummy ML model logic (replace with actual trained model later)
        age = form.age.data
        glucose = form.avg_glucose_level.data
        bmi = form.bmi.data

        if age > 60 or glucose > 150 or bmi > 30:
            prediction = "High Risk of Stroke 😟"
        else:
            prediction = "Low Risk of Stroke 🙂"

    return render_template("predict.html", form=form, prediction=prediction)

# ----------------- Run App -----------------
if __name__ == "__main__":
    app.run(debug=True)
