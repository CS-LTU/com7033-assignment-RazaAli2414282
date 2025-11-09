"""
Stroke Prediction & Patient Management Web Application
Author: Raza Ali

- SQLite (SQLAlchemy) stores user authentication data (users table).
- MongoDB stores patient records (patients collection).
- Flask-WTF used for CSRF + validation; Flask-Login used for sessions.
- Basic logging is configured to file app.log.
"""

import logging
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from pymongo import MongoClient
from bson.objectid import ObjectId

# ----------------- Logging -----------------
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

# ----------------- Flask Setup -----------------
app = Flask(__name__)
app.config.from_object("config.Config")  # SECRET_KEY + SQLALCHEMY_DATABASE_URI

# ----------------- SQLAlchemy (SQLite) - Users -----------------
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# ----------------- MongoDB Setup (Patients) -----------------
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["stroke_app"]
mongo_patients = mongo_db["patients"]

# ----------------- Models (SQLite Users) -----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- Forms -----------------
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class PatientForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=50)])
    gender = SelectField("Gender", choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")])
    age = FloatField("Age", validators=[DataRequired()])
    hypertension = SelectField("Hypertension", choices=[("0", "No"), ("1", "Yes")])
    heart_disease = SelectField("Heart Disease", choices=[("0", "No"), ("1", "Yes")])
    ever_married = SelectField("Ever Married", choices=[("Yes", "Yes"), ("No", "No")])
    work_type = SelectField(
        "Work Type",
        choices=[
            ("Private", "Private"),
            ("Self-employed", "Self-employed"),
            ("Govt_job", "Govt_job"),
            ("Children", "Children"),
            ("Never_worked", "Never_worked"),
        ],
    )
    residence_type = SelectField("Residence Type", choices=[("Urban", "Urban"), ("Rural", "Rural")])
    avg_glucose_level = FloatField("Average Glucose Level", validators=[DataRequired()])
    bmi = FloatField("BMI", validators=[DataRequired()])
    smoking_status = SelectField(
        "Smoking Status",
        choices=[("formerly smoked", "Formerly smoked"), ("never smoked", "Never smoked"),
                 ("smokes", "Smokes"), ("unknown", "Unknown")],
    )
    submit = SubmitField("Save")

# ----------------- Routes -----------------
@app.route("/")
def home():
    return render_template("base.html")

# ---------- Registration ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", "warning")
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

# ---------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("list_patients"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

# ---------- Logout ----------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ----------------- Patient CRUD (MongoDB) -----------------
def _patient_to_template(doc):
    doc = dict(doc)
    doc["_id"] = str(doc["_id"])
    doc["hypertension"] = bool(doc.get("hypertension", False))
    doc["heart_disease"] = bool(doc.get("heart_disease", False))
    return doc

@app.route("/patients")
@login_required
def list_patients():
    docs = list(mongo_patients.find({"user_id": current_user.id}))
    patients = [_patient_to_template(d) for d in docs]
    return render_template("patients.html", patients=patients)

@app.route("/patients/add", methods=["GET", "POST"])
@login_required
def add_patient():
    form = PatientForm()
    if form.validate_on_submit():
        patient_doc = {
            "name": form.name.data,
            "gender": form.gender.data,
            "age": float(form.age.data),
            "hypertension": bool(int(form.hypertension.data)),
            "heart_disease": bool(int(form.heart_disease.data)),
            "ever_married": form.ever_married.data,
            "work_type": form.work_type.data,
            "residence_type": form.residence_type.data,
            "avg_glucose_level": float(form.avg_glucose_level.data),
            "bmi": float(form.bmi.data),
            "smoking_status": form.smoking_status.data,
            "user_id": current_user.id,
            "created_at": datetime.utcnow(),
        }
        mongo_patients.insert_one(patient_doc)
        flash("Patient added successfully!", "success")
        return redirect(url_for("list_patients"))
    return render_template("patients_add_edit.html", form=form, action="Add")

@app.route("/patients/edit/<patient_id>", methods=["GET", "POST"])
@login_required
def edit_patient(patient_id):
    doc = mongo_patients.find_one({"_id": ObjectId(patient_id)})
    if not doc or doc.get("user_id") != current_user.id:
        flash("Record not found or unauthorized.", "danger")
        return redirect(url_for("list_patients"))

    form = PatientForm()
    if request.method == "GET":
        form.name.data = doc.get("name")
        form.gender.data = doc.get("gender")
        form.age.data = doc.get("age")
        form.hypertension.data = "1" if doc.get("hypertension") else "0"
        form.heart_disease.data = "1" if doc.get("heart_disease") else "0"
        form.ever_married.data = doc.get("ever_married")
        form.work_type.data = doc.get("work_type")
        form.residence_type.data = doc.get("residence_type")
        form.avg_glucose_level.data = doc.get("avg_glucose_level")
        form.bmi.data = doc.get("bmi")
        form.smoking_status.data = doc.get("smoking_status")

    if form.validate_on_submit():
        updated = {
            "name": form.name.data,
            "gender": form.gender.data,
            "age": float(form.age.data),
            "hypertension": bool(int(form.hypertension.data)),
            "heart_disease": bool(int(form.heart_disease.data)),
            "ever_married": form.ever_married.data,
            "work_type": form.work_type.data,
            "residence_type": form.residence_type.data,
            "avg_glucose_level": float(form.avg_glucose_level.data),
            "bmi": float(form.bmi.data),
            "smoking_status": form.smoking_status.data,
            "updated_at": datetime.utcnow(),
        }
        mongo_patients.update_one({"_id": ObjectId(patient_id)}, {"$set": updated})
        flash("Patient updated successfully!", "success")
        return redirect(url_for("list_patients"))

    return render_template("patients_add_edit.html", form=form, action="Edit")

@app.route("/patients/delete/<patient_id>", methods=["POST"])
@login_required
def delete_patient(patient_id):
    doc = mongo_patients.find_one({"_id": ObjectId(patient_id)})
    if doc and doc.get("user_id") == current_user.id:
        mongo_patients.delete_one({"_id": ObjectId(patient_id)})
        flash("Patient deleted successfully!", "info")
    else:
        flash("Record not found or unauthorized.", "danger")
    return redirect(url_for("list_patients"))

# ----------------- Prediction -----------------
@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():
    form = PatientForm()
    prediction_text = None
    if form.validate_on_submit():
        age = float(form.age.data)
        glucose = float(form.avg_glucose_level.data)
        bmi = float(form.bmi.data)
        prediction = 1 if (age > 60 or glucose > 150 or bmi > 30) else 0
        prediction_text = "High Risk of Stroke" if prediction == 1 else "Low Risk of Stroke"

        # Save prediction
        record = {
            "name": form.name.data,
            "gender": form.gender.data,
            "age": age,
            "hypertension": bool(int(form.hypertension.data)),
            "heart_disease": bool(int(form.heart_disease.data)),
            "ever_married": form.ever_married.data,
            "work_type": form.work_type.data,
            "residence_type": form.residence_type.data,
            "avg_glucose_level": glucose,
            "bmi": bmi,
            "smoking_status": form.smoking_status.data,
            "prediction": int(prediction),
            "predicted_at": datetime.utcnow(),
            "user_id": current_user.id,
        }
        mongo_patients.insert_one(record)
        flash("Prediction saved to records.", "success")

    return render_template("predict.html", form=form, prediction=prediction_text)

# ----------------- Run -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
