from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from validate_email_address import validate_email
from dotenv import load_dotenv
import os
load_dotenv()

app = Flask(__name__)

app.secret_key = "secret_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///home.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/')
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/home')
def home():
    # Fetch the username from the query parameters passed in the redirect
    username = request.args.get('username')
    if 'email' in session:
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/login_validation', methods=['POST'])
def login_validation():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not validate_email(email):
        return render_template('login.html', error="Invalid Email Format!")
    
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = email
        username = user.username  # Fetch the username from the User model
        return redirect(url_for('home', username=username))  # Redirect with username
    else:
        return render_template('login.html', error="Wrong Password/Email!")

@app.route('/reg_validation', methods=['POST'])
def reg_validation():
    username = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    
    if not validate_email(email):
        return render_template('login.html', error="Invalid Email Format!")
    
    if user:
        return render_template("register.html", error="User Already Here!")
    else:
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('home', username=username))  # Redirect with username

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
