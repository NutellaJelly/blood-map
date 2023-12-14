from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect
import pymongo
import uuid
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.secret_key = b'\xeb\xa2\xc9\x1b#\x84\xb8\x1cjq\xc0\x1e3\x11+\xc9'

# MongoDB Database
client = pymongo.MongoClient("localhost", 27017)
db = client.blood_map

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
        
    return wrap


class User:
    def signup(self):
        print(request.form)

        user = {
            "_id": uuid.uuid4().hex,
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "password": request.form.get('password'),
        }
        # Encrypting the Password (For security ofc :)
        user['password'] = pbkdf2_sha256.encrypt(user['password'])

        if db.users.find_one({"email": user['email'] }):
            return jsonify({"error": "Email Address already in use."}), 400

        if db.users.insert_one(user):
            return self.startSession(user)
        
        return jsonify({"error": "Signup Failed"}), 400


    def startSession(self, user):
        del user['password']
        session['logged_in'] = True
        session['user'] = user

        return jsonify(user), 200
    
    def signout(self):
        session.clear()
        return redirect('/')
    
    def login(self):
        user = db.users.find_one({
            "email": request.form.get('email')
        })

        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.startSession(user)
        
        return jsonify({"error": "Invalid Login Credentials."}), 401
    

# Flask Routes
@app.route("/user/signup", methods=["POST"])
def signup():
    return User().signup()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/dashboard/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/user/signout")
def signout():
    return User().signout()


@app.route("/user/login", methods = ["POST"])
def login():
    return User().login()


app.run(host="0.0.0.0", port=81)
