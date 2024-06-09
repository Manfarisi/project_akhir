from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask import make_response, flash

client = MongoClient('mongodb+srv://resellerida:idariseller@cluster0.yckjm3g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client.projek_akhir
SECRET_KEY = 'IDA'
TOKEN_KEY = 'ida'

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

@app.route('/', methods=['GET'])
def home():
    token_receive = request.cookies.get(TOKEN_KEY)
    if not token_receive:
        return redirect(url_for('login'))
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({'username': payload.get('id')})
        return render_template('index.html', user_info=user_info)
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was a problem logging you in'
        return redirect(url_for('login', msg=msg))

@app.route('/sign_up/check_dup', methods=['POST'])
def check_dup():
    username_receive = request.form.get('username_give')
    exists = bool(db.users.find_one({"username": username_receive}))
    return jsonify({'result': 'success', 'exists': exists})

@app.route('/sign_in', methods=['POST'])
def sign_in():
    username_receive = request.form.get("username_give")
    password_receive = request.form.get("password_give")
    pw_hash = hashlib.sha256(password_receive.encode("utf-8")).hexdigest()
    result = db.users.find_one({"username": username_receive, "password": pw_hash})
    
    if result:
        payload = {"id": username_receive, "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24)}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        response = make_response(jsonify({"result": "success"}))
        response.set_cookie(TOKEN_KEY, token)
        flash('Login berhasil! Selamat datang, {}'.format(username_receive), 'success')
        return response
    else:
        return jsonify({"result": "fail", "msg": "We could not find a user with that id/password combination"})

@app.route('/sign_up/save', methods=['POST'])
def sign_up():
    username_receive = request.form.get('username_give')
    password_receive = request.form.get('password_give')
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    if db.users.find_one({"username": username_receive}):
        return jsonify({'result': 'fail', 'msg': 'Username already exists'})
    doc = {"username": username_receive, "password": password_hash}
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie(TOKEN_KEY, expires=0)
    return response

@app.route('/login', methods=['GET'])
def login():
    msg = request.args.get('msg')
    return render_template('login.html', msg=msg)

@app.route('/shop', methods=['GET'])
def shop():
    msg = request.args.get('msg')
    return render_template('shop.html', msg=msg)

@app.route('/detail', methods=['GET'])
def detail():
    msg = request.args.get('msg')
    return render_template('detail.html', msg=msg)

@app.route('/contact', methods=['GET'])
def contact():
    msg = request.args.get('msg')
    return render_template('contact.html', msg=msg)

@app.route('/cart', methods=['GET'])
def cart():
    msg = request.args.get('msg')
    return render_template('cart.html', msg=msg)

@app.route('/checkout', methods=['GET'])
def checkout():
    msg = request.args.get('msg')
    return render_template('checkout.html', msg=msg)

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
