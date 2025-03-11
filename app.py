from flask import Flask, request, jsonify, redirect, send_from_directory, make_response
import secrets
import os

app = Flask(__name__, static_folder='.')
app.secret_key = os.urandom(24)

# In a real app, you'd use a database
users = {}  # Will store username: {password, session_id}

@app.route('/')
def index():
    # Check if user has a session_id cookie
    session_id = request.cookies.get('session_id')
    
    # If session_id exists and is valid, redirect to home
    if session_id:
        for username, user_data in users.items():
            if user_data.get('session_id') == session_id:
                return redirect('/home')
    
    # Otherwise redirect to login
    return redirect('/login')

@app.route('/login')
def login():
    return send_from_directory('.', 'login.html')

@app.route('/do-login', methods=['POST'])
def do_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username in users:
        # User exists, check password
        if users[username]['password'] == password:
            # Password matches, create session
            session_id = secrets.token_hex(16)
            users[username]['session_id'] = session_id
            
            response = jsonify({
                "success": True,
                "message": "Login successful",
                "session_id": session_id,
                "username": username
            })
            
            # Set cookie with session_id
            response.set_cookie('session_id', session_id)
            return response
        else:
            # Password doesn't match
            return jsonify({
                "success": False,
                "message": "Invalid password"
            }), 401
    else:
        # User doesn't exist, create new account
        session_id = secrets.token_hex(16)
        users[username] = {
            'password': password,
            'session_id': session_id
        }
        
        response = jsonify({
            "success": True,
            "message": "Account created and logged in",
            "session_id": session_id,
            "username": username
        })
        
        # Set cookie with session_id
        response.set_cookie('session_id', session_id)
        return response

@app.route('/home')
def home():
    # Check if user has a session_id cookie
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return redirect('/login')
    
    # Find user with this session_id
    for username, user_data in users.items():
        if user_data.get('session_id') == session_id:
            # User is logged in
            return send_from_directory('.', 'home.html')
    
    # No user found with this session_id
    return redirect('/login')

@app.route('/user-data')
def user_data():
    # This route provides the user data to the home.html page
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({"logged_in": False}), 401
    
    for username, user_data in users.items():
        if user_data.get('session_id') == session_id:
            return jsonify({
                "logged_in": True,
                "username": username,
                "password": user_data['password'],
                "session_id": session_id
            })
    
    return jsonify({"logged_in": False}), 401

if __name__ == '__main__':
    app.run(debug=True)
