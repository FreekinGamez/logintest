from flask import Flask, request, jsonify, redirect, send_from_directory, make_response
import secrets
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__, static_folder='.')
app.secret_key = os.urandom(24)

# Database connection parameters
DB_NAME = os.getenv('DB_DBNAME')  # Change to your PostgreSQL database name
DB_USER = os.getenv('DB_USER'),  # Change to your PostgreSQL username
DB_PASSWORD = os.getenv('DB_PASSWORD'),  # Change to your PostgreSQL password
DB_HOST = "localhost"
DB_PORT = "5432"

def get_db_connection():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    conn.autocommit = True
    return conn

@app.route('/')
def index():
    # Check if user has a session_id cookie
    session_id = request.cookies.get('session_id')
    
    # If session_id exists and is valid, redirect to home
    if session_id:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT user_id FROM sessions WHERE session_id = %s", (session_id,))
        session = cur.fetchone()
        cur.close()
        conn.close()
        
        if session:
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
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check if user exists
    cur.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    
    if user:
        # User exists, check password
        if user['password'] == password:  # In production, use password hashing!
            # Password matches, create session
            session_id = secrets.token_hex(16)
            
            # Store session in database
            cur.execute(
                "INSERT INTO sessions (session_id, user_id) VALUES (%s, %s)",
                (session_id, user['id'])
            )
            
            response = jsonify({
                "success": True,
                "message": "Login successful",
                "session_id": session_id,
                "username": username
            })
            
            # Set cookie with session_id
            response.set_cookie('session_id', session_id)
            cur.close()
            conn.close()
            return response
        else:
            # Password doesn't match
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": "Invalid password"
            }), 401
    else:
        # User doesn't exist, create new account
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id",
            (username, password)  # In production, use password hashing!
        )
        user_id = cur.fetchone()['id']
        
        # Create session
        session_id = secrets.token_hex(16)
        cur.execute(
            "INSERT INTO sessions (session_id, user_id) VALUES (%s, %s)",
            (session_id, user_id)
        )
        
        response = jsonify({
            "success": True,
            "message": "Account created and logged in",
            "session_id": session_id,
            "username": username
        })
        
        # Set cookie with session_id
        response.set_cookie('session_id', session_id)
        cur.close()
        conn.close()
        return response

@app.route('/home')
def home():
    # Check if user has a session_id cookie
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return redirect('/login')
    
    # Check if session exists
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM sessions WHERE session_id = %s", (session_id,))
    session = cur.fetchone()
    cur.close()
    conn.close()
    
    if session:
        # User is logged in
        return send_from_directory('.', 'home.html')
    
    # No session found
    return redirect('/login')

@app.route('/user-data')
def user_data():
    # This route provides the user data to the home.html page
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({"logged_in": False}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Join users and sessions to get user data
    cur.execute("""
        SELECT u.id, u.username, u.password, s.session_id
        FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.session_id = %s
    """, (session_id,))
    
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user:
        return jsonify({
            "logged_in": True,
            "username": user['username'],
            "password": user['password'],  # In production, don't send password to client
            "session_id": user['session_id']
        })
    
    return jsonify({"logged_in": False}), 401

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
