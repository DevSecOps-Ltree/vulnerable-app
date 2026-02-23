#!/usr/bin/env python3
"""
Deliberately Vulnerable Flask Application for Security Testing
WARNING: This application contains INTENTIONAL security vulnerabilities
DO NOT deploy to production!
"""

from flask import Flask, request, render_template_string, redirect
import sqlite3
import os
import pickle
import base64
import hashlib

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials
DATABASE = '/tmp/users.db'
API_KEY = 'sk-prod-1234567890abcdef'  # Hardcoded secret
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# VULNERABILITY 2: Debug mode enabled
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'easy-to-guess-secret'

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user TEXT,
            comment TEXT
        )
    ''')
    # Insert test data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@company.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'john', 'password', 'john@company.com')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return '''
    <html>
    <head><title>Vulnerable Web App</title></head>
    <body>
        <h1>Security Testing Lab - Vulnerable Application</h1>
        <h2>Available Endpoints:</h2>
        <ul>
            <li><a href="/search">Search Users (SQL Injection)</a></li>
            <li><a href="/comment">Comments (XSS)</a></li>
            <li><a href="/ping">Ping Tool (Command Injection)</a></li>
            <li><a href="/file">File Viewer (Path Traversal)</a></li>
            <li><a href="/deserialize">Deserialize Data (Insecure Deserialization)</a></li>
            <li><a href="/hash">Hash Calculator (Weak Crypto)</a></li>
        </ul>
    </body>
    </html>
    '''

# VULNERABILITY 3: SQL Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')

    if query:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # VULNERABLE: Direct string concatenation
        sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%%'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            conn.close()

            output = '<h2>Search Results:</h2><ul>'
            for row in results:
                output += f'<li>Username: {row[0]}, Email: {row[1]}</li>'
            output += '</ul>'
        except Exception as e:
            output = f'<p>Error: {str(e)}</p>'

        return f'''
        <html>
        <body>
            <h1>User Search</h1>
            <form action="/search" method="get">
                <input type="text" name="q" value="{query}">
                <input type="submit" value="Search">
            </form>
            {output}
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''
    else:
        return '''
        <html>
        <body>
            <h1>User Search</h1>
            <form action="/search" method="get">
                <input type="text" name="q" placeholder="Search username">
                <input type="submit" value="Search">
            </form>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''

# VULNERABILITY 4: XSS (Reflected and Stored)
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user = request.form.get('user', 'Anonymous')
        comment_text = request.form.get('comment', '')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO comments (user, comment) VALUES (?, ?)", (user, comment_text))
        conn.commit()
        conn.close()

        return redirect('/comment')

    # Retrieve all comments
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT user, comment FROM comments")
    comments = cursor.fetchall()
    conn.close()

    # VULNERABLE: No output encoding
    comments_html = ''
    for user, comment_text in comments:
        comments_html += f'<div><strong>{user}:</strong> {comment_text}</div>'

    return f'''
    <html>
    <body>
        <h1>Comments</h1>
        <form method="post">
            <input type="text" name="user" placeholder="Your name" required><br>
            <textarea name="comment" placeholder="Your comment" required></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        <h2>All Comments:</h2>
        {comments_html}
        <p><a href="/">Back</a></p>
    </body>
    </html>
    '''

# VULNERABILITY 5: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '')

    if host:
        # VULNERABLE: Unsanitized input to shell command
        result = os.popen(f'ping -c 3 {host}').read()
        return f'''
        <html>
        <body>
            <h1>Ping Tool</h1>
            <form action="/ping" method="get">
                <input type="text" name="host" value="{host}">
                <input type="submit" value="Ping">
            </form>
            <h2>Result:</h2>
            <pre>{result}</pre>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''
    else:
        return '''
        <html>
        <body>
            <h1>Ping Tool</h1>
            <form action="/ping" method="get">
                <input type="text" name="host" placeholder="Enter IP or hostname">
                <input type="submit" value="Ping">
            </form>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''

# VULNERABILITY 6: Path Traversal
@app.route('/file')
def view_file():
    filename = request.args.get('name', '')

    if filename:
        # VULNERABLE: No path validation
        try:
            with open(filename, 'r') as f:
                content = f.read()
            return f'''
            <html>
            <body>
                <h1>File Viewer</h1>
                <form action="/file" method="get">
                    <input type="text" name="name" value="{filename}">
                    <input type="submit" value="View">
                </form>
                <h2>File Contents:</h2>
                <pre>{content}</pre>
                <p><a href="/">Back</a></p>
            </body>
            </html>
            '''
        except Exception as e:
            return f'<p>Error: {str(e)}</p><p><a href="/">Back</a></p>'
    else:
        return '''
        <html>
        <body>
            <h1>File Viewer</h1>
            <form action="/file" method="get">
                <input type="text" name="name" placeholder="Enter filename">
                <input type="submit" value="View">
            </form>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''

# VULNERABILITY 7: Insecure Deserialization
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')

    if data:
        try:
            # VULNERABLE: Unpickling untrusted data
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f'''
            <html>
            <body>
                <h1>Deserialize Data</h1>
                <p>Deserialized object: {obj}</p>
                <p><a href="/">Back</a></p>
            </body>
            </html>
            '''
        except Exception as e:
            return f'<p>Error: {str(e)}</p><p><a href="/">Back</a></p>'
    else:
        return '''
        <html>
        <body>
            <h1>Deserialize Data</h1>
            <form action="/deserialize" method="get">
                <input type="text" name="data" placeholder="Enter base64 encoded pickle data">
                <input type="submit" value="Deserialize">
            </form>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''

# VULNERABILITY 8: Weak Cryptography
@app.route('/hash')
def hash_password():
    password = request.args.get('password', '')

    if password:
        # VULNERABLE: Using MD5 for password hashing
        hashed = hashlib.md5(password.encode()).hexdigest()
        return f'''
        <html>
        <body>
            <h1>Hash Calculator</h1>
            <form action="/hash" method="get">
                <input type="text" name="password" value="{password}">
                <input type="submit" value="Hash">
            </form>
            <p>MD5 Hash: {hashed}</p>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''
    else:
        return '''
        <html>
        <body>
            <h1>Hash Calculator</h1>
            <form action="/hash" method="get">
                <input type="password" name="password" placeholder="Enter password">
                <input type="submit" value="Hash">
            </form>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        '''

if __name__ == '__main__':
    # VULNERABILITY 9: Running on all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)
