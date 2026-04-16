from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import os
from werkzeug.utils import secure_filename
from uuid import uuid4
import uuid
from flaskwebgui import FlaskUI


# System Setup & Configuration
# Imports necessary tools and sets strict file upload limits / encryption cookie setup
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.secret_key = 'ultra_secure_session_key'

# Security Firewall (Before Request)
# Acts as a strict bouncer before ANY route loads. Redirects unverified guests to Login.
@app.before_request
def require_login():
    allowed_routes = ['login', 'static']
    if request.endpoint not in allowed_routes and 'user_email' not in session:
        return redirect(url_for('login'))
        
    # Strictly Admin-only routes
    if 'user_role' in session and session['user_role'] != 'admin':
        admin_only = ['add_user_page', 'add_user', 'delete_user', 'send_notification', 'delete_notification']
        if request.endpoint in admin_only:
            return redirect(url_for('index'))


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ceah_3007",
        database="userdb"
    )

# Dashboard & Directory
# Renders the main table and constructs search & filter SQL queries
@app.route("/")
def index():
    search = request.args.get("search", "")
    role = request.args.get("role", "")
    status = request.args.get("status", "")

    db = get_db_connection()
    cursor = db.cursor()

    query = "SELECT * FROM users WHERE 1=1"
    params = []

    if search:
        query += " AND (name LIKE %s OR email LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%"])
    
    if role:
        query += " AND role = %s"
        params.append(role)

    if status:
        query += " AND status = %s"
        params.append(status)

    cursor.execute(query, tuple(params))
    users = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("index.html", users=users)

# Add / Edit / Remove Logic
@app.route("/add", methods=["GET"])
def add_user_page():
    return render_template("add.html")

@app.route("/add", methods=["POST"])
def add_user():
    name = request.form["name"]
    email = request.form["email"]
    phone_number = request.form["phone_number"]
    password = request.form["password"]
    role = request.form["role"]
    status = request.form["status"]

    profile_pic = request.files.get("profile_pic")
    pic_filename = 'default.png'
    if profile_pic and profile_pic.filename != '':
        filename = secure_filename(profile_pic.filename)
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        # Tukar nama file jadi unik guna UUID (elak duplicate nama)
        filename = f"{uuid4().hex}.{ext}" if ext else f"{uuid4().hex}"
        profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        pic_filename = filename

    db = get_db_connection()
    cursor = db.cursor()
    #finding the next available ID
    cursor.execute("SELECT id FROM users ORDER BY id ASC")
    existing_ids = [row[0] for row in cursor.fetchall()]
    next_id = 1
    for eid in existing_ids:
        if eid == next_id:
            next_id += 1
        else:
            break
            
    sql = "INSERT INTO users (id, name, email, phone_number, password, role, status, profile_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    cursor.execute(sql, (next_id, name, email, phone_number, password, role, status, pic_filename))
    db.commit()
    cursor.close()
    db.close()

    return redirect(url_for("index"))

@app.route("/update/<int:id>", methods=["GET", "POST"])
def update_user(id):
    db = get_db_connection()
    cursor = db.cursor()
    if request.method == "POST":
        # Security Check: Only Admin or Owner can update
        if session.get('user_role') != 'admin' and session.get('user_id') != id:
            return redirect(url_for('index'))
            
        name = request.form["name"]
        email = request.form["email"]
        phone_number = request.form["phone_number"]
        password = request.form["password"]
        role = request.form["role"]
        status = request.form["status"]

        profile_pic = request.files.get("profile_pic")
        
        if profile_pic and profile_pic.filename != '':
            filename = secure_filename(profile_pic.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            filename = f"{uuid4().hex}.{ext}" if ext else f"{uuid4().hex}"
            profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            sql = "UPDATE users SET name=%s, email=%s, phone_number=%s, password=%s, role=%s, status=%s, profile_pic=%s WHERE id=%s"
            cursor.execute(sql, (name, email, phone_number, password, role, status, filename, id))
        else:
            sql = "UPDATE users SET name=%s, email=%s, phone_number=%s, password=%s, role=%s, status=%s WHERE id=%s"
            cursor.execute(sql, (name, email, phone_number, password, role, status, id))
        
        db.commit()
        cursor.close()
        db.close()
        return redirect(url_for("index"))
    else:
        # Security Check: Only Admin or Owner can access update page
        if session.get('user_role') != 'admin' and session.get('user_id') != id:
            return redirect(url_for('index'))
            
        cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        return render_template("update.html", user=user)


# Read-Only User Information Page
@app.route("/view/<int:id>")
def view_user(id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    return render_template("view.html", user=user)

@app.route("/delete/<int:id>", methods=["GET"])
def delete_user(id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (id,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for("index"))


# Session Authentication Core (Login / Logout)
# Verifies Database credentials, assigns User Roles into Cookies, and sets login_time

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        
        if user:
            session['user_id'] = user[0]
            session['user_email'] = user[2]
            session['user_name'] = user[1]
            session['user_role'] = user[5]
            
            cursor.execute("UPDATE users SET login_time=CURRENT_TIMESTAMP WHERE id=%s", (user[0],))
            db.commit()
            
            cursor.close()
            db.close()
            if session['user_role'] == 'admin':
                return redirect(url_for("index"))
            else:
                return redirect(url_for("view_user", id=session['user_id']))
        else:
            cursor.close()
            db.close()
            return render_template("login.html", error="Invalid Email or Password.")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.context_processor
def inject_unread_count():
    if 'user_id' in session:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM notifications WHERE receiver_id = %s AND is_read = 0", (session['user_id'],))
        count = cursor.fetchone()[0]
        cursor.close()
        db.close()
        return dict(unread_count=count)
    return dict(unread_count=0)

# --- NOTIFICATION SYSTEM ---
@app.route("/notifications")
def notifications():
    db = get_db_connection()
    cursor = db.cursor()
    
    if session.get('user_role') == 'admin':
        # Admin sees all sent history - Grouped by batch_id for broadcasts
        cursor.execute("""
            SELECT MAX(n.id), MAX(n.sender_id), MAX(n.receiver_id), n.message, MAX(n.is_read), n.created_at, MAX(n.batch_id) as batch_id,
                   MAX(u_sender.name) as sender_name, 
                   IF(MAX(n.batch_id) IS NOT NULL, 'All Users', MAX(u_receiver.name)) as receiver_name 
            FROM notifications n
            JOIN users u_sender ON n.sender_id = u_sender.id
            LEFT JOIN users u_receiver ON n.receiver_id = u_receiver.id
            GROUP BY IFNULL(n.batch_id, CONCAT('single_', n.id)), n.message, n.created_at
            ORDER BY n.created_at DESC
        """)
        msgs = cursor.fetchall()
        
        # Also need user list for the send form
        cursor.execute("SELECT id, name, role FROM users WHERE id != %s", (session['user_id'],))
        users = cursor.fetchall()
        
        cursor.close()
        db.close()
        return render_template("notifications.html", messages=msgs, users=users)
    else:
        # User/Guest sees messages sent to them
        cursor.execute("""
            SELECT n.*, u_sender.name as sender_name 
            FROM notifications n
            JOIN users u_sender ON n.sender_id = u_sender.id
            WHERE n.receiver_id = %s
            ORDER BY n.created_at DESC
        """, (session['user_id'],))
        msgs = cursor.fetchall()
        cursor.close()
        db.close()
        return render_template("notifications.html", messages=msgs)

@app.route("/notifications/send", methods=["POST"])
def send_notification():
    receiver_id = request.form.get("receiver_id")
    message = request.form.get("message")
    sender_id = session['user_id']
    
    db = get_db_connection()
    cursor = db.cursor()
    
    if receiver_id == "all":
        batch_id = str(uuid.uuid4())
        cursor.execute("SELECT id FROM users WHERE id != %s", (sender_id,))
        all_user_ids = [row[0] for row in cursor.fetchall()]
        for rid in all_user_ids:
            cursor.execute("INSERT INTO notifications (sender_id, receiver_id, message, batch_id) VALUES (%s, %s, %s, %s)", 
                           (sender_id, rid, message, batch_id))
    else:
        cursor.execute("INSERT INTO notifications (sender_id, receiver_id, message) VALUES (%s, %s, %s)", 
                       (sender_id, receiver_id, message))
    
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for("notifications"))

@app.route("/notifications/mark_read/<int:id>", methods=["POST"])
def mark_read(id):
    db = get_db_connection()
    cursor = db.cursor()
    # Ensure ONLY the receiver can mark it as read
    cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = %s AND receiver_id = %s", 
                   (id, session['user_id']))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for("notifications"))

@app.route("/notifications/delete/<int:id>", methods=["POST"])
def delete_notification(id):
    db = get_db_connection()
    cursor = db.cursor()
    
    # Check if it's part of a batch
    cursor.execute("SELECT batch_id FROM notifications WHERE id = %s", (id,))
    res = cursor.fetchone()
    if res and res[0]:
        cursor.execute("DELETE FROM notifications WHERE batch_id = %s", (res[0],))
    else:
        cursor.execute("DELETE FROM notifications WHERE id = %s", (id,))
        
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for("notifications"))

if __name__ == "__main__":
    # Initialize FlaskUI with the app and set fullscreen mode
    ui = FlaskUI(app=app, server="flask", fullscreen=True)
    ui.run()