import psycopg2
from flask import Flask, render_template, jsonify, redirect, request, url_for, session, flash
from flask_socketio import SocketIO
from encryption import encrypt_password, verify_password 
from functools import wraps



app = Flask(__name__)
app.secret_key = 'your_secret_key' 
socketio = SocketIO(app)



# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="access_logs_db",
            user="postgres",  # Replace with your username
            password="smith"  # Replace with your password
        )
        print("Database connection established")  # Debugging line
        return conn
    except Exception as e:
        print("Error connecting to the database:", e)
        return None
    


"""def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("You need to log in first.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function    
"""

# Route to fetch logs from the database and return as JSON
@app.route('/')
def home():
    return render_template('home.html')
#def index():
 #   # Redirect to logs page
  #  return redirect('/logs')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the username and password from the form
        username = request.form['username']
        password = request.form['password']
        
        # Get the database connection
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error connecting to the database"}), 500

        try:
            # Create a cursor to execute the query
            cur = conn.cursor()
            cur.execute("SELECT password FROM login_info_table WHERE username = %s", (username,))
            user = cur.fetchone()

            # Check if the user exists and verify the password
            if user and verify_password(user[0], password):
                # Set session variable for the logged-in user
                session['username'] = username
                
                
                # Fetch logs from the database
                cur.execute('SELECT * FROM access_logs ORDER BY id DESC')
                logs = cur.fetchall()

                cur.close()
                conn.close()

                if session.get('username') == 'admin':
                    return render_template('admin_logs.html', logs=logs)  # Render admin logs page
                else:
                    return render_template('user_logs.html', logs=logs)  # Render user logs page    

                # Render the logs.html page with the fetched logs
            
            else:
                # Flash an error message and render the login template with the error
                flash("Invalid username or password", 'error')
                return render_template('login.html')

        except Exception as e:
            return jsonify({"error": f"Error during login process: {e}"}), 500

    # If the request method is GET, just render the login page
    return render_template('login.html')


# Sign Up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Handle sign up logic here (e.g., create new user)
        username = request.form['username']
        password = request.form['password']
        encrypted_password = encrypt_password(password)

        # Save the username and encrypted password to the database
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error connecting to the database"}), 500

        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO login_info_table (username, password) VALUES (%s, %s)", (username, encrypted_password))
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            return jsonify({"error": "Username already exists"}), 400
        finally:
            cur.close()
            conn.close()
        # Add logic for user registration
        return redirect(url_for('login'))  # Redirect to login after sign up
    return render_template('signup.html')

@app.route('/add_log', methods=['POST'])
def add_log():
    if 'username' in session and session['username'] == 'admin':
        data = request.get_json()
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500

        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO access_logs (code, name, role, status, timestamp) 
                VALUES (%s, %s, %s, %s, NOW())
                """, (data['code'], data['name'], data['role'], data['status']))
            conn.commit()
            cur.close()
            conn.close()
            
            socketio.emit('log_update')  # Notify all clients about the update
            return jsonify({"success": True}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

@app.route('/edit_log/<int:log_id>', methods=['POST'])
def edit_log(log_id):
    if 'username' in session and session['username'] == 'admin':
        data = request.get_json()
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500

        try:
            cur = conn.cursor()
            cur.execute("""
                UPDATE access_logs 
                SET code = %s, name = %s, role = %s, status = %s, timestamp = NOW()
                WHERE id = %s
                """, (data['code'], data['name'], data['role'], data['status'], log_id))
            conn.commit()
            cur.close()
            conn.close()
            
            socketio.emit('log_update')  # Notify all clients about the update
            return jsonify({"success": True}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

@app.route('/delete_log/<int:log_id>', methods=['POST'])
def delete_log(log_id):
    if 'username' in session and session['username'] == 'admin':
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500

        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM access_logs WHERE id = %s", (log_id,))
            conn.commit()
            cur.close()
            conn.close()
            
            socketio.emit('log_update')  # Notify all clients about the update
            return jsonify({"success": True}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success": False, "error": "Unauthorized"}), 403


@app.route('/fetch_logs', methods=['GET'])
def fetch_logs():
    if 'username' in session and session['username'] in ['admin', 'user']:  # Allow both admin and user
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error connecting to the database"}), 500

        try:
            cur = conn.cursor()
            cur.execute('SELECT * FROM access_logs ORDER BY id DESC')
            logs = cur.fetchall()
            cur.close()
            conn.close()

            # Format logs for JSON response
            logs_list = [
                {
                    "id": log[0],
                    "code": log[1],
                    "name": log[2],
                    "role": log[3],
                    "status": log[4],
                    "timestamp": log[5]
                }
                for log in logs
            ]

            print("Fetched logs:", logs_list)  # Debug print
            return jsonify({"success": True, "logs": logs_list})

        except Exception as e:
            print(f"Error fetching logs: {e}")
            return jsonify({"error": "Error fetching logs"}), 500
    else:
        return jsonify({"error": "Unauthorized access"}), 403





@app.route('/logout', methods=['GET'])
def logout():
    # Clear the user session
    session.clear()
    return redirect(url_for('home'))





if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

