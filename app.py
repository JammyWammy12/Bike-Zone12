from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'super secret key'  # Used for encryption

DATABASE = 'project1'
bcrypt = Bcrypt(app)  # Used to hash and check passwords
UPLOAD_FOLDER = 'static/images'  # Uploading images file path

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Check if a user is logged in
def is_logged_in():
    if (session.get('user_id') is None):
        print("Not logged in!")
        return False
    else:
        print("Logged in broski!")
        return True


# Creates a connection to the SQLite database
def connect_database(db_file):
    try:
        con = sqlite3.connect(db_file)

        print("Database connected successfully")
        return con
    except Error as e:
        print(f"Database connection error: {e}")


@app.route('/')
def render_homepage():
    user = None
    # If user is logged in, get their first and last name for display in home page
    if 'user_id' in session:

        con = connect_database(DATABASE)
        if con:
            cur = con.cursor()
            query = "SELECT username FROM user WHERE user_id = ?"
            cur.execute(query, (session['user_id'],))
            user = cur.fetchone()
            con.close()

            # Extract first_name from tuple

    return render_template('home.html', user=user, logged_in=is_logged_in())


# Signup route for new users
@app.route('/sign', methods=['POST', 'GET'])
def render_sign_page():
    if request.method == 'POST':
        # Get the form data and format it

        email = request.form.get('user_email').lower().strip()
        username = request.form.get('username').title().strip()
        password = request.form.get('user_password')
        password2 = request.form.get('user_password2')

        # Check password match and length
        if password != password2:
            error_message = "Passwords don't match!"
            return render_template("sign.html", error_message=error_message)

        if len(password) < 8:
            error_message = "Password must be at least 8 characters"
            return render_template("sign.html", error_message=error_message)

        # Securely hashes a plain text password, making it safe to store in a database.
        hashed_password = bcrypt.generate_password_hash(password)

        # Try to connect to the database
        con = connect_database(DATABASE)

        # If the connection is successful
        if con:
            # Create a cursor object to interact with the database
            cur = con.cursor()
            # Check if email already exists

            # Check if the email already exists in the database by searching the user table
            cur.execute("SELECT * FROM user WHERE email = ?", (email,))

            # Get the first row that matches the email
            existing_email = cur.fetchone()

            if existing_email:
                # Display error of email inused
                error_message = "Email already exists"
                # Render the sign up page again, passing the error message to the template to be displayed
                return render_template("sign.html", error_message=error_message)

            cur.execute("SELECT * FROM user WHERE username = ?", (username,))
            existing_username = cur.fetchone()

            if existing_username:
                error_message = "Username already taken"
                return render_template("sign.html", error_message=error_message)

            if con:
                cur = con.cursor()
                query_insert = "INSERT INTO user (username, email, password) VALUES (?, ?, ?)"
                cur.execute(query_insert, (username, email, hashed_password))

            con.commit()
            con.close()
            return redirect("/login")  # Redirect to login page after signing up

    return render_template("sign.html")


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    error_message = request.args.get('error')

    if is_logged_in():
        return redirect('/login?error=please+log+in+first')

    if request.method == 'POST':
        email = request.form.get('user_email').lower().strip()
        password = request.form.get('user_password')

        con = connect_database(DATABASE)
        if con:
            cur = con.cursor()
            query = "SELECT email, user_id, password FROM user WHERE email = ?"
            cur.execute(query, (email,))
            user_info = cur.fetchone()
            con.close()
            if user_info and bcrypt.check_password_hash(user_info[2], password):
                session['user_id'] = user_info[1]
                session['email'] = user_info[0]
                return redirect("/")
            else:
                error_message = "Incorrect email or password"

    return render_template("login.html", logged_in=is_logged_in(), error_message=error_message)




@app.route('/show_post', methods=['POST', 'GET'])
def render_show_post_page():
    if not is_logged_in():
        return redirect('/login?error=please+log+in+first')



    try:
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT post.title, post.image, post.description, post.session_id, user.username FROM post JOIN user ON post.session_id = user.user_id"
        cur.execute(query)
        posts = cur.fetchall()  # Get all rows
        con.close()
        print(posts)


    except Exception as e:
        return f"An error occurred: {e}", 500  # Handle any database errors

    return render_template('show_post.html', logged_in=True, posts=posts)


# Check if the extension is in our allowed list

@app.route('/post', methods=['POST', 'GET'])
def render_post_page():
    if not is_logged_in():
        return redirect('/login?error=please+log+in+first')

    if request.method == 'POST':
        title = request.form.get('title').strip()
        description = request.form.get('description').strip()
        image = request.files.get('image')

        session_id = session.get('user_id')
        name = session.get('first_name')

        # Process image if one was uploaded
        if image and image.filename:
            try:
                # Secure the filename and prepare upload path
                filename = secure_filename(image.filename)  # Create unique filename
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Save file
                image.save(upload_path)
                image_path = f"{filename}"  # Store image title in database
                con = connect_database(DATABASE)
                if con:
                    cur = con.cursor()
                    cur.execute(
                        "INSERT INTO post (title, description, image, session_id, name) VALUES (?, ?, ?, ?, ?)",
                        (title, description, image_path, session_id, name)
                    )
                    con.commit()
                    con.close()
                    return redirect("/post")
            except Error as e:
                print(f"Error uploading file: {e}")
                return redirect("/post?error=upload+failed")

    return render_template('post.html', logged_in=True)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login?message=logged+out')


@app.route('/delete_post', methods=['POST'])
def delete_post():
    if not is_logged_in():
        return redirect('/login?error=please+log+in+first')

    title = request.form.get('title')
    image = request.form.get('image')
    user_id = session.get('user_id')

    try:
        con = connect_database(DATABASE)
        cur = con.cursor()

        query = "SELECT * FROM post WHERE title = ? AND session_id = ?"
        cur.execute(query, (title, user_id))

        post = cur.fetchone()

        if post:
            # Delete from database
            query = "DELETE FROM post WHERE title = ? AND session_id = ?"
            cur.execute(query, (title, user_id))

            con.commit()
            con.close()

        return redirect('/show_post')
    except Exception as e:
        return f"An error occurred while deleting: {e}", 500
