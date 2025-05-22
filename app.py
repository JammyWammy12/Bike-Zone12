from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'super secret key'  # Used for encryption

DATABASE = 'database5'
bcrypt = Bcrypt(app)  # Used to hash and check passwords
UPLOAD_FOLDER = 'static/images'  # Uploading images file path
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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


# If Homepage for user
@app.route('/')
def render_home():
    user = None
    # If user is logged in, get their first and last name for display in home page
    if 'user_id' in session:
        # Try to connect to the database
        con = connect_database(DATABASE)
        # If the connection is successful
        if con:
            # Create a cursor object to allow for SELECT and INSERT
            cur = con.cursor()
            query = "SELECT username FROM user WHERE user_id = ?"
            cur.execute(query, (session['user_id'],))
            user = cur.fetchone()
            con.close()

    return render_template('/home.html', user=user, logged_in=is_logged_in())


# Signup route for new users
@app.route('/sign', methods=['POST', 'GET'])
def render_sign_page():
    if request.method == 'POST':
        # Get the form data and format it
        email = request.form.get('user_email').lower().strip()
        username = request.form.get('username').title().strip()
        password = request.form.get('user_password')
        password2 = request.form.get('user_password2')

        error_message = None

        # Confirm the field lengths
        if len(email) > 30:
            error_message = "Email must be 30 characters or less!"
        elif len(username) > 30:
            error_message = "Username must be 30 characters or less!"
        elif len(password) > 30:
            error_message = "Password must be 30 characters or less!"
        elif password != password2:
            error_message = "Passwords don't match!"
        elif len(password) < 8:
            error_message = "Password must be at least 8 characters"
            return render_template("sign.html", error_message=error_message)

        # If any confirm failed, render template with error
        if error_message:
            return render_template("sign.html", error_message=error_message)

        # Securely hashes a plain text password, making it safe to store in a database.
        hashed_password = bcrypt.generate_password_hash(password)

        con = connect_database(DATABASE)

        if con:
            cur = con.cursor()

            # Check if the email already exists in the database by searching the user table
            cur.execute("SELECT * FROM user WHERE email = ?", (email,))

            # Get the first row that matches the email
            existing_email = cur.fetchone()

            if existing_email:
                # Display error of email in used
                error_message = "Email already exists"
                # Render the sign-up page again, passing the error message to the template to be displayed
                return render_template("sign.html", error_message=error_message)

            cur.execute("SELECT * FROM user WHERE username = ?", (username,))
            existing_username = cur.fetchone()

            if existing_username:
                error_message = "Username already taken"
                return render_template("sign.html", error_message=error_message)

            if con:
                cur = con.cursor()
                query_insert = "INSERT INTO user (username, email, password, admin) VALUES (?, ?, ?, ?)"
                cur.execute(query_insert, (username, email, hashed_password, False))

            con.commit()
            con.close()
            return redirect("/login")  # Redirect to login page after signing up

    return render_template("sign.html")


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    # Using this to grab the error message first
    error_message = request.args.get('error')

    if is_logged_in():
        return redirect('/login?error=Please+log+in+first')

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
            # This check if the user stored hashed password matches the entered password.
            if user_info and bcrypt.check_password_hash(user_info[2], password):
                session['user_id'] = user_info[1]  # stores session to keep them logged in
                session['email'] = user_info[0]
                return redirect("/")
            else:
                error_message = "Incorrect email or password"

    return render_template("login.html", logged_in=is_logged_in(), error_message=error_message)


@app.route('/show_post', methods=['POST', 'GET'])
def render_show_post_page():
    # If user not logged in they can't access this
    if not is_logged_in():
        return redirect('/login?error=Please+log+in+first')

    try:
        con = connect_database(DATABASE)
        cur = con.cursor()
        # This query fetches bike details, user info, and post data, ordered by bike ID in descending order.
        query = """
                SELECT type_bike.model, type_bike.brand, type_bike.image, user.username, 
                       post.description, post.rating, post.session_id, type_bike.bike_id
                FROM post 
                JOIN user ON post.session_id = user.user_id 
                JOIN type_bike ON post.bike_id = type_bike.bike_id 
                ORDER BY post.bike_id DESC
                """
        cur.execute(query, )
        # This fetches all the data
        posts = cur.fetchall()
        con.close()

        print(posts)

    except Exception as e:
        return f"An error occurred: {e}", 500

    return render_template('show_post.html', logged_in=True, posts=posts)


# Checks if there is "." in the filename
# Then it splits the filename at the last dot
# Then checks if file type allowed


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/post', methods=['POST', 'GET'])
def render_post_page():
    if not is_logged_in():
        return redirect('/login?error=please+log+in+first')
    if request.method == 'POST':
        model = request.form.get('model').strip()
        description = request.form.get('description').strip()
        image = request.files.get('image')
        rating = request.form.get('rating').strip()
        session_id = session.get('user_id')
        brand = request.form.get('brand').strip()



        if len(model) > 30:
            error_message = "Bike model must be 30 characters or less!"
            return render_template("post.html", error_message=error_message)
        if len(brand) > 30:
            error_message = "Bike brand must be 30 characters or less!"
            return render_template("post.html", error_message=error_message)
        elif len(description) > 300:
            error_message = "Description must be 300 characters or less!"
            return render_template("post.html", error_message=error_message)



        if image and allowed_file(image.filename):
            try:
                filename = secure_filename(image.filename)
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(upload_path)
                image_path = f"{filename}"

                con = connect_database(DATABASE)
                if con:
                    cur = con.cursor()

                    # First insert bike details and get the bike_id
                    cur.execute(
                        "INSERT INTO type_bike (model, image, brand) VALUES (?, ?, ?)",
                        (model, image_path, brand)
                    )
                    bike_id = cur.lastrowid

                    # Then insert post with reference to the bike
                    cur.execute(
                        "INSERT INTO post (description, session_id, rating, bike_id) VALUES (?, ?, ?, ?)",
                        (description, session_id, rating, bike_id)
                    )

                    con.commit()
                    con.close()
                    return redirect("/show_post")
            except Error as e:
                print(f"Error uploading file: {e}")
                return redirect("/post?Error=upload+failed")

    return render_template('post.html', logged_in=True)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login?message=logged+out')


@app.route('/delete_post', methods=['POST'])
def delete_post():
    bike_id = request.form.get('bike_id')

    user_id = session.get('user_id')

    try:
        con = connect_database(DATABASE)
        cur = con.cursor()

        # Fetch post to check existence
        cur.execute("SELECT * FROM post WHERE bike_id = ? AND session_id = ?", (bike_id, user_id,))

        post = cur.fetchone()

        if post:
            # Delete from post table
            cur.execute("DELETE FROM post WHERE bike_id = ? AND session_id = ?", (bike_id, user_id,))
            # Delete from type_bike table
            cur.execute("DELETE FROM type_bike WHERE bike_id = ?", (bike_id,))

            con.commit()
            con.close()

        return redirect('/show_post')
    except Exception as e:
        return f"An error occurred while deleting: {e}", 500


@app.route('/admin_delete', methods=['POST'])
def admin_post():
    bike_id = request.form.get('bike_id')

    try:
        con = connect_database(DATABASE)
        cur = con.cursor()

        # Fetch post to check existence
        cur.execute("SELECT * FROM post WHERE bike_id = ?", (bike_id, ))

        post = cur.fetchone()

        if post:
            # Delete from post table
            cur.execute("DELETE FROM post WHERE bike_id = ?", (bike_id, ))
            # Delete from type_bike table
            cur.execute("DELETE FROM type_bike WHERE bike_id = ?", (bike_id,))

            con.commit()
            con.close()

        return redirect('/show_post')
    except Exception as e:
        return f"An error occurred while deleting: {e}", 500


@app.route('/change_user', methods=['GET', 'POST'])
def change_user():
    if not is_logged_in():
        return redirect('/login?error=Please+log+in+first')

    user_id = session.get('user_id')
    if request.method == 'POST':
        email = request.form.get('user_email').lower().strip()
        username = request.form.get('username').title().strip()
        password = request.form.get('user_password')
        password2 = request.form.get('user_password2')

        error_message = None

        # Validate field lengths
        if len(email) > 30:
            error_message = "Email must be 30 characters or less!"
        elif len(username) > 30:
            error_message = "Username must be 30 characters or less!"
        elif len(password) > 30:
            error_message = "Password must be 30 characters or less!"
        elif password != password2:
            error_message = "Passwords don't match!"
        elif len(password) < 8:
            error_message = "Password must be at least 8 characters"
            return render_template("change_user.html", error_message=error_message)

        if error_message:
            return render_template("change_user.html", error_message=error_message)

        hashed_password = bcrypt.generate_password_hash(password)

        con = connect_database(DATABASE)

        if con:
            cur = con.cursor()
            cur.execute("SELECT * FROM user WHERE email = ?", (email,))
            existing_email = cur.fetchone()
            if existing_email:
                error_message = "Email already exists"

            cur.execute("SELECT * FROM user WHERE username = ?", (username,))
            existing_username = cur.fetchone()

            if existing_username:
                error_message = "Username already taken"
                # If any validation failed, render template with error

            # Update user info
            update_query = "UPDATE user SET username = ?, email = ?, password = ? WHERE user_id = ?"
            cur.execute(update_query, (username, email, hashed_password, user_id))
            con.commit()
            con.close()

            session['email'] = email
            session['username'] = username

    return render_template("change_user.html", logged_in=True, username=session.get('username'), email=session.get('email'))



