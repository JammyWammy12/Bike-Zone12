from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'super secret key'

DATABASE = 'project1'
bcrypt = Bcrypt(app)


def is_logged_in():
    if (session.get('user_id') is None):
        print("Not logged in!")
        return False
    else:
        print("Logged in broski!")
        return True


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
    if 'user_id' in session:
        con = connect_database(DATABASE)
        if con:
            cur = con.cursor()
            query = "SELECT first_name, last_name FROM user WHERE user_id = ?"
            cur.execute(query, (session['user_id'],))
            user = cur.fetchone()
            con.close()

             # Extract first_name from tuple

    return render_template('home.html', user=user, logged_in=is_logged_in())


@app.route('/sign', methods=['POST', 'GET'])
def render_sign_page():
    if request.method == 'POST':
        fname = request.form.get('user_fname').title().strip()
        lname = request.form.get('user_lname').title().strip()
        email = request.form.get('user_email').lower().strip()
        password = request.form.get('user_password')
        password2 = request.form.get('user_password2')
        user_class = request.form.get('user_role')  # Retrieve selected role

        if password != password2:
            return redirect("/sign?error=passwords+do+not+match")

        if len(password) < 8:
            return redirect("/sign?error=password+must+be+8+long")

        hashed_password = bcrypt.generate_password_hash(password)



        con = connect_database(DATABASE)
        if con:
            cur = con.cursor()
            query_insert = "INSERT INTO user (first_name, last_name, email, password, class) VALUES (?, ?, ?, ?, ?)"
            cur.execute(query_insert, (fname, lname, email, hashed_password,user_class))
            con.commit()
            con.close()
            return redirect("/login")  # Redirect to login page after signing up

    return render_template('sign.html')



@app.route('/login', methods=['POST', 'GET'])
def render_login_page():

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

            if user_info:

                if user_info[2] == password:
                    session['user_id'] = user_info[1]
                    session['email'] = user_info[0]
                    print(session)



                    return redirect("/")

        return redirect("/login?error=invalid+credentials")

    return render_template('login.html', logged_in=is_logged_in())




@app.route('/sessions', methods=['POST', 'GET'])
def render_sessions_page():
    if request.method == 'POST':
        name = request.form.get('name1').title().strip()
        subject = request.form.get('subject').title().strip()
        date = request.form.get('date').title().strip()



        con = connect_database(DATABASE)
        if con:
            cur = con.cursor()
            query_insert = "INSERT INTO sessions (name, date, subject) VALUES (?, ?, ?)"
            cur.execute(query_insert, (name, date, subject))
            con.commit()
            con.close()
            return redirect("/sessions")




    return render_template('sessions.html', logged_in=is_logged_in())

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login?message=logged+out')


