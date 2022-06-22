from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from datetime import datetime
from Forms import *
app = Flask(__name__)

app.secret_key = "SSP"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
#change to ur own password
app.config['MYSQL_PASSWORD'] = '5zbhihcxqxeS'
app.config['MYSQL_DB'] = 'sspassignment'
db = MySQL(app)
bcrypt = Bcrypt()


@app.route('/')
@app.route('/home')
def home():
    pass

# @loginrequired here
@app.route('/dashboard')
def dashboard():
    return render_template('base_admin.html')

@app.route('/admins')
def admins():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM admin_accounts')
    all_data = cursor.fetchall()
    return render_template('admins.html', employees = all_data)

@app.route('/create_admin', methods=['POST'])
def create_admin():
    form = MakeAdminForm(request.form)
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        hashedpw = bcrypt.generate_password_hash(password)
        date_created = datetime.utcnow()
        #checks if email is aready exists
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor.execute('SELECT * FROM admin_accounts WHERE email = %s', (email)):
            flash('Email Exists')
            return redirect(url_for('admins'))
        elif cursor.execute('SELECT * FROM admin_accounts WHERE phone = %s', (phone)):
            flash('Phone Number exists')
            return redirect(url_for('admins'))
        else:
            #make account
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)', (name,email,phone,hashedpw,date_created))
            db.connection.commit()
            flash("Employee Inserted Successfully")
            return redirect(url_for('admins'))




# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Internal Server Error
@app.errorhandler(500)
def error500(e):
    return render_template('500.html'), 500

# Internal Server Error
@app.errorhandler(403)
def error403(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=True)