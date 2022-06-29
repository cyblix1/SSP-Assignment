from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from Forms import *
from configparser import ConfigParser

app = Flask(__name__)

#properities
file = 'config.properities'
config = ConfigParser()
config.read(file)
app.config['SECRET_KEY']= 'SSP Assignment'
SECRET_KEY = 'SSP Assignment'
app.config['MYSQL_HOST'] = config['account']['host']
app.config['MYSQL_USER'] = config['account']['user']
app.config['MYSQL_PASSWORD'] = config['account']['password']
app.config['MYSQL_DB'] = config['account']['db']
    

app.permanent_session_lifetime = timedelta(minutes=10)
db = MySQL(app)
bcrypt = Bcrypt()



@app.route('/')
@app.route('/home')
def home():
    return render_template('about.html')

#base template
@app.route('/dashboard')
def dashboard():
    return render_template('base_admin.html')

@app.route('/admins', methods=['POST','GET'])
def admins():
    form = CreateAdminForm()
    form2 = UpdateAdminForm()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM staff_accounts')
    all_data = cursor.fetchall()
    if request.form == 'POST'and form.validate_on_submit():
        return redirect(url_for('create_admin'))
    elif request.form == 'POST' and form2.validate_on_submit():
        return redirect(url_for('update_admin'))
    elif form.csrf_token.errors or form2.csrf_token.errors:
        pass
    else:
        pass
    return render_template('admins.html', employees = all_data, form = form, form2=form2)

@app.route('/admins/create_admin', methods=['POST'])
def create_admin():
    form = CreateAdminForm()
    name = form.name.data
    email = form.email.data
    phone = form.phone.data
    description = form.description.data
    password = form.password1.data
    password2 = form.password2.data
    if password != password2:
        flash('passwords does not match')
        return redirect('admins')
    hashedpw = bcrypt.generate_password_hash(password)
    date_created = datetime.utcnow()
    #simple first later check is exists
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    #make account
    cursor.execute('INSERT INTO staff_accounts VALUES (NULL, %s, %s, %s, %s, %s, %s)', (name,email,phone,hashedpw,date_created,description))
    db.connection.commit()
    flash("Employee Added Successfully!")
    return redirect(url_for('admins'))


@app.route('/admins/update_admin', methods=['POST'])
def update_admin():
    form = UpdateAdminForm()
    id = form.id.data
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    name = form.name.data
    email = form.email.data
    phone = form.phone.data
    description = form.description.data
    cursor.execute('UPDATE staff_accounts SET name = %s, email = %s, phone=%s, description=%s WHERE id = %s', (name,email,phone,description,id))
    db.connection.commit()
    flash("Employee updated successfully")
    return redirect(url_for('admins'))

@app.route('/admins/delete_admin/<int:id>/',  methods=['GET','POST'])
def delete_admin(id):
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM staff_accounts WHERE id = %s', [id])
    db.connection.commit()
    flash("Employee deleted successfully")
    return redirect(url_for('admins'))


@app.route('/staff')
def staff():
    return render_template('staff.html')

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s)', (username, password, email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)



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