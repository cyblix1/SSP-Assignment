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

app.secret_key = "SSPAssignment"
app.config['MYSQL_HOST'] = config['account']['host']
app.config['MYSQL_USER'] = config['account']['user']
app.config['MYSQL_PASSWORD'] = config['account']['password']
app.config['MYSQL_DB'] = config['account']['db']
app.permanent_session_lifetime = timedelta(minutes=10)
db = MySQL(app)
bcrypt = Bcrypt()

# def check():
#     cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)



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
    if request.form == 'POST' and form2.validate_on_submit():
        return redirect(url_for('update_admin'))
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