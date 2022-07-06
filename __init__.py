from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from Forms import *
from configparser import ConfigParser
import re
from csrf import csrf, CSRFError
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
# csrf.init_app(app)

# @app.errorhandler(CSRFError)
# def handle_csrf_error(e):
#     flash('CSRF token was not found')
#     return render_template('#something')


@app.route('/')
@app.route('/register',methods =['POST','GET'])
def register():
    form = Register_Users()
    if form.validate_on_submit():
        name = form.name.data
        password = form.password1.data
        email = form.email.data
        time = datetime.utcnow()
        password_age=4
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s)",(name,email,password,password_age,time))
        db.connection.commit()
        return redirect(url_for('home'))
    return render_template('register.html',form=form)


@app.route('/home')
def home():
    # userID = User.query.filter_by(id=current_user.id).first()
    # admin_user()
    return render_template('about.html')

@app.route('/checkout')
def checkout_purchase():
    return render_template('checkout.html')


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
    gender = 'M'
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
    cursor.execute('INSERT INTO staff_accounts VALUES (NULL, %s, %s, %s, %s, %s, NULL, %s, %s)', (name,email,phone,gender,hashedpw,description,date_created))
    db.connection.commit()
    flash("Employee Added Successfully!")
    return redirect(url_for('admins'))


@app.route('/admins/update_admin', methods=['POST'])
def update_admin():
    form = UpdateAdminForm()
    id = form.id.data
    name = form.name.data
    email = form.email.data
    phone = form.phone.data
    description = form.description.data
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE staff_accounts SET full_name = %s, email = %s, phone_no=%s, description=%s WHERE staff_id = %s', (name,email,phone,description,id))
    db.connection.commit()
    flash("Employee updated successfully")
    return redirect(url_for('admins'))

@app.route('/admins/delete_admin/<int:id>/',  methods=['GET','POST'])
def delete_admin(id):
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    #checks if exists 
    cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [id])
    hi = cursor.fetchone()
    if hi:
        cursor.execute('DELETE FROM staff_accounts WHERE staff_id = %s', [id])
        db.connection.commit()
        flash("Employee deleted successfully",'error')
    else:
        flash("Employee does not exist")
    return redirect(url_for('admins'))

#customers section
@app.route('/customers')
def customers():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM customer_accounts')
    customers = cursor.fetchall()
    return render_template('customers.html',customers=customers)

@app.route('/customers/delete/<int:id>/', methods=['GET','POST'])
def delete_customer():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute


@app.route('/products')
def products():
    return render_template('products.html')

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
