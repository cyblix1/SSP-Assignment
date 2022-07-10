from flask import Flask, render_template, request, make_response, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from Forms import *
from configparser import ConfigParser
import re
# from freecaptcha import captcha
import uuid
from csrf import csrf, CSRFError
import mysql.connector
from mysql.connector import Error
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from cryptography.fernet import Fernet

app = Flask(__name__)


#properities
file = 'config.properities'
config = ConfigParser()
config.read(file)
# Conguration stuff
app.config['SECRET_KEY']= 'SSP Assignment'
SECRET_KEY = 'SSP Assignment'
app.config['MYSQL_HOST'] = config['account']['host']
app.config['MYSQL_USER'] = config['account']['user']
app.config['MYSQL_PASSWORD'] = config['account']['password']
app.config['MYSQL_DB'] = config['account']['db']
captcha_solutions = {}
captcha_solved = []

#validate email
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
def check(email):
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

@app.route('/captcha')
def login():
    # This means they just submitted a CAPTCHA
    # We need to see if they got it right
    incorrect_captcha = False
    if request.method == 'POST':
        captcha_quess = request.form.get('captcha', None)
        captcha_cookie = request.cookies.get('captcha_cookie')
        real_answer = captcha_solutions.get(captcha_cookie, None)
        if real_answer is not None:
            if int(captcha_quess) == int(real_answer):
                captcha_solved.append(captcha_cookie)
                return redirect("/", code=302)
            else:
                incorrect_captcha = True

    # Select an image
    image_path = captcha.random_image()

    # Generate list of rotated versions of image
    # and save which one is correct
    answer, options = captcha.captchafy(image_path)

    # Provide the CAPTCHA options to the web page using the CAPTCHA
    resp = make_response(render_template("captcha.html", captcha_options=options, incorrect_captcha=incorrect_captcha))

    # Track this user with a cookie and store the correct answer
    # by linking the cookie with the answer, we can check their answer
    # later
    freecaptcha_cookie = str(uuid.uuid4())
    resp.set_cookie('captcha_cookie', freecaptcha_cookie)
    captcha_solutions[freecaptcha_cookie] = answer

    return render_template('captcha.html')
    

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

    elif request.method == 'POST':
        msg = 'Please fill out the form !'
   

        return redirect(url_for('home'))
    return render_template('register.html',form=form)



@app.route('/home')
def home():
    # userID = User.query.filter_by(id=current_user.id).first()
    # admin_user()
    return render_template('captcha.html')

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
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM staff_accounts')
        all_data = cursor.fetchall()
        if request.form == 'POST'and form.validate_on_submit():
            return redirect(url_for('create_admin'))
        elif request.form == 'POST' and form2.validate_on_submit():
            return redirect(url_for('update_admin'))
        elif form.csrf_token.errors or form2.csrf_token.errors:
            pass
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
    return render_template('admins.html', employees = all_data, form = form, form2=form2)

@app.route('/admins/create_admin', methods=['POST','GET'])
def create_admin():
    form = CreateAdminForm()
    name = form.name.data
    email = form.email.data
    phone = form.phone.data
    gender = form.gender.data
    description = form.description.data
    password = form.password1.data
    password2 = form.password2.data
    hashedpw = bcrypt.generate_password_hash(password)
    date_created = datetime.utcnow()
    if password != password2:
        flash('passwords does not match',category="danger")
        return redirect(url_for('admins'))
    elif check(email) == False:
        flash('Invalid email')
    else:
        email = email.encode
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted_email = f.encrypt(email)
    #simple first later check is exists
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO staff_accounts VALUES (NULL, %s, %s, %s, %s, %s, NULL, %s, %s)', (name,encrypted_email,phone,gender,hashedpw,description,date_created))
        db.connection.commit()
        flash("Employee Added Successfully!",category="success")
        return redirect(url_for('admins'))


@app.route('/admins/update_admin', methods=['POST'])
def update_admin():
    form = UpdateAdminForm()
    id = form.id.data
    name = form.name.data
    email = form.email.data
    phone = form.phone.data
    description = form.description.data
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('UPDATE staff_accounts SET full_name = %s, email = %s, phone_no=%s, description=%s WHERE staff_id = %s', (name,email,phone,description,id))
            db.connection.commit()
            flash("Employee updated successfully", category="success")
        else:
            flash('Something went wrong!')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:    
        cursor.close()
        db.connection.close()
        return redirect(url_for('admins'))

@app.route('/admins/delete_admin/<int:id>/',  methods=['GET','POST'])
def delete_admin(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #checks if exists 
        cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [id])
        account = cursor.fetchone()
        if account:
            cursor.execute('DELETE FROM staff_accounts WHERE staff_id = %s', [id])
            db.connection.commit()
            flash("Employee deleted successfully",category="success")
        #user no exists
        elif account is None:
            flash("Employee does not exist",category="danger")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('admins'))

#customers section
@app.route('/customers')
def customers():
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('SELECT * FROM customer_accounts')
            customers = cursor.fetchall()
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
    return render_template('customers.html',customers=customers)

@app.route('/customers/delete/<int:id>/', methods=['GET','POST'])
def delete_customer():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute


@app.route('/products')
def products():
    return render_template('products.html')


@app.route('/profile')
def profile():
    return render_template('profile.html')
    
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
