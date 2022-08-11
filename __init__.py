# from crypt import methods
from distutils import ccompiler
from distutils.util import byte_compile
from email.message import Message
from mimetypes import init
from pydoc import render_doc
# from nis import cat
# from nis import cat
from tkinter import Image
from tkinter.tix import Tree
from flask import Flask, render_template, request, make_response, redirect, url_for, session,flash, json
from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
from flask_bcrypt import Bcrypt
from datetime import date, datetime, timedelta
from pymysql import NULL
from Forms import *
from configparser import ConfigParser
import re
import requests
# from freecaptcha import captcha
import uuid
from csrf import csrf, CSRFError
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from validations import *
# from verify import email_verification
from flask_mail import Mail,Message

# import stripe
import logging
from logging.config import dictConfig , fileConfig

from random import *



import smtplib
from logging.handlers import SMTPHandler
from email.message import EmailMessage


app = Flask(__name__)
#properities
file = 'config.properties'
config = ConfigParser()
config.read(file)
# Conguration stuff
app.config['SECRET_KEY']= 'SSP Assignment'
SECRET_KEY = 'SSP Assignment'
app.config['MYSQL_HOST'] = config['account']['host']
app.config['MYSQL_USER'] = config['account']['user']
app.config['MYSQL_PASSWORD'] = config['account']['password']
app.config['MYSQL_DB'] = config['account']['db']
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes = 15)
app.config['RECAPTCHA_PUBLIC_KEY'] = "6Ldzgu0gAAAAAKF5Q8AdFeTRJpvl5mLBncz-dsBv"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Ldzgu0gAAAAANuXjmXEv_tLJLQ_s7jtQV3rPwX2"
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51LM6HwJDutS1IqmOR34Em3mZeuTsaUwAaUp40HLvcwrQJpUR5bR60V1e3kkwugBz0A8xAuXObCpte2Y0M251tBeD00p16YXMgE'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51LM6HwJDutS1IqmOFhsHKYQcSM2OEF8znqltmmy2vcQCkRUMiKyJrQunP0OlJji6Nlg142NVZ8CpTaMJgZLzzucx00tx6FdjY0'

# app.config["MAIL_SERVER"]='smtp.gmail.com'
# app.config["MAIL_PORT"]=465
# app.config["MAIL_USERNAME"]=config['email']['mail']
# app.config['MAIL_PASSWORD']=config['email']['password']
# app.config['MAIL_USE_TLS']=False
# app.config['MAIL_USE_SSL']=True
# stripe.api_key = app.config['STRIPE_SECRET_KEY']

bcrypt2 = Bcrypt()
mail=Mail(app)
db = MySQL(app)

# dictConfig({
#     'version': 1,
#     'disable_existing_loggers': False,
#     'formatters': {
#             'default': {
#                         'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
#                        },
#             'simpleformatter' : {
#                         'format' : '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
#             }
#     },
#     'handlers':
#     {
#         'custom_handler': {
#             'class' : 'logging.FileHandler',
#             'filename' : 'warnings.log',
#                         'level': 'WARN',
#         }
#     },
#     'root': {
#         'level': 'WARN',
#         'handlers': ['custom_handler'],
#     },
# })

# fileConfig('logging.cfg')

smtp_handler = SMTPHandler(mailhost=('smtp.gmail.com', 587),
                            fromaddr='chamsamuel01@gmail.com',
                            toaddrs=['boyixin823@logodez.com','chamsamuel01@gmail.com'],
                            subject='A dashing subject',
                            credentials=("chamsamuel01@gmail.com","giyvimnfxcmvszsr"),
                            secure=None)

# smtp_handler.setLevel(logging.INFO)
# formatter = logging.Formatter('%(asctime)s : %(funcName)s : %(levelname)s : %(name)s : %(message)s')
smtp_handler.setFormatter(logging.Formatter('%(asctime)s : %(funcName)s : %(levelname)s : %(name)s : %(message)s'))
# smtp_handler.setFormatter(formatter)
if not app.debug:
    app.logger.addHandler(smtp_handler)

import logging.handlers

#Define Logger
logger = logging.getLogger("SSH_Parser")

#Set the Minimum Log Level for logger
logger.setLevel(logging.DEBUG)

#Create Handlers(Filehandler with filename| StramHandler with stdout)
file_handler_info = logging.FileHandler('app.log')
# smtp_handler = SMTPHandler(mailhost=('smtp.gmail.com', 587),
#                             fromaddr='chamsamuel01@gmail.com',
#                             toaddrs=['boyixin823@logodez.com','chamsamuel01@gmail.com'],
#                             subject='A dashing subject',
#                             credentials=("chamsamuel01@gmail.com","giyvimnfxcmvszsr"),
#                             secure=None)

#Set Additional log level in Handlers if needed
file_handler_info.setLevel(logging.INFO)
smtp_handler.setLevel(logging.WARNING)

#Create Formatter and Associate with Handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s')
file_handler_info.setFormatter(formatter)
smtp_handler.setFormatter(formatter)

#Add Handlers to logger
logger.addHandler(file_handler_info)
logger.addHandler(smtp_handler)




file_name = "app.log"
file = open(file_name, "r")
data_list = []
order = ["date", "url", "type", "message"]

for line in file.readlines():
    details = line.split("|")
    details = [x.strip() for x in details]
    structure = {key: value for key, value in zip(order, details)}
    data_list.append(structure)



# @app.route("/logs")
# def main():
#     app.logger.debug("debug")
#     app.logger.info("info")
#     app.logger.warning("warning")
#     app.logger.error("error")
#     app.logger.critical("critical")
#     return ""

# logger = logging.getLogger('dev')
# logger.info('This is an information message')

@app.before_first_request
def before_first_request():
    log_level = logging.ERROR

    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)

    root = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(root, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    log_file = os.path.join(logdir, 'app.log')
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)
    app.logger.addHandler(handler)

    app.logger.setLevel(log_level)

    defaultFormatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(defaultFormatter)


class checks_exists:
    def check_staff_email(email_address_to_check):
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM staff_email_hash')
            all_staff = cursor.fetchall()
        except Error as e:
            print('Database Error!',{e})      
        finally:
            cursor.close()
            for staff in all_staff:
                staff_email_hash = (staff['email_hash']).encode()
                if bcrypt.checkpw(email_address_to_check.encode(),staff_email_hash):
                    #if staff exists
                    return True
                else:
                    return False
   
@app.route('/register',methods =['POST','GET'])
def register():
    form = Register_Users()
    if form.is_submitted() and request.method == 'POST' and RecaptchaField != NULL:
        name = form.name.data
        question = form.question.data
        answer = form.answer.data
        password = form.password1.data
        hashpassword = bcrypt2.generate_password_hash(password)
        password2 = form.password2.data
        if password != password2:
            flash('passwords do not match',category='danger')

            return redirect(url_for('register'))
        elif password == password2:
            flash('Account created successfully!')
        email = form.email.data
        time = datetime.utcnow()
        password_age=4
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        # print('INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s)',(name,email,hashpassword,password_age,time))
        cursor.execute('INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s)',(name,email,question,answer,hashpassword,password_age,time,))
        cursor.execute('INSERT INTO logs_login (log_id ,description, date_created) VALUES (NULL,concat("User ",%s," has registered"),%s)',(name, time))

        db.connection.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        # Create variables for easy access
        email = form.email.data
        password = form.password1.data
        login_time = datetime.utcnow()
        #check if its staff account
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #decryption later + salted hashing + login history
        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM customer_accounts WHERE email = %s',[email])
        # Fetch one record and return result
        account = cursor.fetchone()
        if account: 
            user_hashpwd = account['hashed_pw']
            if bcrypt2.check_password_hash(user_hashpwd, password):
                id = account['customer_id']
                # Create session data, we can access this data in other routes
                cursor.execute('SELECT max(login_attempt_no) AS last_login FROM customer_login_history WHERE customer_id = %s',[id])
                acc_login = cursor.fetchone()
                #means first login
                if acc_login['last_login'] is None:
                    #means first login
                    zero = 1
                    cursor.execute('INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',(id,zero,login_time))
                    db.connection.commit()
                    session['loggedin'] = True
                    session['id'] = account['customer_id']
                    session['name'] = account['full_name']
                    session['email']= account['email']
                    session['customer_login_no'] = 1
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(minutes = 15)
                    # Redirect to home page
                    cursor.execute('INSERT INTO logs_login (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has logged in"),%s)',(id,login_time))
                    db.connection.commit()
                    return redirect(url_for('market'))
                # elif acc_login['last_login'] == 3 :
                #     flash('TOO MANY LOGIN ATTEMPTS', category='danger')
                #     return redirect(url_for('logout'))
                #means not first login
                else:
                        next_login_attempt = acc_login['last_login'] +1
                        cursor.execute('INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',(id,next_login_attempt,login_time))
                        db.connection.commit()
                        session['loggedin'] = True
                        session['id'] = account['customer_id']
                        session['name'] = account['full_name']
                        session['customer_login_no'] = int(next_login_attempt)
                        # Redirect to home page
                        cursor.execute('INSERT INTO logs_login (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has logged in"," (Number of Times: ",%s, ")"),%s)',(id, next_login_attempt ,login_time))
                        db.connection.commit()
                        return redirect(url_for('market'))
        else:
            #check for staff account
            cursor.execute('SELECT * FROM staff_email_hash')
            all_staff = cursor.fetchall()
            #check if email exists
            id = 0
            for staff in all_staff:
                hash = (staff['email_hash']).encode()
                if bcrypt.checkpw(email.encode(),hash):
                    id = staff['staff_id']
                    break
            #decryption of email
            #get key
            if id == 0:
                #checks for admin accounts 
                cursor.execute('SELECT * from admin_accounts')
                admin = cursor.fetchone()
                if admin['email'] == email and admin['password'] == password:
                    session['loggedin3'] = True
                    session['id'] = admin['admin_id']
                    session['name'] = admin['full_name']
                    flash(f"Successfully logged in as {admin['full_name']}!",category="success")
                    return redirect(url_for('admins'))
                else:
                    flash('invalid login details')
                    return redirect(url_for('login'))
            else:
                cursor.execute('SELECT staff_key FROM staff_key WHERE staff_id = %s',[id])
                columns = cursor.fetchone()
                staff_key = columns['staff_key']
                #Get account information
                cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s',[id])
                staff = cursor.fetchone()
                #check password hash
                if staff and bcrypt.checkpw(password.encode(),staff['hashed_pw'].encode()):
                    #decrypt email
                    f = Fernet(staff_key)
                    encrypted_email = staff['email']
                    decrypted = f.decrypt(encrypted_email.encode())
                    if decrypted:
                        session['loggedin2'] = True
                        session['id'] = id
                        session['name'] = staff['full_name']
                        flash(f"Successfully logged in as {staff['full_name']}!",category="success")
                        return redirect(url_for('customers'))
            
    return render_template('login.html', form=form)

@app.route('/forgetpassword1', methods=['GET', 'POST'])
def forgetpassword1():
    form = ForgetPassword(request.form)
    if request.method == 'POST':
        email_forget = form.email.data
        login_time = datetime.utcnow()
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [email_forget])
        account_forget = cursor.fetchone()
        if account_forget:
            if email_forget == account_forget['email']:
                id = account_forget['customer_id']
                session['forget_pw'] = account_forget['email']
                cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has been verififed for Forget Password"),%s)',(id, login_time))
                db.connection.commit()
                return redirect(url_for('forgetpassword2'))
        else:
            flash("Please Verify Again", category="success")
            return redirect(url_for('login'))

    return render_template('forgetpassword.html', form=form)

@app.route('/forgetpassword2', methods=['GET', 'POST'])
def forgetpassword2():
    form = ForgetPassword(request.form)
    # email_forget = form.email.data
    password_forget = form.password.data
    login_time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    # cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [email_forget])
    # user_email = cursor.fetchone()
    user_id_forget = 'hello'
    msg = EmailMessage()
    msg.set_content("This is your OTP {}".format(user_id_forget))
    msg["Subject"] = "An Email Alert"
    msg["From"] = "chamsamuel01@gmail.com"
    msg["To"] = session['forget_pw']

    with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
        smtp.starttls()
        smtp.login(msg["From"], "giyvimnfxcmvszsr")
        smtp.send_message(msg)

    if request.method == 'POST':
            if password_forget == user_id_forget:
                cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has been verififed2 for Forget Password"),%s)',(1, login_time))
                cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [session['forget_pw']])
                # Fetch one record and return result
                account = cursor.fetchone()
                session['id'] = account['customer_id']
                db.connection.commit()
                return redirect(url_for('updatePassword'))

            else:
                flash("Forget Password Unsuccessfully, Try Again!", category="success")
                return redirect(url_for('login'))
    else:
        return render_template('forgetpassword2.html', form=form)

@app.route('/logout')
def logout():
    if 'loggedin' in session:
        id=session['id']
        login_num=session['customer_login_no']
# Remove session data, this will log the user out
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        logout_time = datetime.utcnow()
        #Once fix this done alr
        cursor.execute('UPDATE customer_login_history SET logout_time = %s WHERE customer_id = %s AND login_attempt_no = %s',(logout_time,id,login_num))
        cursor.execute('INSERT INTO logs_login (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has logged out"),%s)',(id, logout_time))
        db.connection.commit()
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('name', None)
        session.pop('customer_login_no',None)
        flash('Successfully logged out')
        # Redirect to login page]
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


# @app.route('/')
# Verify the strength of 'password'
#Returns a dict indicating the wrong criteria
#A password is considered strong if:
        #8 characters length or more
        #1 digit or more
        #1 symbol or more
        #1 uppercase letter or more
        #1 lowercase letter or more
def password_check(password):

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }
@app.route('/updatepassword', methods=['GET', 'POST'])
def updatePassword():
    id=session['id']
    form = UpdatePassword(request.form)
    oldpassword = form.oldpassword.data
    newpassword = form.newpassword.data
    confirmpassword = form.confirmpassword.data
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
    # Fetch one record and return result
    account = cursor.fetchone()
    user_hashpwd = account['hashed_pw']

    if request.method == 'POST':
        if newpassword == confirmpassword:
            if bcrypt2.check_password_hash(user_hashpwd, newpassword):
                flash("Same Password as Old , Try Again", category="success")
                return redirect(url_for('updatePassword'))
            
            elif bcrypt2.check_password_hash(user_hashpwd, oldpassword):
                flash("Please enter the correct old password")
                return redirect(url_for('updatePassword'))

            else:
                update_hashpassword = bcrypt2.generate_password_hash(newpassword)
                cursor.execute('UPDATE customer_accounts SET hashed_pw = %s WHERE customer_id = %s',(update_hashpassword, id))
                db.connection.commit()
                flash("Successful", category="success")
                return redirect(url_for('login'))

    else:
        return render_template('updatePassword.html', form=form)





@app.route('/')
def home():
    if 'loggedin' in session:
        # User is loggedin show them the home page
        id=session['id']
        login_num=session['customer_login_no']
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT login_time FROM customer_login_history WHERE customer_id =%s and login_attempt_no =%s',(id, login_num))
        logintime = cursor.fetchone()
        return render_template('home.html',id=session['id'], name=session['name'],logintime=logintime)
# User is not loggedin redirect to login page
    flash('Session timeout')
    return redirect(url_for('login'))




#base template
@app.route('/dashboard')
def dashboard():
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM logs_login')
                login = cursor.fetchall()
                cursor.execute('SELECT * FROM logs_product')
                products = cursor.fetchall()
                cursor.execute('SELECT * FROM logs_error')
                error = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('dashboard.html', items=login , products = products, error = error  )
    else:
        flash('You are not allowed to access this page', category='danger')
        return redirect(url_for('login'))



@app.route('/admins', methods=['POST','GET'])
def admins():
    form2 = UpdateAdminForm()
    form = CreateAdminForm()
    if 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM staff_accounts')
            all_data = cursor.fetchall()
            for staff in all_data:
                id = staff['staff_id']
                cursor.execute('SELECT * FROM staff_key WHERE staff_id=%s',[id])
                staff_key = cursor.fetchone()
                key_staff = staff_key['staff_key'].encode()
                fernet = Fernet(key_staff)    
                decrypted = fernet.decrypt(staff['email'].encode())
                staff['email'] = decrypted.decode()
            if request.form == 'POST' and form2.validate_on_submit():
                return redirect(url_for('update_admin'))
            elif request.form == 'POST' and form.validate_on_submit():
                return redirect(url_for('create_admin'))
            elif form2.csrf_token.errors or form.csrf_token.errors:
                pass
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('admins.html', employees = all_data, form2=form2,form=form)
    elif 'loggedin2' in session:
        flash('You are not allowed into this section',category='danger')
        return redirect(url_for('customers'))
    else:
        flash('Error,you are not logged in')
        return redirect(url_for('login'))

@app.route('/create_admin', methods=['POST','GET'])
def create_admin(): 
    form = CreateAdminForm()   
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        phone = form.phone.data
        gender = form.gender.data
        description = form.description.data
        password = form.psw.data
        password2 = form.password2.data
        date_created = datetime.utcnow()
        #Server side validations
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('SELECT * FROM staff_email_hash')
            all_staff = cursor.fetchall()
            #check if email exists
            for staff in all_staff:
                if bcrypt.checkpw(email.encode(),staff['email_hash'].encode()):
                    flash('Email exists!',category="danger")
                    return redirect(url_for('admins'))
                continue
            if password != password2:
                flash('passwords does not match',category="danger")
                return redirect(url_for('admins'))
            #server side confirmations 
            elif Validations.validate_password(password) == False:
                flash('Invalid password',category="danger")
                return redirect(url_for('admins'))
            elif Validations.validate_email(email) == False:
                flash('Invalid email',category="danger")
                return redirect(url_for('admins'))
            else:
                  #hashing password 
                salt = bcrypt.gensalt()        
                hashedpw = bcrypt.hashpw(password.encode(),salt)

                #hashing email to find it later in login 
                email_salt = bcrypt.gensalt()
                hashed_email = bcrypt.hashpw(email.encode(),email_salt)
                #encryption of email using password, getting key using salt
                encoded_password = password.encode()
                salt = b'\x829\xf0\x9e\x0e\x8bl;\x1a\x95\x8bB\xf9\x16\xd4\xe2'
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend())
                key = base64.urlsafe_b64encode(kdf.derive(encoded_password))

                #encrypting email
                encoded_email = email.encode()
                encoded_email = email.encode()
                f = Fernet(key)
                encrypted_email = f.encrypt(encoded_email)
                cursor.execute('INSERT INTO staff_accounts VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s)', (name,encrypted_email,phone,gender,hashedpw.decode(),30,description,date_created))
                db.connection.commit()

                #get staff-id + sorting key
                cursor.execute('SELECT staff_id FROM staff_accounts WHERE email = %s',[encrypted_email])
                staff_id = cursor.fetchone()
                #store email encryption key
                cursor.execute('INSERT INTO staff_key VALUES (%s,%s)',((staff_id['staff_id']),key.decode()))
                #store email hash
                cursor.execute('INSERT INTO staff_email_hash VALUES (%s,%s)',((staff_id['staff_id']),hashed_email.decode()))
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

@app.route('/admins/delete_admin/<int:id>', methods=['POST'])
def delete_admin(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #checks if exists 
        cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [id])
        account = cursor.fetchone()
        if account:
            #have to delete the outer stuff
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
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM customer_accounts')
                customers = cursor.fetchall()
                for customer in customers:
                    cursor.execute('SELECT login_attempt_no,login_time,logout_time FROM customer_login_history WHERE customer_id=%s',[customer['customer_id']])
                    login_logs= cursor.fetchall()
                    customer['history'] = login_logs
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('customers.html',customers=customers)
    else:
        flash('Error,you are not logged in')
        return redirect(url_for('login'))


@app.route('/customers/delete/<int:id>/', methods=['GET','POST'])
def delete_customer(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #checks if exists 
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
        account = cursor.fetchone()
        if account:
            cursor.execute('DELETE FROM customer_accounts WHERE customer_id = %s', [id])
            db.connection.commit()
            flash("Employee deleted successfully",category="success")
        #user no exists
        elif account is None:
            flash("Customer does not exist",category="danger")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
            db.connection.close()
            return redirect(url_for('login'))



@app.route('/profile',methods=['GET','POST'])
def profile():
    name_form = Update_Name()
    email_form = Update_Email()
    gender_form = Update_Gender()
    if 'loggedin' in session:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [session['id']])
        account = cursor.fetchone()
        return render_template('profile.html',account=account,name_form=name_form,email_form=email_form,gender_form=gender_form)
    elif 'loggedin' not in session:
        flash('Session timeout')
    return redirect(url_for('login'))



@app.route('/admin_profile',methods=['GET','POST'])
def admin_profile():
    name_form = Update_Name()
    email_form = Update_Email()
    gender_form = Update_Gender()
    if 'staffloggedin' in session:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [session['id']])
        account = cursor.fetchone()
        return render_template('admin_profile.html',account=account,name_form=name_form,email_form=email_form,gender_form=gender_form)
    else:
        flash('please login')
        return redirect(url_for('login'))


#for customer use, can implement 2fa confirmation
@app.route('/profile/customer_delete/<int:id>',methods=['GET','POST'])
def customer_delete(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #checks if exists 
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
        account = cursor.fetchone()
        if account:
            cursor.execute('DELETE FROM customer_accounts WHERE customer_id = %s', [id])
            db.connection.commit()
            flash("Deleted successfully",category="success")
        #user no exists
        elif account is None:
            flash("Something went wrong! Data does not exist!")
        else:
            flash("Something went wrong, please try again!",category="danger")
            return redirect(url_for('profile'))
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('login'))

# incomplete need session
@app.route("/profile/update_name/<name>/<int:id>")
def update_name(name,id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
        account = cursor.fetchone()
        #acc exists
        if account:
            cursor.execute('UPDATE customer_accounts SET full_name = %s WHERE customer_id = %s', (name,id))
        elif account is None:
            flash("account doesnt exist")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        redirect(url_for('profile'))


# incomplete need session
@app.route("/profile/update_email/<email>")
def update_email(email,id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
        account = cursor.fetchone()
        #acc exists
        if account:
            cursor.execute('UPDATE customer_accounts SET email = %s WHERE customer_id = %s', (email,id))
        elif account is None:
            flash("account doesnt exist")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        redirect(url_for('profile'))

@app.route('/logoutstaff')
def logoutstaff():
    if 'loggedin2' in session:
        session.pop('loggedin2', None)
        session.pop('id', None)
        session.pop('name', None)
        flash('Successfully logged out')
        # Redirect to login page
        return redirect(url_for('login'))
    elif 'loggedin3' in session:
        session.pop('loggedin3',None)
        session.pop('id',None)
        session.pop('name',None)
        flash('Successfully logged out')
        # Redirect to login page
        return redirect(url_for('login'))
    else:
        flash('Something went wrong!')

# incomplete need session
@app.route("/profile/update_gender/<gender>")
def update_gender(gender):
    pass


@app.route('/products')
def products():
    form = Create_Products()
    form2 = Update_Products()
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM products')
                products = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('products.html', items=products,form=form , form2 = form2)
    else:
        flash('Something went wrong!, please relog')
        return redirect(url_for('login'))

@app.route('/create_products', methods=['POST','GET'])
def create_products():
    form = Create_Products()
    try:
        if form.validate_on_submit():
            product_id = uuid.uuid4()
            name = form.product_name.data
            price = form.price.data
            description = form.description.data
            time = datetime.utcnow()

            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO products VALUES (%s, %s, %s, %s)', (product_id,name,price,description))
            cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("Admin has created product (ID :",%s," )"),%s)',(product_id, time))
            db.connection.commit()
            flash("Product Added Successfully!",category="success")
            return redirect(url_for('products'))

    except Exception :
        flash("Error Adding Products", category="error")
        return redirect(url_for('products'))

    return render_template('AddItem.html', add_item_form=form)

@app.route('/products/delete_products/<id>/',  methods=['POST'])
def delete_products(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM products WHERE product_id = %s', [id])
        account = cursor.fetchone()
        if account:
            time = datetime.utcnow()
            cursor.execute('DELETE FROM products WHERE product_id = %s', [id])
            cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("Admin has deleted product from shopping cart (ID :",%s," )"),%s)',(id, time))

            db.connection.commit()
            flash("Product deleted successfully",category="success")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('products'))


@app.route('/products/update_products/<id>/', methods=['POST'])
def update_products(id):
    form = Update_Products()
    name = form.product_name.data
    price = form.price.data
    description = form.description.data
    time = datetime.utcnow()

    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('UPDATE products SET product_name = %s, price = %s, description =%s WHERE product_id = %s', (name,price,description,id))
            cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("Admin has updated product from shopping cart (ID :",%s," )"),%s)',(id, time))

            db.connection.commit()
            flash("Products updated successfully", category="success")
        else:
            flash('Something went wrong!')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
        flash("Error Updating Products", category="error")
        return redirect(url_for('products'))
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('products'))

@app.route('/market')
def market():
    if 'loggedin' in session:
        id=session['id']
        login_num=session['customer_login_no']
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM products')
                products = cursor.fetchall()
                cursor.execute('SELECT * FROM shopping_cart')
                shopping_cart = cursor.fetchall()
                cursor.execute('SELECT login_time FROM customer_login_history WHERE customer_id =%s and login_attempt_no =%s',(id, login_num))
                logintime = cursor.fetchone()
                
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('market.html', items=products, cart = shopping_cart,id=session['id'], name=session['name'], logintime=logintime)
    else:
        flash("Please LOG IN!", category="error")
        return redirect(url_for('login'))

@app.route('/add_to_checkout', methods=['POST'])
def add_to_checkout():
    customer_id = session['id']
    time = datetime.utcnow()
    product_id = str(request.form['product-value'])
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM products WHERE product_id = %s ', [product_id])
        sc = cursor.fetchall()
        for i in sc:
            name = i['product_name']
            price = i['price']
            description = i['description']
        cursor.execute('INSERT INTO shopping_cart (product_id, product_name, price , description, customer_id) VALUES (%s,%s,%s,%s,%s)',(product_id,name,price, description, customer_id))
        cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("User (",%s,") has added product to Shopping Cart (ID :",%s," )"),%s)',(customer_id,product_id, time))
        db.connection.commit()
    except:
        flash("NO", category="error")


    return redirect(url_for('market'))

@app.route('/check_sc', methods=['POST','GET'])
def check_sc():
    if 'loggedin' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT sum(price) as price FROM shopping_cart')
            total = cursor.fetchall()
            for i in total:
                if i['price'] > 1000:
                    flash('Please do a Verification as Amount is too big', category="success")
                    return redirect(url_for('checkout_verification2'))
                else:
                    return redirect(url_for('checkout'))
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        except:
            return redirect(url_for('market'))
    else:
        flash("Please LOG IN!", category="error")
        return redirect(url_for('login'))

@app.route('/checkout', methods=['POST', 'GET'])
def checkout():
    customer_id = session['id']
    if 'loggedin' in session:
        # session_checkout = stripe.checkout.Session.create(
        #     payment_method_types=['card'],
        #     line_items=[{
        #         'price': 'price_1LMQn6JDutS1IqmOYxizfOAB',
        #         'quantity': 1,
        #     }],
        #     mode='payment',
        #     success_url=url_for('orders', _external=True),
        #     cancel_url=url_for('market', _external=True),
        # )
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM shopping_cart WHERE customer_id = %s ', [customer_id])
                products = cursor.fetchall()
                cursor.execute('SELECT sum(price) as price FROM shopping_cart')
                total = cursor.fetchall()


        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('checkout.html', cart_items=products , total = total )
        # checkout_session_id = session_checkout['id'],
        # checkout_public_key = app.config['STRIPE_PUBLIC_KEY']
    else:
        flash("Please LOG IN!", category="error")
        return redirect(url_for('login'))

@app.route('/payment1', methods=['POST','GET'])
def payment():
    form = Add_Card_Details()
    if request.method == 'POST':
        card_number = form.card_number.data
        card_name = form.card_name.data
        card_date = form.card_date.data
        card_cvc = form.card_cvc.data

        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO payment VALUES (%s, %s, %s, %s)', (card_number,card_date,card_name,card_cvc))
        db.connection.commit()
        flash("Card Added Successfully!", category="success")
        return redirect(url_for('market'))


    return render_template('payment.html', form =form)

@app.route('/checkout_verification', methods=['POST','GET'])
def checkout_verification():
    form = LoginForm(request.form)
    customer_id = session['id']
    if request.method == 'POST':
        password = form.password1.data
        email = form.email.data
        login_time = datetime.utcnow()
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [customer_id])
        account = cursor.fetchone()
        if email == account['email']:
            user_hashpwd = account['hashed_pw']
            if bcrypt2.check_password_hash(user_hashpwd, password):
                cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("User ID (",%s,") has been verififed for checkout"),%s)',(customer_id, login_time))
                db.connection.commit()
                return redirect(url_for('orders'))
            else:
                flash("Please Verify Again", category="success")
                return redirect(url_for('checkout'))
        else:
            flash("Please Verify Again", category="success")
            return redirect(url_for('checkout'))

    return render_template('checkout_verification.html', form=form)

@app.route('/checkout_verification2', methods=['POST','GET'])
def checkout_verification2():
    form = ShoppingCart_Validation(request.form)
    password_sc = form.password.data
    login_time = datetime.utcnow()
    customer_id = session['id']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT email FROM customer_accounts WHERE customer_id = %s',[customer_id])
    # Fetch one record and return result
    user_email = cursor.fetchone()
    cursor.execute('SELECT max(sc_status) as sc_status FROM sc_attempts WHERE customer_id = %s',[customer_id])
    status_sc = cursor.fetchone()
    cursor.execute('SELECT max(attempts) AS attempts FROM sc_attempts WHERE customer_id = %s',[customer_id])
    acc_sc = cursor.fetchone()
    db.connection.commit()

    if status_sc['sc_status'] is None:
        attempted = 1
        user_checkout_id = randint(000000,999999)
        # retry_time = datetime.utcnow() + timedelta(minutes=30)
        cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time) VALUES (%s,%s,%s,%s,%s)',(user_checkout_id, attempted, customer_id, 0,login_time))
        db.connection.commit()
        cursor.execute('SELECT unique_otp FROM sc_attempts WHERE customer_id = %s',[customer_id])
        unique_otp_sc = cursor.fetchone()
        msg = EmailMessage()
        msg.set_content("This is your OTP {}".format(unique_otp_sc['unique_otp']))
        msg["Subject"] = "An Email Alert"
        msg["From"] = "chamsamuel01@gmail.com"
        msg["To"] = user_email['email']

        with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
            smtp.starttls()
            smtp.login(msg["From"], "giyvimnfxcmvszsr")
            # smtp.login(msg["From"], "boktzsjhixxajuix")
            smtp.send_message(msg)

        if request.method == 'POST':
                if password_sc == unique_otp_sc['unique_otp']:
                    # cursor.execute('INSERT INTO sc_attempts (unique_id ,product_attempts,customer_id,sc_status) VALUES (%s,%s,%s,%s)',(unique_id_sc['unique_id'], attempted, customer_id, 1))
                    cursor.execute('UPDATE sc_attempts SET unique_otp =%s ,attempts =%s ,customer_id =%s ,sc_status =%s ,attempt_time= %s WHERE customer_id = %s and unique_id = %s',(1, customer_id))
                    db.connection.commit()
                    return redirect(url_for('checkout'))

                else:
                    # cursor.execute('INSERT INTO sc_attempts (unique_id ,product_attempts,customer_id,sc_status) VALUES (%s,%s,%s,%s)',
                    #     (user_checkout_id, attempted, customer_id, 0))
                    flash("OTP Unsuccessfully, Try Again!", category="success")
                    db.connection.commit()
                    return redirect(url_for('checkout_verification2'))
        else:
            return render_template('checkout_verification2.html', form=form)

    elif status_sc['sc_status'] == 0:
        if acc_sc['attempts'] < 4:
            cursor.execute('SELECT unique_otp FROM sc_attempts WHERE customer_id = %s', [customer_id])
            acc_uuid = cursor.fetchone()
            db.connection.commit()
            if request.method == 'POST':
                next_sc_attempt = acc_sc['attempts'] + 1
                if password_sc == acc_uuid['unique_otp']:
                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time) VALUES (%s,%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,1,login_time))
                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))
                    db.connection.commit()
                    return redirect(url_for('checkout'))
                else:
                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time) VALUES (%s,%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,0,login_time))
                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))
                    flash("TRY",category="success")
                    db.connection.commit()

                    return redirect(url_for('checkout_verification2'))
            else:
                return render_template('checkout_verification2.html', form=form)
        elif acc_sc['attempts'] == 4:
            flash("This is your Last Attempt", category="success")
            cursor.execute('SELECT unique_otp FROM sc_attempts WHERE customer_id = %s', [customer_id])
            acc_uuid = cursor.fetchone()
            db.connection.commit()
            if request.method == 'POST':
                next_sc_attempt = acc_sc['attempts'] + 1
                if password_sc == acc_uuid['unique_otp']:
                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time) VALUES (%s,%s,%s,%s,%s)',(acc_uuid['unique_otp'], next_sc_attempt, customer_id, 1, login_time))
                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))

                    db.connection.commit()
                    return redirect(url_for('checkout'))
                else:
                    cursor.execute(
                        'INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time) VALUES (%s,%s,%s,%s,%s)',
                        (acc_uuid['unique_otp'], next_sc_attempt, customer_id, 0, login_time))
                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))
                    # retry_time = datetime.utcnow() + timedelta(minutes=30)
                    cursor.execute('SELECT now_time as a_time from sc_time where customer_id = %s',[customer_id])
                    a_time = cursor.fetchone()
                    db.connection.commit()

                    if a_time is None:
                        # retry_time = datetime.utcnow() + timedelta(minutes=30)
                        retry_time = datetime.utcnow() + timedelta(seconds=15)
                        cursor.execute('INSERT INTO sc_time (sc_status ,customer_id,now_time, attempt_time) VALUES (%s,%s,NULL,%s)',(0, customer_id, retry_time))
                        flash("OTP Unsuccessfully, Try Again AGAIN!", category="success")
                        db.connection.commit()
                        return redirect(url_for('checkout_verification2'))
                    else:
                        cursor.execute('DELETE FROM sc_time WHERE customer_id = %s', [customer_id])
                        db.connection.commit()
                        # retry_time = datetime.utcnow() + timedelta(minutes=30)
                        retry_time = datetime.utcnow() + timedelta(seconds=15)
                        cursor.execute(
                            'INSERT INTO sc_time (sc_status ,customer_id,now_time, attempt_time) VALUES (%s,%s,NULL,%s)',
                            (0, customer_id, retry_time))
                        flash("OTP Unsuccessfully, Try Again AGAIN!", category="success")
                        db.connection.commit()
                        return redirect(url_for('checkout_verification2'))


            else:
                return render_template('checkout_verification2.html', form=form)
        elif acc_sc['attempts'] > 4:

            cursor.execute('UPDATE sc_time SET now_time = %s WHERE customer_id = %s',(login_time, customer_id))
            db.connection.commit()

            cursor.execute('SELECT * from sc_time where now_time > attempt_time and customer_id = %s',[customer_id])
            check_time = cursor.fetchone()
            db.connection.commit()

            cursor.execute('SELECT count(attempts) as attempts from sc_logs where customer_id = %s and attempts = 5', [customer_id])
            attempt_check = cursor.fetchone()
            db.connection.commit()

            if check_time is not None:
                if attempt_check['attempts'] <= 3 :
                    # current time has exceeded 30mins
                    cursor.execute('DELETE FROM sc_attempts WHERE customer_id = %s', [customer_id])
                    db.connection.commit()
                    return redirect(url_for('checkout_verification2'))
                else:
                    flash("Admin Client Session Message", category="success")
                    # implement message here
                    return redirect(url_for('market'))
            else:
                flash("Please Wait for 30 Minutes, Thank You", category="success")
                return redirect(url_for('market'))
    else:

        return redirect(url_for('checkout'))
    # cursor.execute('INSERT INTO logs_product (log_id ,description,date_created) VALUES (NULL,concat("User ID (",%s,") has been verififed for products"),%s)',(customer_id, login_time))
    # db.connection.commit()



@app.route('/messages',methods=['GET','POST'])
def messages():
    form = Create_Message(request.form)
    id = session['id']
    if 'loggedin' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM messages WHERE customer_id = %s',[id])
                messages = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('messages.html', items=messages, form=form)
    else:
        flash('Something went wrong!, please relog')
        return redirect(url_for('login'))

@app.route('/messages_admin',methods=['GET','POST'])
def messages_admin():
    form = Update_Message(request.form)
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM messages')
                messages = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('messages_admin.html', items=messages, form=form)
    else:
        flash('Something went wrong!, please relog')
        return redirect(url_for('login'))

@app.route('/create_messages', methods=['POST','GET'])
def create_messages():
    form = Create_Message(request.form)
    id = session['id']
    try:
        if form.validate_on_submit():
            description = form.description.data
            time = datetime.utcnow()


            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT max(message_id) as message_id from messages WHERE customer_id = %s',[id])
            message_id = cursor.fetchone()
            db.connection.commit()

            if message_id['message_id'] is None:
                cursor.execute('INSERT INTO messages VALUES (%s, %s, %s, %s, NULL, NULL, NULL)', (1, id , description, time))
                db.connection.commit()
                flash("Message Added Successfully!",category="success")
                return redirect(url_for('messages'))
            else:
                updated_message_id = message_id['message_id'] + 1
                cursor.execute('INSERT INTO messages VALUES (%s, %s, %s, %s, NULL, NULL, NULL)',
                               (updated_message_id,id, description, time))
                db.connection.commit()
                flash("Message Added Successfully!", category="success")
                return redirect(url_for('messages'))


    except Exception :
        flash("Error Adding Products", category="error")
        return redirect(url_for('messages'))

    return render_template('AddMessage.html', add_item_form=form)

@app.route('/products/delete_products/<id>/',  methods=['POST'])
def delete_message(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM products WHERE product_id = %s', [id])
        account = cursor.fetchone()
        if account:
            time = datetime.utcnow()
            cursor.execute('DELETE FROM products WHERE product_id = %s', [id])
            cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("Admin has deleted product from shopping cart (ID :",%s," )"),%s)',(id, time))

            db.connection.commit()
            flash("Product deleted successfully",category="success")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('products'))

@app.route('/checkout/delete_checkout_products/<id>/',  methods=['POST'])
def delete_checkout_products(id):
    customer_id = session['id']
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM shopping_cart WHERE product_id = %s and customer_id = %s', [id,customer_id])
        account = cursor.fetchone()
        if account:
            cursor.execute('DELETE FROM shopping_cart WHERE product_id = %sand customer_id = %s', [id,customer_id])
            db.connection.commit()
            flash("Product deleted successfully",category="success")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('checkout'))

@app.route('/orders')
def orders():
    customer_id = session['id']
    # global payment
    global shopping
    global total_products
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM shopping_cart WHERE customer_id = %s',[customer_id])

        shopping = cursor.fetchall()
        # cursor.execute('SELECT * FROM payment')
        # payment = cursor.fetchall()
        cursor.execute('SELECT sum(price) as price FROM shopping_cart WHERE customer_id = %s',[customer_id])
        total_products = cursor.fetchall()
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()

    return render_template('receipt.html',shopping=shopping, total=total_products)

@app.route('/orders/delete_order',  methods=['POST'])
def delete_order():
    customer_id = session['id']
    id = request.form['product-checkout']
    time = datetime.utcnow()

    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM shopping_cart WHERE product_id = %s', [id])
        account = cursor.fetchone()
        if account:
            cursor.execute('INSERT INTO orders (order_id , product_id ,order_date, quantity) VALUES (NULL, %s , %s , %s)',(id, time, 1))
            cursor.execute('DELETE FROM shopping_cart WHERE customer_id = %s',[customer_id])
            cursor.execute('INSERT INTO logs_product (log_id ,description, date_created) VALUES (NULL,concat("User has purchased product (ID :",%s," )"),%s)',(id, time))
            db.connection.commit()
            flash(id,category="success")
        else:
            flash("Something went wrong, please try again!",category="danger")
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('market'))

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    id = session['id']
    login_time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO logs_error (log_id ,description, date_created) VALUES (NULL,concat("ERROR 404 has Occured, User ID = ",%s),%s)',(id,login_time))
    db.connection.commit()
    return render_template('404.html'), 404

# Internal Server Error
@app.errorhandler(500)
def error500(e):
    id = session['id']
    login_time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        'INSERT INTO logs_error (log_id ,description, date_created) VALUES (NULL,concat("ERROR 505 (Internal Server Error) has Occured, User ID = ",%s),%s)',
        (id, login_time))
    db.connection.commit()
    return render_template('500.html'), 500

# Internal Server Error
@app.errorhandler(403)
def error403(e):
    id = session['id']
    login_time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        'INSERT INTO logs_error (log_id ,description, date_created) VALUES (NULL,concat("ERROR 403 (Internal Server Error) has Occured, User ID = ",%s),%s)',
        (id, login_time))
    db.connection.commit()
    return render_template('403.html'), 403



if __name__ == '__main__':
    app.run(debug=True)
