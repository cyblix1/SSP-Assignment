# from crypt import methods
from distutils import ccompiler
from distutils.util import byte_compile
from email.message import Message
from mimetypes import init
from pydoc import render_doc
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
import random
from flask_mail import Mail,Message
import logging
from logging.config import dictConfig , fileConfig
import smtplib
from logging.handlers import SMTPHandler
from email.message import EmailMessage
from twilio.rest import Client
import flask_monitoringdashboard as dashboard_unqiue
import pyotp
import qrcode
from flask_wtf.csrf import CSRFProtect
import stripe
app = Flask(__name__)
#properities
dashboard_unqiue.config.init_from(file='config_dashboard.cfg')
dashboard_unqiue.bind(app)
csrf = CSRFProtect()
csrf.init_app(app)
file = 'config.properties'
config = ConfigParser()
config.read(file)
# Conguration stuff
app.config['SECRET_KEY']= 'SSP Assignment'
SECRET_KEY = 'SSP Assignment'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes = 15)
app.config['MYSQL_HOST'] = config['account']['host']
app.config['MYSQL_USER'] = config['account']['user']
app.config['MYSQL_PASSWORD'] = config['account']['password']
app.config['MYSQL_DB'] = config['account']['db']
app.config['EMAIL_ADMIN'] = config['account']['email']
app.config['EMAIL_ADMIN_KEY'] = config['account']['keys']
app.config['RECAPTCHA_PUBLIC_KEY'] = "6Ldzgu0gAAAAAKF5Q8AdFeTRJpvl5mLBncz-dsBv"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Ldzgu0gAAAAANuXjmXEv_tLJLQ_s7jtQV3rPwX2"
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51LM6HwJDutS1IqmOR34Em3mZeuTsaUwAaUp40HLvcwrQJpUR5bR60V1e3kkwugBz0A8xAuXObCpte2Y0M251tBeD00p16YXMgE'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51LM6HwJDutS1IqmOFhsHKYQcSM2OEF8znqltmmy2vcQCkRUMiKyJrQunP0OlJji6Nlg142NVZ8CpTaMJgZLzzucx00tx6FdjY0'
app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=465
app.config["MAIL_USERNAME"]= 'nathanaeltzw@gmail.com'
app.config['MAIL_PASSWORD']= 'mxdbfpagawywnxgu'
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
auto_email = app.config['EMAIL_ADMIN']
email_key = app.config['EMAIL_ADMIN_KEY']
stripe.api_key = app.config['STRIPE_SECRET_KEY']




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


import logging.handlers

#Define Logger
logger = logging.getLogger("SSH_Parser")

#Set the Minimum Log Level for logger
logger.setLevel(logging.DEBUG)

#Create Handlers(Filehandler with filename| StramHandler with stdout)
file_handler_info = logging.FileHandler('app.log')


#Set Additional log level in Handlers if needed
file_handler_info.setLevel(logging.INFO)

#Create Formatter and Associate with Handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s')

#Add Handlers to logger
logger.addHandler(file_handler_info)


def generateOTP(otp_size = 6):
        final_otp = ''
        for i in range(otp_size):
            final_otp = final_otp + str(random.randint(0,9))
        return final_otp


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
        if question == 'Where did your parents meet?':
            question_number = 1
        elif question == 'What city did you first go to college?':
            question_number = 2
        else:
            question_number = 3
        answer = form.answer.data
        validate_ans = Validations.validate_answer(answer)
        if validate_ans is True:
            pass
        else:
            flash('Answer is unacceptable',category='danger')


        password = form.password1.data
        hashpassword = bcrypt2.generate_password_hash(password)
        password2 = form.password2.data
        email = form.email.data
        time = datetime.utcnow()
        password_age = 4

        if password != password2:
            flash('passwords do not match',category='danger')

            return redirect(url_for('register'))
        else:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT customer_id from customer_accounts where email = %s',[email])
            email_check = cursor.fetchone()
            db.connection.commit()
            if email != "admin@gmail.com":
                if email_check is None:
                    cursor.execute('INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s,%s)',(name,email,question_number,answer,hashpassword,password_age,time,0))
                    db.connection.commit()
                    cursor.execute('SELECT customer_id from customer_accounts WHERE email = %s', [email])
                    customer_id_email = cursor.fetchone()
                    db.connection.commit()
                    cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_register_success : User ID (",%s,")"))',(time, customer_id_email["customer_id"], customer_id_email["customer_id"]))
                    db.connection.commit()
                    flash('Account Successfully Created ',category='success')
                    return redirect(url_for('login'))
                else:
                    flash('Email has been registered before ',category='danger')
                    return redirect(url_for('register'))
            else:
                flash('Email has been registered before ', category='danger')
                return redirect(url_for('register'))


    return render_template('register.html',form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        # Create variables for easy access
        email = form.email.data
        password = form.password1.data
        login_time = datetime.utcnow()
        # check if its staff account
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        # decryption later + salted hashing + login history
        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [email])
        # Fetch one record and return result
        account = cursor.fetchone()

        if account:
            id = account['customer_id']
            #first checks if account is enabled
            cursor.execute('SELECT status FROM customer_accounts WHERE customer_id = %s ', [id])
            i = cursor.fetchone()
            if i['status'] == 0:
                pass
            else:
                flash('Account is disabled, please contact staff!',category='danger')
                return redirect(url_for('login'))
            cursor.execute(
                'SELECT max(failed_attempt_tries) AS failed_try from login_limitations where customer_id = %s ', [id])
            check_tries = cursor.fetchone()
            if check_tries['failed_try'] is None:
                user_hashpwd = account['hashed_pw']
                if bcrypt2.check_password_hash(user_hashpwd, password):
                    id = account['customer_id']
                    # Create session data, we can access this data in other routes
                    cursor.execute(
                        'SELECT max(login_attempt_no) AS last_login FROM customer_login_history WHERE customer_id = %s',
                        [id])
                    acc_login = cursor.fetchone()
                    # means first login
                    if acc_login['last_login'] is None:
                        # means first login
                        zero = 1
                        cursor.execute(
                            'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                            (id, zero, login_time))
                        db.connection.commit()
                        session['loggedin'] = True
                        session['id'] = account['customer_id']
                        session['name'] = account['full_name']
                        session['email'] = account['email']
                        session['customer_login_no'] = 1
                        session.permanent = True
                        app.permanent_session_lifetime = timedelta(minutes=15)
                        # app.permanent_session_lifetime = timedelta(seconds=15)

                        # Redirect to home page
                        cursor.execute(
                            'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                            (login_time, id, id))
                        db.connection.commit()
                        return redirect(url_for('market'))
                    # elif acc_login['last_login'] == 3 :
                    #     flash('TOO MANY LOGIN ATTEMPTS', category='danger')
                    #     return redirect(url_for('logout'))
                    # means not first login

                    else:
                        next_login_attempt = acc_login['last_login'] + 1
                        cursor.execute(
                            'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                            (id, next_login_attempt, login_time))
                        db.connection.commit()
                        session['loggedin'] = True
                        session['id'] = account['customer_id']
                        session['name'] = account['full_name']
                        session['customer_login_no'] = int(next_login_attempt)
                        # Redirect to home page
                        cursor.execute(
                            'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                            (login_time, id, id))
                        db.connection.commit()

                        return redirect(url_for('market'))
                else:
                    flash("Incorrect E-mail or Password, 2 tries remaining ",category='danger')
                    failed_tries = 1
                    attempt_time = datetime.utcnow()
                    cursor.execute(
                        'INSERT INTO login_limitations (customer_id, failed_attempt_tries, attempt_time, locked_time) VALUES (%s,%s,%s,NULL)',
                        (id, failed_tries, attempt_time))
                    db.connection.commit()
                    return redirect(url_for('login'))


            elif check_tries['failed_try'] < 3:
                user_hashpwd = account['hashed_pw']
                if bcrypt2.check_password_hash(user_hashpwd, password):
                    id = account['customer_id']
                    # Create session data, we can access this data in other routes
                    cursor.execute(
                        'SELECT max(login_attempt_no) AS last_login FROM customer_login_history WHERE customer_id = %s',
                        [id])
                    acc_login = cursor.fetchone()
                    # means first login
                    if acc_login['last_login'] is None:
                        # means first login
                        zero = 1
                        cursor.execute(
                            'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                            (id, zero, login_time))
                        db.connection.commit()
                        session['loggedin'] = True
                        session['id'] = account['customer_id']
                        session['name'] = account['full_name']
                        session['email'] = account['email']
                        session['customer_login_no'] = 1
                        session.permanent = True
                        app.permanent_session_lifetime = timedelta(minutes=15)
                        # Redirect to home page
                        cursor.execute(
                            'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                            (login_time, id, id))
                        cursor.execute('DELETE FROM login_limitations WHERE customer_id = %s', [id])
                        db.connection.commit()
                        return redirect(url_for('market'))
                    # elif acc_login['last_login'] == 3 :
                    #     flash('TOO MANY LOGIN ATTEMPTS', category='danger')
                    #     return redirect(url_for('logout'))
                    # means not first login

                    else:
                        next_login_attempt = acc_login['last_login'] + 1
                        cursor.execute(
                            'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                            (id, next_login_attempt, login_time))
                        db.connection.commit()
                        session['loggedin'] = True
                        session['id'] = account['customer_id']
                        session['name'] = account['full_name']
                        session['customer_login_no'] = int(next_login_attempt)
                        # Redirect to home page
                        cursor.execute(
                            'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                            (login_time, id, id))
                        cursor.execute('DELETE FROM login_limitations WHERE customer_id = %s', [id])
                        db.connection.commit()

                        return redirect(url_for('market'))
                else:
                    customer_id = account['customer_id']
                    cursor.execute(
                        'SELECT max(failed_attempt_tries) AS failed_attempt_tries FROM login_limitations WHERE customer_id = %s',
                        [customer_id])
                    failed_attempt = cursor.fetchone()

                    if failed_attempt['failed_attempt_tries'] is None:
                        flash("Incorrect E-mail or Password, 2 tries remaining ")
                        failed_tries = 1
                        attempt_time = datetime.utcnow()
                        cursor.execute(
                            'INSERT INTO login_limitations (customer_id, failed_attempt_tries, attempt_time, locked_time) VALUES (%s,%s,%s,NULL)',
                            (customer_id, failed_tries, attempt_time))
                        db.connection.commit()
                        return redirect(url_for('login'))

                    elif failed_attempt['failed_attempt_tries'] < 2:
                        flash("Incorrect E-mail or Password, this is your last try")
                        failed_tries = 2
                        attempt_time = datetime.utcnow()
                        cursor.execute(
                            'INSERT INTO login_limitations (customer_id, failed_attempt_tries, attempt_time, locked_time) VALUES (%s,%s,%s,NULL)',
                            (customer_id, failed_tries, attempt_time))
                        db.connection.commit()
                        return redirect(url_for('login'))


                    elif failed_attempt['failed_attempt_tries'] < 3:
                        flash("Please Try Again in 5 Minutes", category="success")
                        failed_tries = 3
                        attempt_time = datetime.utcnow()
                        retry_time2 = datetime.utcnow() + timedelta(minutes=5)
                        cursor.execute(
                            'INSERT INTO login_limitations (customer_id, failed_attempt_tries, attempt_time, locked_time) VALUES (%s,%s,%s,%s)',
                            (customer_id, failed_tries, attempt_time, retry_time2))
                        db.connection.commit()
                    # flash("Incorrect E-mail or Password, 2 tries remaining ")
                    # failed_tries = 1
                    # attempt_time = datetime.utcnow()
                    # cursor.execute(
                    #     'INSERT INTO login_limitations (customer_id, failed_attempt_tries, attempt_time, locked_time) VALUES (%s,%s,%s,NULL)',
                    #     (id, failed_tries, attempt_time))
                    # db.connection.commit()
                    # return redirect(url_for('login'))




            else:
                attempt_time = datetime.utcnow()
                cursor.execute(
                    'UPDATE login_limitations SET attempt_time = %s WHERE customer_id = %s and failed_attempt_tries = %s',
                    (attempt_time, id, 3))
                db.connection.commit()
                cursor.execute('SELECT * from login_limitations where attempt_time > locked_time and customer_id = %s',
                               [id])
                check_time = cursor.fetchone()
                db.connection.commit()
                if check_time is not None:
                    # current time has not exceeded 5mins
                    cursor.execute('DELETE FROM login_limitations WHERE customer_id = %s', [id])
                    db.connection.commit()
                    user_hashpwd = account['hashed_pw']
                    if bcrypt2.check_password_hash(user_hashpwd, password):
                        id = account['customer_id']

                        # Create session data, we can access this data in other routes
                        cursor.execute(
                            'SELECT max(login_attempt_no) AS last_login FROM customer_login_history WHERE customer_id = %s',
                            [id])
                        acc_login = cursor.fetchone()
                        # means first login
                        if acc_login['last_login'] is None:
                            # means first login
                            zero = 1
                            cursor.execute(
                                'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                                (id, zero, login_time))
                            db.connection.commit()
                            session['loggedin'] = True
                            session['id'] = account['customer_id']
                            session['name'] = account['full_name']
                            session['email'] = account['email']
                            session['customer_login_no'] = 1
                            session.permanent = True
                            app.permanent_session_lifetime = timedelta(minutes=15)
                            # Redirect to home page
                            cursor.execute(
                                'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                                (login_time, id, id))
                            db.connection.commit()
                            return redirect(url_for('market'))
                        # elif acc_login['last_login'] == 3 :
                        #     flash('TOO MANY LOGIN ATTEMPTS', category='danger')
                        #     return redirect(url_for('logout'))
                        # means not first login

                        else:
                            next_login_attempt = acc_login['last_login'] + 1
                            cursor.execute(
                                'INSERT INTO customer_login_history (customer_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                                (id, next_login_attempt, login_time))
                            db.connection.commit()
                            session['loggedin'] = True
                            session['id'] = account['customer_id']
                            session['name'] = account['full_name']
                            session['customer_login_no'] = int(next_login_attempt)
                            # Redirect to home page
                            cursor.execute(
                                'INSERT INTO logs_info (log_id ,date_created,customer_id, description) VALUES (NULL,%s,%s,concat("authn_login_success : User ID (",%s,")"))',
                                (login_time, id, id))
                            db.connection.commit()

                            return redirect(url_for('market'))

                else:
                    flash("Please Wait for 5 Minutes, Thank You", category="success")
                    return redirect(url_for('login'))
        else:
            # check for staff account
            cursor.execute('SELECT * FROM staff_email_hash')
            all_staff = cursor.fetchall()
            # check if email exists
            id = 0
            for staff in all_staff:
                hash = (staff['email_hash']).encode()
                if bcrypt.checkpw(email.encode(), hash):
                    id = staff['staff_id']
                    break
            # decryption of email
            # get key
            if id == 0:
                # checks for admin accounts
                cursor.execute('SELECT * from admin_accounts')
                admin = cursor.fetchone()
                if admin['email'] == email and admin['password'] == password:
                    session['loggedin3'] = True
                    session['id'] = admin['admin_id']
                    session['name'] = admin['full_name']
                    flash(f"Successfully logged in as {admin['full_name']}!", category="success")
                    return redirect(url_for('admins'))
                else:
                    flash('invalid login details', category='danger')
                    return redirect(url_for('login'))
            else:
                # This is staff account
                cursor.execute('SELECT staff_key FROM staff_key WHERE staff_id = %s', [id])
                columns = cursor.fetchone()
                staff_key = columns['staff_key']
                # Get account information
                cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [id])
                staff = cursor.fetchone()
                # check password hash
                if staff and bcrypt.checkpw(password.encode(), staff['hashed_pw'].encode()):
                    # decrypt email
                    f = Fernet(staff_key)
                    encrypted_email = staff['email']
                    decrypted = f.decrypt(encrypted_email.encode())
                    if decrypted:
                        cursor.execute(
                            'SELECT max(login_attempt_no) AS last_login FROM staff_login_history WHERE staff_id = %s',[id])
                        acc_login = cursor.fetchone()
                        # means first login so need 3fa
                        if acc_login['last_login'] is None:
                            # otp is a string
                            otp = str(generateOTP())
                            msg = Message("Hello", sender='tannathanael24@gmail.com',
                                          recipients=[email])
                            body = "Your OTP is " + otp
                            msg.body = body
                            mail.send(msg)
                            # Encrypting OTP to put in session
                            key = Fernet.generate_key()
                            # storing key
                            cursor.execute('INSERT INTO staff_otp_key VALUES (%s,%s)', (id, key.decode()))
                            db.connection.commit()
                            f = Fernet(key)
                            encrypted_otp = f.encrypt(otp.encode())
                            decoded_otp = encrypted_otp.decode()
                            session['id'] = id
                            # stored the otp in a session, after need to encode and key in database
                            session['OTP'] = decoded_otp
                            return redirect(url_for('firstloginstaff'))
                        # means not first login
                        else:
                            next_login_attempt = acc_login['last_login'] + 1
                            cursor.execute(
                                'INSERT INTO staff_login_history (staff_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',
                                (id, next_login_attempt, login_time))
                            db.connection.commit()
                            session['loggedin2'] = True
                            session['id'] = id
                            session['name'] = staff['full_name']
                            session['staff_login_no'] = int(next_login_attempt)
                            flash(f"Successfully logged in as {staff['full_name']}!", category="success")
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
        db.connection.commit()

        if account_forget:
            if email_forget == account_forget['email']:
                session['fp_id'] = account_forget['customer_id']
                session['forget_pw'] = account_forget['email']
                db.connection.commit()
                return redirect(url_for('forgetpassword2'))
        else:
            flash("Please Verify Again", category="danger")
            return redirect(url_for('login'))

    return render_template('forgetpassword.html', form=form)

@app.route('/forgetpassword2', methods=['GET', 'POST'])
def forgetpassword2():
    # try:
        email = session['forget_pw']
        login_time = datetime.utcnow()
        secret = pyotp.random_base32()
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT customer_id FROM customer_accounts WHERE email = %s', [email])
        # Fetch one record and return result
        id = cursor.fetchone()
        db.connection.commit()

        cursor.execute('SELECT google_otp FROM fp_google WHERE customer_id = %s', [id['customer_id']])
        secret_otp = cursor.fetchone()
        db.connection.commit()

        if secret_otp is None:
            cursor.execute('INSERT INTO fp_google (customer_id, google_otp) VALUES (%s,%s)', (id['customer_id'],secret))
            db.connection.commit()
            pass
        else:
            cursor.execute('UPDATE fp_google SET google_otp = %s WHERE customer_id = %s', (secret,id['customer_id']))
            db.connection.commit()
            pass

        cursor.execute('SELECT google_otp FROM fp_google WHERE customer_id = %s', [id['customer_id']])
        new_otp = cursor.fetchone()
        db.connection.commit()

        data = pyotp.totp.TOTP(new_otp['google_otp']).provisioning_uri(name=email)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save('./static/images/hehe.jpg', 'JPEG')

        secret_input = request.form.get("secret")
        # getting OTP provided by user
        otp = str(request.form.get("otp"))
        # verifying submitted OTP with PyOTP
        if request.method == 'POST':
            if pyotp.TOTP(secret_input).verify(otp):
                # inform users if OTP is valid
                flash("The TOTP 2FA token is valid", "success")
                cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [session['forget_pw']])
                # Fetch one record and return result
                account = cursor.fetchone()
                session['id'] = account['customer_id']
                cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_password_change : User ID (",%s,")"))',(login_time,  id['customer_id'],  id['customer_id']))
                db.connection.commit()
                session['reset_password'] = 1
                return redirect(url_for('resetpassword'))
            else:
                # inform users if OTP is invalid
                flash("You have supplied an invalid 2FA token!", "danger")
                cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_password_fail : User ID (",%s,")"))',(login_time, id['customer_id'] , id['customer_id']))
                return redirect(url_for("forgetpassword2"))
        else:
            return render_template('forgetpassword2.html',secret=new_otp['google_otp'])



@app.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
    form = ResetPassword(request.form)
    # email_forget = form.email.data
    newpassword = form.newpassword.data
    confirmpassword = form.confirmpassword.data
    time = datetime.utcnow()

    try:
        id = session['reset_password']
        if request.method == 'POST':
            if newpassword != confirmpassword:
                    flash('passwords do not match',category='danger')
                    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_password_chang_fail : User ID (",%s,")"))',(time, session['id'], session['id']))

                    return redirect(url_for('resetpassword'))

            elif newpassword == confirmpassword:
                    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                    update_hashpassword = bcrypt2.generate_password_hash(newpassword)
                    cursor.execute('UPDATE customer_accounts SET hashed_pw = %s WHERE customer_id = %s',(update_hashpassword, session['id']))
                    cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_password_change_success : User ID (",%s,")"))',(time, session['id'], session['id']))
                    db.connection.commit()
                    flash("Successful, Password Reset", category="success")
                    db.connection.commit()

                    cursor.execute('SELECT full_name from customer_accounts WHERE customer_id = %s',[session['id']])
                    customer_name = cursor.fetchall()
                    cursor.execute('SELECT email from customer_accounts WHERE customer_id = %s', [session['id']])
                    customer_email = cursor.fetchall()
                    db.connection.commit()

                    for i in customer_name:
                        name = i['full_name']
                    for i in customer_email:
                        email = i['email']

                    user_content = ("Hi %s, \n VALA has received a request to recover access to account (email : %s) \n If you did not make this request, please contact ADMIN IMMEDIATELY (via messages - http://127.0.0.1:5000/). \n\n Thank You! \n\n From, \n VALA TEAM" % (name,email))
                    msg = EmailMessage()
                    msg.set_content(" News from VALA TEAM! \n {}".format(user_content))
                    msg["Subject"] = "Critical Security Alert"
                    msg["From"] = auto_email
                    msg["To"] = session['forget_pw']

                    with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
                        smtp.starttls()
                        smtp.login(msg["From"], email_key)
                        smtp.send_message(msg)

                    session.pop('reset_password',None)
                    return redirect(url_for('login'))
    except:
        flash("Please do Verification!", category="danger")
        return redirect(url_for('login'))

    return render_template('resetpassword.html',form=form)


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
        cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_logout_success : User ID (",%s,")"))',(logout_time, id, id))
        db.connection.commit()
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('name', None)
        session.pop('customer_login_no',None)

        flash('Successfully logged out',category='success')
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
    time = datetime.utcnow()


    if request.method == 'POST':
        if newpassword == oldpassword:
            flash('passwords cannot be equal',category='danger')
            return redirect(url_for('updatePassword'))
        if newpassword == confirmpassword:
            if bcrypt2.check_password_hash(user_hashpwd, oldpassword):
                update_hashpassword = bcrypt2.generate_password_hash(newpassword)
                cursor.execute('UPDATE customer_accounts SET hashed_pw = %s WHERE customer_id = %s',
                               (update_hashpassword, id))
                cursor.execute(
                    'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_logout_success : User ID (",%s,")"))',
                    (time, id,id))

                db.connection.commit()
                flash("Successful", category="success")

                cursor.execute('SELECT full_name from customer_accounts WHERE customer_id = %s', [id])
                customer_name = cursor.fetchall()
                cursor.execute('SELECT email from customer_accounts WHERE customer_id = %s', [id])
                customer_email = cursor.fetchall()
                db.connection.commit()

                for i in customer_name:
                    name = i['full_name']
                for i in customer_email:
                    email = i['email']

                user_content = ("Hi %s, \n VALA has received a request to recover access to account (email : %s) \n If you did not make this request, please contact ADMIN IMMEDIATELY (via messages). \n\n Thank You! \n\n From, \n VALA TEAM" % (name, email))
                msg = EmailMessage()
                msg.set_content("News from VALA TEAM! \n {}".format(user_content))
                msg["Subject"] = "Critical Security Alert"
                msg["From"] = auto_email
                msg["To"] = email

                with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
                    smtp.starttls()
                    smtp.login(msg["From"], email_key)
                    smtp.send_message(msg)

                return redirect(url_for('login'))


            else:
                flash("Same Password as Old , Try Again", category="success")
                return redirect(url_for('updatePassword'))

    
    return render_template('updatePassword.html', form=form)


@app.route('/delete_customer_account', methods=['GET', 'POST'])
def delete_customer_account():
    try:
        id=session['id']
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM messages WHERE customer_id = %s', [id])
        cursor.execute('DELETE FROM sc_logs WHERE customer_id = %s', [id])
        cursor.execute('DELETE FROM customer_accounts WHERE customer_id = %s', [id])
        db.connection.commit()
        flash("Account Has Been Deleted", category='success')
        return redirect(url_for('login'))
    except:
        flash("Please Try Again", category='danger')
        return redirect(url_for('profile'))


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
    flash('Welcome to VALA, Please Log In or Register !',category='success')
    return redirect(url_for('login'))




#base template
@app.route('/logs_info')
def logs_info():
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM logs_info')
                login = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('dashboard.html', items=login  )
    else:
        flash('You are not allowed to access this page', category='danger')
        return redirect(url_for('login'))

@app.route('/logs_warning')
def logs_warning():
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM logs_warning')
                products = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('dashboard_warning.html', products = products )
    else:
        flash('You are not allowed to access this page', category='danger')
        return redirect(url_for('login'))

@app.route('/logs_critical')
def logs_critical():
    if 'loggedin2' in session or 'loggedin3' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM logs_critical')
                error = cursor.fetchall()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('dashboard_critical.html', error = error  )
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
                #staff login history
                cursor.execute('SELECT login_attempt_no,login_time,logout_time FROM staff_login_history WHERE staff_id=%s',[staff['staff_id']])
                login_logs = cursor.fetchall()
                staff['history'] = login_logs
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
        flash('Error,you are not logged in',category='danger')
        return redirect(url_for('login'))
 

@app.route('/create_admin', methods=['POST'])
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
        if Validations.validate_stuff(name) == True:
            flash('Character cant be used!',category='danger')
            return redirect(url_for('admins'))
        #Server side validations
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('SELECT * FROM staff_email_hash')
            all_staff = cursor.fetchall()
            #check if email exists ofr staff accounts
            for staff in all_staff:
                if bcrypt.checkpw(email.encode(),staff['email_hash'].encode()):
                    flash('Email exists!',category="danger")
                    return redirect(url_for('admins'))
                continue
            #checks if email exists in customer side 
            cursor.execute('SELECT email from customer_accounts')
            all_customers = cursor.fetchall()
            for customer in all_customers:
                if customer['email'] == email:
                    flash('Email exists as a customer!',category='danger')
                    return redirect(url_for('admins'))
                continue
            if password != password2:
                flash('passwords does not match',category='danger')
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
                flash(phone)
                return redirect(url_for('admins'))
                


@app.route('/test')
def test():
    return render_template('tes.html')

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
                cursor.execute('SELECT * FROM customer_login_history')
                login_logs = cursor.fetchall()
                db.connection.commit()
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('customers.html',customers=customers, login_logs=login_logs)
    else:
        flash('Error,you are not logged in', category="danger")
        return redirect(url_for('login'))


@app.route('/customers/delete/<int:id>/', methods=['GET','POST'])
def delete_customer(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #checks if exists 
        cursor.execute('SELECT * FROM customer_accounts WHERE customer_id = %s', [id])
        account = cursor.fetchone()
        if account is not None:
            cursor.execute('DELETE FROM sc_logs WHERE customer_id = %s', [id])
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
    return redirect(url_for('customers'))

@app.route('/customers/disable/<int:id>/',methods=['POST','GET'])
def disable(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT status FROM customer_accounts WHERE customer_id=%s',[id])
        status = cursor.fetchone()
        db.connection.commit()
        if status['status'] == 0:
            cursor.execute('UPDATE customer_accounts SET status = %s WHERE customer_id=%s',(1,[id]))
            db.connection.commit()
            flash('Account has been disabled',category='danger')
            return redirect(url_for('customers'))
        elif status['status'] == 1 :
            flash('Customer is already disabled',category='danger')
            return redirect(url_for('customers'))
        else:
            flash('Something went wrong, please try again!',category='danger')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
            db.connection.close()
    flash('User needs to be re-registered!', category='danger')
    return redirect(url_for('customers'))

@app.route('/customers/enable/<int:id>/',methods=['POST','GET'])
def enable(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT status FROM customer_accounts WHERE customer_id=%s',[id])
        status = cursor.fetchone()
        db.connection.commit()
        if status['status'] == 1:
            cursor.execute('UPDATE customer_accounts SET status = %s WHERE customer_id = %s',(0,[id]))
            db.connection.commit()
            flash('Account has been enabled',category='success')
            return redirect(url_for('customers'))
        elif status['status'] == 0:
            flash('Customer is already enabled', category='danger')
            return redirect(url_for('customers'))
        else:
            flash('Something went wrong, please try again!',category='danger')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
            db.connection.close()
    flash('User needs to be re-registered!', category='danger')
    return redirect(url_for('customers'))

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
        flash('Session timeout',category='danger')
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
        id = session['id']
        login_num = session['staff_login_no']
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        logout_time = datetime.utcnow()
        cursor.execute('UPDATE staff_login_history SET logout_time = %s WHERE staff_id = %s AND login_attempt_no = %s',(logout_time,id,login_num))
        db.connection.commit()
        session.pop('loggedin2', None)
        session.pop('id', None)
        session.pop('name', None)
        session.pop('staff_login_no', None)
        flash('Successfully logged out',category='success')
        # Redirect to login page
        return redirect(url_for('login'))
    elif 'loggedin3' in session:
        session.pop('loggedin3',None)
        session.pop('id',None)
        session.pop('name',None)
        flash('Successfully logged out', category='success')
        # Redirect to login page    
        return redirect(url_for('login'))
    else:
        flash('Something went wrong!',category='danger')
        return redirect(url_for('login'))



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
    time = datetime.utcnow()

    try:
        if form.validate_on_submit():
            product_id = uuid.uuid4()
            name = form.product_name.data
            price = form.price.data
            description = form.description.data

            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO products VALUES (%s, %s, %s, %s)', (product_id,name,price,description))
            cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,NULL,concat("product_added_success : Product ID (",%s,")"))',(time, product_id))
            db.connection.commit()
            flash("Product Added Successfully!",category="success")
            return redirect(url_for('products'))

    except Exception :
        flash("Error Adding Products", category="danger")
        time = datetime.utcnow()
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,NULL,concat("product_added_failed : Admin ID (",%s,")"))',
            (time, 0))

        db.connection.commit()

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
            cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,NULL,concat("product_deleted_success : Admin ID (",%s,")"))',(time, 0))

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
            cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,NULL,concat("product_updated_success : Admin ID (",%s,")"))',(time, 0))

            db.connection.commit()
            flash("Products updated successfully", category="success")
        else:
            flash('Something went wrong!')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
        flash("Error Updating Products", category="danger")
        return redirect(url_for('products'))
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('products'))

@app.route('/market')
def market():
    check_logs()
    if 'loggedin' in session:
        id = session['id']
        data_check = 0
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT password_age FROM CUSTOMER_ACCOUNTS WHERE CUSTOMER_ID = %s', [id])
        expiry = cursor.fetchone()
        db.connection.commit()
        if expiry['password_age'] >= 30:
            data_check += 1
            flash('Password has expired, please update.', category="danger")
        else:
            pass

        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT count(index_id) as index_id FROM messages WHERE customer_id = %s', [id])
        messages_count = cursor.fetchall()

        cursor.execute('SELECT * FROM messages where customer_id = %s', [id])
        messages = cursor.fetchall()
        login_num = session['customer_login_no']
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            if cursor:
                cursor.execute('SELECT * FROM products')
                products = cursor.fetchall()
                cursor.execute('SELECT * FROM shopping_cart')
                shopping_cart = cursor.fetchall()

                cursor.execute(
                    'SELECT login_time FROM customer_login_history WHERE customer_id =%s and login_attempt_no =%s',
                    (id, login_num))
                logintime = cursor.fetchone()

        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            if cursor:
                cursor.close()
        return render_template('market.html', items=products, cart=shopping_cart, id=session['id'],
                               name=session['name'], logintime=logintime, messages=messages, count=messages_count,data=data_check)
    else:
        flash("Please Log In!", category="danger")
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
        cursor.execute('INSERT INTO shopping_cart (product_id, product_name, price , description, customer_id) VALUES (%s,%s,%s,%s,%s)',(product_id, name, price, description, customer_id))
        cursor.execute('INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_add_sc_success : Product ID (",%s,")"))',(time, customer_id, product_id))
        db.connection.commit()
        flash("Product Added Successfully", category="success")

    except:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("authn_add_sc_fail : Product ID (",%s,")"))',(time, customer_id, product_id))
        db.connection.commit()
        flash("Product Added Unsuccessfully", category="danger")


    return redirect(url_for('market'))


@app.route('/check_shopping_cart')
def check_shopping_cart():
    if 'loggedin' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT sum(price) as price FROM shopping_cart')
            total = cursor.fetchall()
            for i in total:
                if i['price'] > 1000:
                    flash('Please do a Verification as Amount is too big', category="success")
                    session.pop('sc_verified_1', None)
                    session.pop('sc_verified_2', None)
                    session.pop('sc_ready', None)
                    return redirect(url_for('checkout_verification'))
                else:
                    session['sc_verified_2'] = 1
                    return redirect(url_for('checkout_verification'))
        except IOError:
            print('Database problem!')
        except Exception as e:
            # print(f'Error while connecting to MySQL,{e}')
            flash("No Items in Shopping Cart", category="danger")
            return redirect(url_for('market'))
    else:
        flash("Please Log In!", category="danger")
        return redirect(url_for('login'))

@app.route('/checkout', methods=['POST', 'GET'])
def checkout():
    customer_id = session['id']
    try:
        verification = session['sc_verified_1']
        if verification == 1:
            if 'loggedin' in session:
                cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)

                try:
                    cursor.execute('SELECT * FROM shopping_cart WHERE customer_id = %s ', [customer_id])
                    products = cursor.fetchall()
                    cursor.execute('SELECT sum(price) as price FROM shopping_cart')
                    total = cursor.fetchall()
                    session['sc_ready'] = 1
                    cursor.execute('SELECT max(sc_status) as sc_status FROM sc_attempts WHERE customer_id = %s',[customer_id])
                    status_sc = cursor.fetchone()

                    db.connection.commit()

                    session_checkout = stripe.checkout.Session.create(
                        payment_method_types=['card'],
                        line_items=[{
                            'price': 'price_1LYu6pJDutS1IqmODTkbCZan',
                            'quantity': 1,
                        }],
                        mode='payment',
                        success_url=url_for('orders', _external=True),
                        cancel_url=url_for('checkout', _external=True),
                    )

                    if status_sc['sc_status'] == 1 :
                        session['orders_verified'] = 1
                        pass
                    else:
                        pass


                except IOError:
                    print('Database problem!')
                except Exception as e:
                    print(f'Error while connecting to MySQL,{e}')


                return render_template('checkout.html', cart_items=products, total = total,status = status_sc, checkout_session_id= session_checkout['id'], checkout_public_key=app.config['STRIPE_PUBLIC_KEY'])
            else:
                flash("Please Log In!", category="danger")
                return redirect(url_for('login'))
        else:
            flash("Please Try Again", category="danger")
            return redirect(url_for('checkout_verification'))
    except:
        flash("Please do verification", category="danger")
        return redirect(url_for('page_not_found'))

@app.route('/checkout_verification', methods=['POST','GET'])
def checkout_verification():
    form = LoginForm(request.form)
    customer_id = session['id']
    try:
        verification = session['sc_verified_2']
        session['sc_verified_1'] = 1
        return redirect(url_for('checkout'))
    except:
        try:
            verification = session['sc_verified_1']
            return redirect(url_for('checkout'))
        except:
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
                        cursor.execute(
                            'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_1_success : User ID (",%s,")"))',
                            (login_time, customer_id, customer_id))
                        db.connection.commit()
                        session['sc_verified_1'] = 1
                        return redirect(url_for('checkout'))
                    else:
                        flash("Please Verify Again", category="danger")
                        cursor.execute(
                            'INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_1_fail : User ID (",%s,")"))',
                            (login_time, customer_id, customer_id))
                        db.connection.commit()
                        return redirect(url_for('market'))
                else:
                    flash("Please Verify Again", category="danger")
                    return redirect(url_for('market'))

            return render_template('checkout_verification.html', form=form)

@app.route('/checkout_verification2', methods=['POST','GET'])
def checkout_verification2():
    try:
        verification = session['sc_ready']
        if verification == 1:
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
            cursor.execute('SELECT * from sc_attempts where attempt_time > otp_time and customer_id = %s', [customer_id])
            otp_check_time = cursor.fetchone()
            db.connection.commit()

            if otp_check_time is None:

                if status_sc['sc_status'] is None:
                    attempted = 1
                    user_checkout_id = random.randint(000000,999999)
                    otp_time = datetime.utcnow() + timedelta(seconds=30)
                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time,otp_time) VALUES (%s,%s,%s,%s,%s,%s)',(user_checkout_id, attempted, customer_id, 0,login_time,otp_time))
                    db.connection.commit()
                    cursor.execute('SELECT unique_otp FROM sc_attempts WHERE customer_id = %s',[customer_id])
                    unique_otp_sc = cursor.fetchone()
                    msg = EmailMessage()
                    msg.set_content("This is your OTP {}".format(unique_otp_sc['unique_otp']))
                    msg["Subject"] = "An Email Alert"
                    msg["From"] = auto_email
                    msg["To"] = user_email['email']

                    with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
                        smtp.starttls()
                        smtp.login(msg["From"], email_key)
                        smtp.send_message(msg)

                    if request.method == 'POST':
                            if password_sc == unique_otp_sc['unique_otp']:
                                # cursor.execute('INSERT INTO sc_attempts (unique_id ,product_attempts,customer_id,sc_status) VALUES (%s,%s,%s,%s)',(unique_id_sc['unique_id'], attempted, customer_id, 1))
                                cursor.execute('UPDATE sc_attempts SET unique_otp =%s ,attempts =%s ,customer_id =%s ,sc_status =%s ,attempt_time= %s WHERE customer_id = %s and unique_id = %s',(1, customer_id))
                                cursor.execute(
                                    'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_2_success : User ID (",%s,")"))',
                                    (login_time, customer_id, customer_id))
                                db.connection.commit()
                                session['orders_verified'] = 1
                                flash("Verification Successful, Please Proceed to Payment", category="success")
                                return redirect(url_for('checkout'))

                            else:
                                # cursor.execute('INSERT INTO sc_attempts (unique_id ,product_attempts,customer_id,sc_status) VALUES (%s,%s,%s,%s)',
                                #     (user_checkout_id, attempted, customer_id, 0))
                                cursor.execute('INSERT INTO logs_warning (log_id ,date_created,description) VALUES (NULL,%s,concat("authn_checkout_fail : User ID (",%s,")"))',(login_time, customer_id))
                                flash("OTP Unsuccessfully, Try Again!", category="danger")
                                db.connection.commit()
                                return redirect(url_for('checkout_verification2'))
                    else:
                        return render_template('checkout_verification2.html', form=form)

                elif status_sc['sc_status'] == 0:
                        cursor.execute('SELECT max(otp_time) AS otp_time FROM sc_attempts WHERE customer_id = %s',[customer_id])
                        max_otp_time = cursor.fetchone()

                        if acc_sc['attempts'] < 4:
                            cursor.execute('SELECT unique_otp FROM sc_attempts WHERE customer_id = %s', [customer_id])
                            acc_uuid = cursor.fetchone()
                            db.connection.commit()
                            if request.method == 'POST':
                                next_sc_attempt = acc_sc['attempts'] + 1
                                if password_sc == acc_uuid['unique_otp']:
                                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time,otp_time) VALUES (%s,%s,%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,1,login_time,max_otp_time['otp_time']))
                                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))
                                    cursor.execute(
                                        'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_2_success : User ID (",%s,")"))',
                                        (login_time, customer_id, customer_id))
                                    db.connection.commit()
                                    flash("Verification Successful, Please Proceed to Payment", category="success")
                                    return redirect(url_for('checkout'))
                                else:
                                    cursor.execute('INSERT INTO sc_attempts (unique_otp ,attempts,customer_id,sc_status,attempt_time,otp_time) VALUES (%s,%s,%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,0,login_time,max_otp_time['otp_time']))
                                    cursor.execute('INSERT INTO sc_logs (unique_otp ,attempts,customer_id,attempt_time) VALUES (%s,%s,%s,%s)', (acc_uuid['unique_otp'],next_sc_attempt,customer_id,login_time))
                                    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,description) VALUES (NULL,%s,concat("authn_checkout_fail : User ID (",%s,")"))',(login_time, customer_id))
                                    db.connection.commit()
                                    flash("OTP Unsuccessfully, Try Again!", category="danger")
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
                                    cursor.execute(
                                        'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_2_success : User ID (",%s,")"))',
                                        (login_time, customer_id, customer_id))
                                    session['orders_verified'] = 1
                                    db.connection.commit()
                                    flash("Verification Successful, Please Proceed to Payment", category="success")
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
                                        retry_time = datetime.utcnow() + timedelta(minutes=30)
                                        # retry_time = datetime.utcnow() + timedelta(seconds=15)
                                        cursor.execute('INSERT INTO sc_time (sc_status ,customer_id,now_time, attempt_time) VALUES (%s,%s,NULL,%s)',(0, customer_id, retry_time))
                                        cursor.execute('INSERT INTO logs_warning (log_id ,date_created,description) VALUES (NULL,%s,concat("authn_checkout_fail : User ID (",%s,")"))',(login_time, customer_id))
                                        flash("OTP Unsuccessfully, Try Again!", category="danger")
                                        db.connection.commit()
                                        return redirect(url_for('checkout_verification2'))
                                    else:
                                        cursor.execute('DELETE FROM sc_time WHERE customer_id = %s', [customer_id])
                                        db.connection.commit()
                                        retry_time = datetime.utcnow() + timedelta(minutes=30)
                                        # retry_time = datetime.utcnow() + timedelta(seconds=15)
                                        cursor.execute(
                                            'INSERT INTO sc_time (sc_status ,customer_id,now_time, attempt_time) VALUES (%s,%s,NULL,%s)',
                                            (0, customer_id, retry_time))
                                        flash("OTP Unsuccessfully, Try Again!", category="danger")
                                        cursor.execute('INSERT INTO logs_warning (log_id ,date_created,description) VALUES (NULL,%s,concat("authn_checkout_fail : User ID (",%s,")"))',(login_time, customer_id))
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
                                    flash("Please Contact Admin", category="danger")
                                    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,description) VALUES (NULL,%s,concat("authn_checkout_fail_max : User ID (",%s,")"))',(login_time, customer_id))
                                    db.connection.commit()
                                    # implement message here
                                    return redirect(url_for('messages'))
                            else:
                                flash("Please Wait for 30 Minutes, Thank You", category="danger")
                                return redirect(url_for('market'))


                else:
                    session['orders_verified'] = 1
                    cursor.execute(
                        'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_verf_2_success : User ID (",%s,")"))',
                        (login_time, customer_id, customer_id))
                    db.connection.commit()
                    flash("Verification Successful, Please Proceed to Payment", category="success")
                    return redirect(url_for('checkout'))
            else:
                cursor.execute('DELETE FROM sc_attempts WHERE customer_id = %s', [customer_id])
                db.connection.commit()
                flash("OTP has expired, Request Again", category="danger")
                return redirect(url_for('market'))
        else:
            flash("Please Verify Again", category="danger")
            return redirect(url_for('market'))
    except:
        flash("Please Verify Again", category="danger")
        return redirect(url_for('page_not_found'))

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

            validate_ans = Validations.validate_answer(description)
            if validate_ans is True:
                pass
            else:
                flash('Answer is unacceptable', category='danger')
                return redirect(url_for('messages'))

            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT max(message_id) as message_id from messages WHERE customer_id = %s',[id])
            message_id = cursor.fetchone()
            db.connection.commit()

            if message_id['message_id'] is None:
                cursor.execute('INSERT INTO messages VALUES (NULL, %s, %s, %s, %s, NULL, NULL, NULL)', (1, id , description, time))
                db.connection.commit()
                flash("Message Added Successfully!",category="success")
                return redirect(url_for('messages'))
            else:
                updated_message_id = message_id['message_id'] + 1
                cursor.execute('INSERT INTO messages VALUES (NULL, %s, %s, %s, %s, NULL, NULL, NULL)',
                               (updated_message_id,id, description, time))
                db.connection.commit()
                flash("Message Added Successfully!", category="success")
                return redirect(url_for('messages'))


    except Exception :
        flash("Error Adding Products", category="danger")
        return redirect(url_for('messages'))

    return render_template('AddMessage.html', add_item_form=form)

@app.route('/messages_admin/update_messages/<id>/', methods=['POST'])
def update_messages(id):
    form = Update_Message(request.form)
    description = form.description.data
    time = datetime.utcnow()

    try:
        validate_ans = Validations.validate_answer(description)
        if validate_ans is True:
            pass
        else:
            flash('Answer is unacceptable', category='danger')
            return redirect(url_for('messages_admin'))

        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('UPDATE messages SET staff_id = %s, reply = %s, reply_time =%s WHERE index_id = %s', (1,description,time,id))
            db.connection.commit()
            flash("Message Replied successfully", category="success")
        else:
            flash('Something went wrong!')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
        flash("Error Updating Products", category="danger")
        return redirect(url_for('messages_admin'))
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('messages_admin'))

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
            return redirect(url_for('checkout'))

    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('market'))

@app.route('/orders')
def orders():
    try:
        customer_id = session['id']
        verified = session['orders_verified']
        if verified == 1:
            session.pop('orders_verified', None)
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM shopping_cart WHERE customer_id = %s', [customer_id])
            shopping = cursor.fetchall()
            db.connection.commit()
            cursor.execute('SELECT sum(price) as price FROM shopping_cart WHERE customer_id = %s', [customer_id])
            total_products = cursor.fetchall()
            db.connection.commit()
            return render_template('receipt.html', shopping=shopping, total=total_products)
        else:
            flash("Please Verify Again", category="danger")
            return redirect(url_for('market'))
    # global payment
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    flash("Please Verify Again", category="danger")
    return redirect(url_for('checkout'))


@app.route('/orders/delete_order',  methods=['POST'])
def delete_order():
    customer_id = session['id']
    id = request.form['product-checkout']
    time = datetime.utcnow()
    session.pop('orders_verified', None)

    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT count(product_id) as counts FROM shopping_cart WHERE customer_id = %s',[customer_id])
        count = cursor.fetchone()
        db.connection.commit()
        cursor.execute('INSERT INTO orders (order_id , product_id ,order_date, quantity, customer_id) VALUES (NULL, %s , %s , %s,%s)',(id, time, count['counts'],[customer_id]))
        cursor.execute('DELETE FROM shopping_cart WHERE customer_id = %s',[customer_id])
        cursor.execute('DELETE FROM sc_attempts WHERE customer_id = %s', [customer_id])
        cursor.execute(
            'INSERT INTO logs_info (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_success : User ID (",%s,")"))',
            (time, customer_id, customer_id))
        db.connection.commit()
        session.pop('sc_ready', None)
        session.pop('sc_verified_1', None)
        flash("Order Successfully",category="success")
        return redirect(url_for('market'))

    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
        flash("Something went wrong, please try again!", category="danger")
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("checkout_fail: User ID (",%s,")"))',
            (time, customer_id, customer_id))
        db.connection.commit()
        return redirect(url_for('checkout'))

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/error')
def page_not_found():
    id = session['id']
    time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("Error 404: User ID (",%s,")"))',(time, id, id))
    db.connection.commit()
    return render_template('404.html'), 404
# Internal Server Error
@app.errorhandler(500)
def error500(e):
    id = session['id']
    time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("Error 505: User ID (",%s,")"))',(time, id, id))
    db.connection.commit()
    return render_template('500.html'), 500

# Internal Server Error
@app.errorhandler(403)
def error403(e):
    id = session['id']
    time = datetime.utcnow()
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO logs_warning (log_id ,date_created,customer_id,description) VALUES (NULL,%s,%s,concat("Error 403: User ID (",%s,")"))',(time, id, id))
    db.connection.commit()
    return render_template('403.html'), 403

@app.route('/firstloginstaff',methods=['GET','POST'])
def firstloginstaff():
    form = getotpform()
    if 'OTP' in session and 'id' in session:
        id = session['id']
        encrypted_otp = session['OTP']
        encrypted = (encrypted_otp.encode())
        if form.validate_on_submit():
            inputed_otp = form.otp.data
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            #getting key to decrypt session otp
            cursor.execute('SELECT otp_key FROM staff_otp_key WHERE staff_id= %s',[id])
            k = cursor.fetchone()
            key = (k['otp_key'].encode())
            f= Fernet(key)
            decrypted_otp = (f.decrypt(encrypted)).decode()
            if inputed_otp == decrypted_otp:
                otp2 = generateOTP()
                #will use same key
                #encrypting otp
                encrypted_otp = f.encrypt(otp2.encode())
                decoded_otp = encrypted_otp.decode()
                #otpmessage
                otpmessage = 'Your OTP is '+otp2
                session['OTP2'] = decoded_otp
                session['OTP3'] = '123456'
                #getting phone number 
                cursor.execute('SELECT phone_no FROM staff_accounts WHERE staff_id=%s',[id])
                num_dict = cursor.fetchone()
                staff_number = num_dict['phone_no']
                #For SG number only
                staff_number2 = '+65'+staff_number
                #Sending message(doesnt work)
                #twilio codes (need to pay for unverified nnunmbers,if number if verified can uncomment this)
                # account_sid = config['twilio']['account']
                # auth_token = config['twilio']['token']
                # client = Client(account_sid,auth_token)
                # message = client.messages.create(
                #     from_='+12183074015',
                #     body = otpmessage,
                #     to = staff_number2
                # )
                return redirect(url_for('firstloginphone'))

            elif inputed_otp != decrypted_otp:
                flash('Incorrect OTP!', category='danger')
                pass
        else:
            flash('Please enter a OTP')
            pass
    else:
        flash('You are not allowed on this page',category='danger')
        return redirect(url_for('login'))

    return render_template('firstloginstaff.html',form=form)

@app.route('/firstloginphone',methods=['GET','POST'])
def firstloginphone():
    form = getotpform()
    if 'OTP3' in session and 'id' in session:
        if session['OTP3'] == '123456':
            if form.validate_on_submit():
                inputed_otp = form.otp.data
                if str(inputed_otp) == '123456':
                    return redirect(url_for('firstchangepassword'))
                else:
                    flash('Invalid OTP',category='danger')
                    return redirect(url_for('firstloginphone'))
    #real code
    elif 'OTP' in session and 'OTP2' in session and 'id' in session:
        encrypted_phoneotp = (session['OTP2']).encode() 
        id = session['id']
        #getkey
        if form.validate_on_submit():
            inputed_otp = form.otp.data
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT otp_key FROM staff_otp_key WHERE staff_id= %s',[id])
            k = cursor.fetchone()
            key = (k['otp_key'].encode())
            f= Fernet(key)
            decrypted_otp = (f.decrypt(encrypted_phoneotp)).decode()
            if decrypted_otp == inputed_otp:
                return redirect(url_for('firstchangepassword'))
            else:
                flash('Incorrect OTP!',category='danger')
    else:
        flash('Something went wrong please relog!',category='danger')
        return redirect(url_for('login'))  

    return render_template('firstloginphone.html',form=form)


@app.route('/firstchangepassword',methods=['POST','GET'])
def firstchangepassword():
    form = ChangePasswordStaffForm()
    if 'OTP' in session and 'OTP2' in session and 'id' in session:
        id = session['id']
        if form.validate_on_submit():
            password1 = form.psw.data
            password2 = form.password2.data
            #validations 
            if Validations.validate_password(password1) == False:
                flash('Invalid password',category="danger")
            elif password1 != password2:
                flash('passwords do not match',category='danger')
            elif password1 == None:
                flash('Please enter a new password',category='danger')
            else:
                #check if password is same as current
                cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                if cursor:
                    cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [id])
                    staff = cursor.fetchone()
                    # check password hash
                    if staff and (bcrypt.checkpw(password1.encode(), staff['hashed_pw'].encode())) == True:
                        flash('Previous password cannot be used',category='danger')
                        return redirect(url_for('firstchangepassword'))
                    else:
                        salt = bcrypt.gensalt()        
                        hashedpw = bcrypt.hashpw(password1.encode(),salt)
                        cursor.execute('UPDATE staff_accounts SET hashed_pw = %s WHERE staff_id = %s',(hashedpw.decode(),id))
                        db.connection.commit()
                        session.pop('OTP', None)
                        session.pop('OTP2', None)
                        zero = 1
                        login_time = datetime.utcnow()
                        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute('SELECT full_name FROM staff_accounts WHERE staff_id= %s',[id])
                        staff = cursor.fetchone()
                        cursor.execute('INSERT INTO staff_login_history (staff_id, login_attempt_no, login_time) VALUES (%s,%s,%s)',(id,zero,login_time))
                        db.connection.commit()
                        session['loggedin2'] = True
                        session['name'] = staff['full_name']
                        session['staff_login_no'] = 1
                        flash(f"Successfully logged in as {staff['full_name']}, password has been changed!",category="success")
                        return redirect(url_for('customers'))
        else:
            pass
    else:
        flash('Please enter a new password',category='success')
    return render_template('firstchangepassword.html',form=form)
    

def check_logs():
    try:
        id = session['id']
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT count(*) as warning_num from logs_warning WHERE customer_id = %s" , [id])
        send_notice = cursor.fetchone()
        db.connection.commit()
        if send_notice is None:
            pass
        elif send_notice['warning_num'] > 15 :
            account_sid = config['twilio']['account']
            auth_token = config['twilio']['token']
            client = Client(account_sid, auth_token)
            message = client.messages.create(
                from_= '+12182504569',
                to="+65",
                #  ^^ insert own number for admin
                body= "User %s has passed warning logs stage, check on user!" % [id]
            )
            print(message)
        else:
            pass
    except:
        return redirect(url_for('login'))


@app.route('/homemain')
def homemain():
    return render_template('homemain.html')

if __name__ == '__main__':
    app.run(debug=True)
