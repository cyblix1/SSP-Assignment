from mimetypes import init
from tkinter import Image
from flask import Flask, render_template, request, make_response, redirect, url_for, session,flash, json
from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
from datetime import datetime, timedelta
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
from verify import *


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
app.config['RECAPTCHA_PUBLIC_KEY'] = "6Ldzgu0gAAAAAKF5Q8AdFeTRJpvl5mLBncz-dsBv"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Ldzgu0gAAAAANuXjmXEv_tLJLQ_s7jtQV3rPwX2"




app.permanent_session_lifetime = timedelta(minutes=10)
db = MySQL(app)



@app.route('/register',methods =['POST','GET'])
def register():
    form = Register_Users()
    if form.is_submitted() and request.method == 'POST' and RecaptchaField != NULL:
        name = form.name.data
        password = form.password1.data
        password2 = form.password2.data
        if password != password2:
            flash('passwords do not match',category='danger')
            return redirect(url_for('register'))
        email = form.email.data
        time = datetime.utcnow()
        password_age=4
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        print('INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s)',(name,email,password,password_age,time,))
        cursor.execute('INSERT INTO customer_accounts VALUES (NULL,%s,%s,%s,%s,%s)',(name,email,password,password_age,time,))
        db.connection.commit()
        return redirect(url_for('home'))

    return render_template('register.html',form=form)

def home():
    if 'loggedin' in session: 
# User is loggedin show them the home page 
        return render_template('home.html', username=session['username']) 
# User is not loggedin redirect to login page 
    return redirect(url_for('login')) 



@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        # Create variables for easy access
        email = form.email.data
        password = form.password1.data
        #check if its staff account
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #decryption later + salted hashing + login history




        cursor.execute('SELECT * FROM staff_accounts WHERE email = %s',[email])
        staff = cursor.fetchone()
        if staff:
            id = staff['staff_id']
            cursor.execute('SELECT * FROM staff_key WHERE staff_id = %s',[id])



            session['staffloggedin'] = True
            session['id'] = account['staff_id']
            session['name'] = account['full_name'] 
            #to admin page Fix later 
            return redirect(url_for('admins'))
        elif staff is None:
            # Check if account exists using MySQL
            cursor.execute('SELECT * FROM customer_accounts WHERE email = %s AND hashed_pw = %s',[email,password])
            # Fetch one record and return result
            account = cursor.fetchone()
            if account:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['customer_id']
                session['name'] = account['full_name']
                # Redirect to home page
                return redirect(url_for('home'))
            else:
                # Account doesn’t exist or username/password incorrect
                # Show the login form with message (if any)
                flash('Incorrect username or Password')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
# Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    flash('Successfully logged out')
    # Redirect to login page
    return redirect(url_for('login'))



@app.route('/')
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





@app.route('/home')
def home():
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html',id=session['id'], name=session['name'])
# User is not loggedin redirect to login page
    return redirect(url_for('login'))




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
    date_created = datetime.utcnow()
    #Server side validations 
    if password != password2:
        flash('passwords does not match',category="danger")
        return redirect(url_for('admins'))
    elif Validations.validate_password(password) == False:
        flash('',category="danger")
        return redirect(url_for('admins'))
    elif Validations.validate_email(email) == False:
        flash('Invalid email')
        return redirect(url_for('admins'))
    else:
        #hashing 
        salt = bcrypt.gensalt()        
        hashedpw = bcrypt.hashpw(password.encode(),salt)
        #encryption
        encoded_password = password.encode()
        salt = b'\x829\xf0\x9e\x0e\x8bl;\x1a\x95\x8bB\xf9\x16\xd4\xe2'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(encoded_password))

        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #encrypting email
        encoded_email = email.encode()
        f = Fernet(key)
        encrypted_email = f.encrypt(encoded_email)
        cursor.execute('INSERT INTO staff_accounts VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s)', (name,encrypted_email,phone,gender,hashedpw,30,description,date_created))
        db.connection.commit()

        #get staff-id + sorting key
        cursor.execute('SELECT staff_id FROM staff_accounts WHERE email = %s',[encrypted_email])
        staff_id = cursor.fetchone()
        cursor.execute('INSERT INTO staff_key VALUE (%s,%s)',((staff_id['staff_id']),key.decode()))
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
            cursor.execute('DELETE FROM staff_key WHERE staff_id = %s',[id])
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
        return 'not in session'
    return redirect(url_for('login'))



@app.route('/admin_profile',methods=['GET','POST'])
def admin_profile():
    name_form = Update_Name()
    email_form = Update_Email()
    gender_form = Update_Gender()
    if 'staffloggedin' in session:
        try:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM staff_accounts WHERE staff_id = %s', [session['id']])
            if account:
                account = cursor.fetchone()
                return render_template('admin_profile.html',account=account,name_form=name_form,email_form=email_form,gender_form=gender_form)
        except IOError:
            print('Database problem!')
        except Exception as e:
            print(f'Error while connecting to MySQL,{e}')
        finally:
            cursor.close()
            db.connection.close()
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
    session.pop('staffloggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    flash('Successfully logged out')
    # Redirect to login page
    return redirect(url_for('login'))

# incomplete need session
@app.route("/profile/update_gender/<gender>")
def update_gender(gender):
    pass


@app.route('/products')
def products():
    form = Create_Products()
    form2 = Update_Products()

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

@app.route('/create_products', methods=['POST','GET'])
def create_products():
    form = Create_Products()
    if form.validate_on_submit():
        id = uuid.uuid4()
        # need to change manually LMAO
        name = form.product_name.data
        price = form.price.data
        description = form.description.data

        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO products VALUES (%s, %s, %s, %s)', (id,name,price,description))
        db.connection.commit()
        flash("Employee Added Successfully!",category="success")

        return redirect(url_for('products'))

    elif request.method == 'POST':
        msg = 'Please fill out the form !'

    return render_template('AddItem.html',add_item_form = form)

@app.route('/products/delete_products/<id>/',  methods=['POST'])
def delete_products(id):
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM products WHERE product_id = %s', [id])
        account = cursor.fetchone()
        if account:
            cursor.execute('DELETE FROM products WHERE product_id = %s', [id])
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
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('UPDATE products SET product_name = %s, price = %s, description =%s WHERE product_id = %s', (name,price,description,id))
            db.connection.commit()
            flash("Products updated successfully", category="success")
        else:
            flash('Something went wrong!')
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        cursor.close()
        db.connection.close()
        return redirect(url_for('products'))





@app.route('/market')
def market():
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
    return render_template('market.html', items = products  )

@app.route('/add_to_checkout', methods=['POST'])
def add_to_checkout():
    id = request.form['product-value']
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO shopping_cart SELECT product_id, product_name, price , description FROM products WHERE product_id = %s', [id])
        db.connection.commit()
        flash("Employee Added Successfully!",category="success")
    except:
        flash("Employee Added NO!", category="success")

    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['POST','GET'])
def checkout():
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor:
            cursor.execute('SELECT * FROM shopping_cart')
            products = cursor.fetchall()
    except IOError:
        print('Database problem!')
    except Exception as e:
        print(f'Error while connecting to MySQL,{e}')
    finally:
        if cursor:
            cursor.close()
    return render_template('checkout.html',cart_items = products)


@app.route('/payment', methods=['POST','GET'])
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
