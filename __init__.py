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

#base template
@app.route('/dashboard')
def dashboard():
    return render_template('base_admin.html')

@app.route('/admins' ,methods=['POST','GET'])
def admins():
    form = CreateAdminForm(request.form)
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM admin_accounts')
    all_data = cursor.fetchall()

    #create employee
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        hashedpw = bcrypt.generate_password_hash(password)
        date_created = datetime.utcnow()
        #simple first later check is exists
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        #make account
        cursor.execute('INSERT INTO admin_accounts VALUES (NULL, %s, %s, %s, %s, %s)', (name,email,phone,hashedpw,date_created))
        db.connection.commit()
        flash("Employee Inserted Successfully")
        return redirect(url_for('admins'))

    return render_template('admins.html', employees = all_data,form=form)

# @app.route('/create_admin', methods=['POST'])
# def create_admin():
#     form = CreateAdminForm(request.form)
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         phone = request.form['phone']
#         password = request.form['password']
#         hashedpw = bcrypt.generate_password_hash(password)
#         date_created = datetime.utcnow()
#         #simple first later check is exists
#         cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
#         #make account
#         cursor.execute('INSERT INTO admin_accounts VALUES (NULL, %s, %s, %s, %s, %s)', (name,email,phone,hashedpw,date_created))
#         db.connection.commit()
#         flash("Employee Inserted Successfully")
#         return redirect(url_for('admins'),form=form)
    


@app.route('/update_admin', methods=['GET','POST'])
def update():
    if request.method == 'POST':
        id = request.form.get('id')
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        cursor.execute('UPDATE admin_accounts SET name = %s, email = %s, phone=%s WHERE id = %s', (name,email,phone,id))
        db.connection.commit()
        flash("Employee updated successfully")
        return redirect(url_for('admins'))

@app.route('/delete_admin/<id>/',  methods=['GET','POST'])
def delete(id):
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM admin_accounts WHERE id = %s', (id))
    db.connection.commit()
    flash("Employee deleted successfully")
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