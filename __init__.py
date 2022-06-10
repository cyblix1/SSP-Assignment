from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors

app = Flask(__name__)

@app.route('/')
@app.route('/home')
def home():
    pass

# @loginrequired here
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


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