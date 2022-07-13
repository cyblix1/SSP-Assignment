from dataclasses import dataclass
import email
from tkinter import W
from tkinter.tix import Select
from flask import Flask
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField, ValidationError, TextAreaField, EmailField, SelectField
from wtforms.validators import DataRequired, EqualTo, Length,ValidationError
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField
import mysql.connector
from mysql.connector import Error
from configparser import ConfigParser

#configuration files
file = 'config.properities'
config = ConfigParser()
config.read(file)


class checks_exists:
    def check_staff_email(self,email_address_to_check):
        try:
            connection = mysql.connector.connect(host=config['account']['host'],user=config['account']['user'],database=config['account']['db'],password=config['account']['password'])
            if connection.is_connected(): 
                cursor = connection.cursor()
                cursor.execute('SELECT * FROM customer_accounts WHERE email = %s', [email_address_to_check])
                existing_email = cursor.fetchone()
                if existing_email:
                    raise ValidationError('Email Aready exists! Please use another!')
                else:
                    pass
        except Error as e:
            print('Database Error!',{e})      
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close() 
    def check_customer_email(self,email_address_to_check):
        try:
            connection = mysql.connector.connect(host=config['account']['host'],user=config['account']['user'],database=config['account']['db'],password=config['account']['password'])
            if connection.is_connected(): 
                cursor = connection.cursor()
                cursor.execute('SELECT * FROM staff_accounts WHERE email = %s', [email_address_to_check])
                existing_email = cursor.fetchone()
                if existing_email:
                    raise ValidationError('Email Aready exists! Please use another!')
                else:
                    pass
        except Error as e:
            print('Database Error!',{e})      
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close() 

                
class CreateAdminForm(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    gender = SelectField("gender",validators=[DataRequired()],choices=[('M', 'Male'), ('F', 'Female')], default='M')
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    description = TextAreaField("description",validators=[Length(max=200)])
    password1 = PasswordField("Password:", validators=[DataRequired(), EqualTo('password2'),Length(min=1,max=200)])
    password2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Add Employee")


class UpdateAdminForm(FlaskForm):
    id = IntegerField("Id",validators=[DataRequired()])
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    description = StringField("description",validators=[Length(max=200)])
    submit = SubmitField("Save Changes")

class Update_Name(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    submit = SubmitField(label='Done')

class Update_Email(FlaskForm): 
    email_address = EmailField(label='Email Address:', validators=[DataRequired(), Length(min=5,max=100)])
    submit = SubmitField(label='Done')


class Update_Gender(FlaskForm):
    gender = SelectField("gender",validators=[DataRequired()],choices=[('M', 'Male'), ('F', 'Female')], default='M')
    submit = SubmitField(label='Done')



class Register_Users(FlaskForm):
    #name = StringField("Name", validators=[Length(min=1, max=50, message='length is between 1 to 50'), DataRequired(message="no name")])
    #email = EmailField("Email", validators=[Length(min=5, max=100,  message='length is between 5 to 100'), DataRequired(message ='no email')])
    #password1 = PasswordField("Password:", validators=[DataRequired(message ="no password"), EqualTo('password2', message="password not match")])
    name = StringField("Name")
    email = EmailField("Email")
    password1 = PasswordField("Password:")
    password2 = PasswordField("Confirm Password")
    submit = SubmitField("Add Customer")

class Create_Products(FlaskForm):
    product_name = StringField(label='Name', validators=[Length(min=1, max=100), DataRequired()])
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    price = StringField(label='Price', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField(label='Add Item')

class Update_Products(FlaskForm):
    product_id = IntegerField("Id",validators=[DataRequired()])
    product_name = StringField(label='Name', validators=[Length(min=1, max=100), DataRequired()])
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    price = StringField(label='Price', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField(label = "Save Changes")

class LoginForm(FlaskForm):
    customer_name = StringField("Name", validators=[Length(min=1, max=50), DataRequired()])
    password1 = PasswordField("Password:", validators=[DataRequired()])
    submit = SubmitField(label = "Login")
