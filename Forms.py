# from ast import Sub, pattern
from dataclasses import dataclass
import email
from tkinter import W
from tkinter.tix import Select
from flask import Flask
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField, ValidationError, TextAreaField, EmailField, SelectField,DateField
from wtforms.validators import DataRequired, EqualTo, Length,ValidationError
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField
import mysql.connector
from mysql.connector import Error
from configparser import ConfigParser
import bcrypt
import re

#configuration files
file = 'config.properities'
config = ConfigParser()
config.read(file)

RECAPTCHA_PUBLIC_KEY = "6Ldzgu0gAAAAAKF5Q8AdFeTRJpvl5mLBncz-dsBv"
RECAPTCHA_PRIVATE_KEY = "6Ldzgu0gAAAAANuXjmXEv_tLJLQ_s7jtQV3rPwX2"    

class CreateAdminForm(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    gender = SelectField("gender",validators=[DataRequired()],choices=[('M', 'Male'), ('F', 'Female')], default='M')
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    description = TextAreaField("description",validators=[Length(max=200)])
    psw = PasswordField("Password:", validators=[DataRequired(),Length(min=1,max=200)])
    password2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Add Employee")

class VerifyStaffOtp(FlaskForm):
    email = EmailField("Email")
    submit = SubmitField("Verify")

class VerifyStaffOtp2(FlaskForm):
    otp = StringField(DataRequired())
    submit = SubmitField("Verify")

class getotpform(FlaskForm):
    otp = StringField("OTP",validators=[DataRequired(),Length(min=6,max=6)])
    submit = SubmitField("Submit")

class ChangePasswordStaffForm(FlaskForm):
    psw = PasswordField("Password:", validators=[DataRequired(), EqualTo('password2',message="passwords must match"),Length(min=8,max=200)])
    password2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

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
    name = StringField("Name", validators=[Length(min=1, max=50, message='length is between 1 to 50'), DataRequired(message="no name")])
    email = EmailField("Email", validators=[Length(min=5, max=100,  message='length is between 5 to 100'), DataRequired(message ='no email')])
    question = SelectField("Security Question", validators=[DataRequired(message="Please Select a question")], choices=[("What was the name of your first stuffed toy?"),
    ("Where did your parents meet?"),("What city did you first go to college?")])
    answer = StringField("Answer", validators=[Length(max=50),DataRequired(message="Please answer")])
    password1 = PasswordField("Password:", validators=[DataRequired(message ="no password")])
    password2 = PasswordField("Confirm:",validators=[DataRequired(message ="no password")])
    recaptcha = RecaptchaField(validators=[DataRequired(message="Click here")])
    submit = SubmitField("Register")

class Create_Products(FlaskForm):
    product_name = StringField(label='Name', validators=[Length(min=1, max=100), DataRequired()])
    description = StringField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    price = StringField(label='Price', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField(label='Add Item')

class Update_Products(FlaskForm):
    product_id = IntegerField("Id",validators=[DataRequired()])
    product_name = StringField(label='Name', validators=[Length(min=1, max=100), DataRequired()])
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    price = StringField(label='Price', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField(label = "Save Changes")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[Length(min=5, max=100,  message='length is between 5 to 100'), DataRequired(message ='no email')])
    password1 = PasswordField("Password:", validators=[DataRequired()])
    submit = SubmitField(label = "Login")

class Add_Card_Details(FlaskForm):
    card_number = IntegerField("Card Number",validators=[Length(min=16, max=16),DataRequired()])
    card_name = StringField(label='Card Name', validators=[Length(min=1, max=100), DataRequired()])
    card_date = DateField("Card Date",validators=[DataRequired()])
    card_cvc = IntegerField("CVC Number",validators=[Length(min=3, max=3), DataRequired()])
    submit = SubmitField(label = "Add Card")

class UpdatePassword(FlaskForm):
    oldpassword = PasswordField("Old Password:",validators=[DataRequired(message ="Enter the correct password!")])
    newpassword = PasswordField("New Password:",validators=[DataRequired()])
    confirmpassword = PasswordField("Confirm New Password:",validators=[DataRequired()])
    submit = SubmitField(label = "Change Password")

class ShoppingCart_Validation(FlaskForm):
    password = PasswordField("Input OTP:", validators=[DataRequired()])
    submit = SubmitField(label = "Verify")

class ForgetPassword(FlaskForm):
    email = EmailField("Email", validators=[Length(min=5, max=100,  message='length is between 5 to 100'), DataRequired(message ='no email')])
    password = PasswordField("Password:", validators=[DataRequired(message ="no password")])
    submit = SubmitField(label = "Verify")

class ResetPassword(FlaskForm):
    newpassword = PasswordField("New Password:",validators=[DataRequired()])
    confirmpassword = PasswordField("Confirm New Password:",validators=[DataRequired()])
    submit = SubmitField(label = "Change Password")

class Create_Message(FlaskForm):
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField(label='Add Item')

class Update_Message(FlaskForm):
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField(label='Add Item')
