import email
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField, ValidationError, TextAreaField, EmailField
from wtforms.validators import DataRequired, EqualTo, Length,ValidationError, Email
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField


class CreateAdminForm(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    description = TextAreaField("description",validators=[Length(max=200)])
    password1 = PasswordField("Password:", validators=[DataRequired(), EqualTo('password2')])
    password2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Add Employee")


class UpdateAdminForm(FlaskForm):
    id = IntegerField("Id")
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    description = StringField("description",validators=[Length(max=200)])
    submit = SubmitField("Save Changes")

# class AdminChangePassword(FlaskForm):

class Register_Users (FlaskForm):
    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    # email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')


