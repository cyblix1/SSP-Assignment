import email
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField, EmailField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField

# Example
# class LoginForm(FlaskForm):
# 	username = StringField("Username", validators=[DataRequired()])
# 	password = PasswordField("Password", validators=[DataRequired()])
# 	submit = SubmitField("Submit")

class CreateAdminForm(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    password1 = PasswordField("Password:", validators=[Length(min=8), DataRequired()])
    password2 = PasswordField("Confirm Password", validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField("Submit")


class UpdateAdminForm(FlaskForm):
    name = StringField("Name", validators=[Length(min=1, max=50),DataRequired()])
    email = EmailField("Email", validators=[Length(min=5, max=100),DataRequired()])
    phone = StringField("Phone No", validators=[Length(min=8, max=8, message='Please enter a real number'),DataRequired()])
    submit = SubmitField("Submit")

