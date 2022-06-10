from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField

# Example
# class LoginForm(FlaskForm):
# 	username = StringField("Username", validators=[DataRequired()])
# 	password = PasswordField("Password", validators=[DataRequired()])
# 	submit = SubmitField("Submit")