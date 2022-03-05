# Copyright (C) 2022 Raunak Parmar, @trouble1_raunak
# All rights reserved to Raunak Parmar

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# This tool is meant for educational purposes only. 
# The creator takes no responsibility of any mis-use of this tool.

from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, IntegerField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.fields.simple import HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, IPAddress
from vajra import app, db
from vajra.models import Admin

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('SIGN IN')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=200)], render_kw={"placeholder": "Username"})
    email = EmailField('Email', validators=[DataRequired(), Length(min=5, max=200), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=100)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = Admin.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken.')

    def validate_email(self, email):
        email = Admin.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('That email address is taken')


class victimForm(FlaskForm):
    displayName = StringField('Display Name', render_kw={"placeholder": "Trouble1 Raunak"}, validators=[Length(min=0, max=200)])
    email = StringField('Email Address', render_kw={"placeholder": "trouble1fake@gmail.com"}, validators=[Length(min=0, max=200)])
    objectID = StringField('UID', render_kw={"placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}, validators=[Length(min=0, max=200)])
    submit = SubmitField('Search')


class oneDriveForm(FlaskForm):
    fileName = StringField('File Name', render_kw={"placeholder": "reports.docx"}, validators=[Length(min=0, max=200)])
    emailId = StringField('Email Id', render_kw={"placeholder": "trouble1fake@onmicrosoft.com"}, validators=[Length(min=0, max=200)])
    submit = SubmitField('Search')

class outlookForm(FlaskForm):
    fileName = StringField(render_kw={"placeholder": "Search keywords"}, validators=[Length(min=0, max=200)])
    attachments = BooleanField('Attachments')
    submit = SubmitField('Search')
    submitAll = SubmitField('Search In All')

class sendmailForm(FlaskForm):
    receiver = StringField('Email Address', render_kw={"placeholder": "Email Id"},validators=[Length(min=0, max=200), Email()])
    subject = StringField('Subject', render_kw={"placeholder": "Subject"}, validators=[Length(min=0, max=500)])
    body = TextAreaField('Body(Insert html content)')
    attachment = FileField()
    submit = SubmitField('Send')

class outlooRules(FlaskForm):
    victim = StringField('Email Address', render_kw={"placeholder": "Email Id"},validators=[Length(min=0, max=200), Email()])
    rules = TextAreaField('Body(Provide json content)')
    submit = SubmitField('Send')


class attachmentsForm(FlaskForm):
    fileName = StringField('File Name', render_kw={"placeholder": "reports.docx"}, validators=[Length(min=0, max=200)])
    emailId = StringField('Email Id', render_kw={"placeholder": "trouble1fake@onmicrosoft.com"}, validators=[Length(min=0, max=200)])
    submit = SubmitField('Search')

class onenoteForm(FlaskForm):
    fileName = StringField('File Name', render_kw={"placeholder": "reports.html"}, validators=[Length(min=0, max=200)])
    emailId = StringField('Email Id', render_kw={"placeholder": "trouble1fake@onmicrosoft.com"}, validators=[Length(min=0, max=200)])
    submit = SubmitField('Search')    

class stealerConfigForm(FlaskForm):
    clientId = StringField('Client ID', render_kw={"placeholder": "Client Id"}, validators=[Length(min=0, max=200)])
    clientSecret = StringField('Client Secret', render_kw={"placeholder": "Client Secret"}, validators=[Length(min=0, max=200)])
    redirectUrl = StringField('Redirect Url', render_kw={"placeholder": "https://stealer.com/redirect"}, validators=[Length(min=0, max=200)])
    redirectUrlNext = StringField('Redirect Url After Seating(Optional)', render_kw={"placeholder": "https://safedomain.com"}, validators=[Length(min=0, max=200)])
    macrofile = FileField()
    stealAll = BooleanField()
    victimsColleague = BooleanField()
    oneDrive = BooleanField()
    oneNote = BooleanField()
    outlook = BooleanField()
    noStealing = BooleanField()
    macroInjection = BooleanField()
    extension = StringField('Extentions to download', render_kw={"placeholder": "docx config xlsx"}, validators=[Length(min=0, max=200)])
    delay = StringField('Delay in requests', render_kw={"placeholder": "1"})
    submit = SubmitField('Submit')

class sprayingConfigForm(FlaskForm):
    password = StringField('Password 1', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Password"})
    moreVictims = FileField('Upload file with email id\'s for custom spray attack')
    customVictims = BooleanField()
    advanceSpray = BooleanField()
    submit = SubmitField('Save')

class bruteforceConfigForm(FlaskForm):
    usernameList = TextAreaField('Paste list of email Address')
    passwordList = TextAreaField('Paste list of password(For best result use max 9 passwords)')
    usernameListFile = FileField("Upload file with email id\'s")
    passwordListFile = FileField("Upload file with passwords. 9 passwords is recommended")
    submit = SubmitField('Save')    

class userenumeration(FlaskForm):
    userList = TextAreaField('Paste email Address for verification')
    moreVictims = FileField('Upload file with email id\'s')
    submit = SubmitField('Save')

class subdomainenumeration(FlaskForm):
    dnsList = TextAreaField('Paste wordlist for subdomain enum')
    moreVictims = FileField('Upload file with email id\'s')
    submit = SubmitField('Save')

class azureAdEnumerate(FlaskForm):
    username = StringField('Username', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Password"})
    clientId = StringField('Client Id', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Client Id from user's tenant"})
    accessToken = StringField('Access Token', render_kw={"placeholder": "eyJ0eXAiOiJKV1QiLCJub25jZSI6IjcxY2J2SUhyLU...."})
    submit = SubmitField('Enumerate')

class azureServicesEnumerate(FlaskForm):
    username = StringField('Username', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Password"})
    clientId = StringField('Client Id', validators=[Length(min=0, max=200)], render_kw={"placeholder": "Client Id from user's tenant"})
    accessToken = StringField('Access Token', render_kw={"placeholder": "eyJ0eXAiOiJKV1QiLCJub25jZSI6IjcxY2J2SUhyLU...."})
    submit = SubmitField('Enumerate')

class adminConfiguration(FlaskForm):
    username = StringField('Username', validators=[Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    new_password = PasswordField('New Password', render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('new_password')], render_kw={"placeholder": "Confirm Password"})
    enableIp = BooleanField("Enable Ip restriction")
    ips = StringField('Allowed IP for phishing page', render_kw={"placeholder": "xxx.xxx.xxx.xxx"})
    theme = BooleanField("Dark Theme")
    submit = SubmitField('Submit')
    
    def validate_username(self, username):
        user = Admin.query.filter_by(username=username.data, id=current_user.id).first()
        if user:
            pass
        else:
            user = Admin.query.filter_by(username=username.data).first()
            if user:    
                raise ValidationError('That username is taken. Please choose a different one.')


class startStealer(FlaskForm):
    submit = SubmitField('Start')

class stopStealer(FlaskForm):
    submit = SubmitField('Stop')


class storageEnumeration(FlaskForm):
    commonWord = StringField('Common Word', validators=[Length(min=1, max=200)], render_kw={"placeholder": "companyname"})
    permutations = TextAreaField('Paste your permutations list')
    submit = SubmitField("Save")