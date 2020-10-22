import datetime
import os
import uuid
import sys
from flask import Flask, render_template, redirect, url_for, flash
from flask_cqlalchemy import CQLAlchemy

from flask_wtf import FlaskForm
from flask_login import login_user, login_required, logout_user, LoginManager, UserMixin, current_user
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from passlib.hash import sha256_crypt

from cassandra.cqlengine.query import BatchQuery

db = CQLAlchemy()
login_manager = LoginManager()

class UserCredentials(db.Model, UserMixin):
	username = db.columns.Text(primary_key=True, required=True)
	password = db.columns.Text(required=True)
	uuid = db.columns.UUID(default=uuid.uuid4)

	def get_id(self):
		return self.uuid

class Users(db.Model, UserMixin):
	uuid = db.columns.UUID(primary_key=True, default=uuid.uuid4)
	username = db.columns.Text(required=True)
	first_name = db.columns.Text(required=True)
	last_name = db.columns.Text(required=True)
	created_date = db.columns.DateTime(required=True)

class LoginForm(FlaskForm):
	username = StringField(validators=[DataRequired()], render_kw={"placeholder": "username"})
	password = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "username"})


class RegistrationForm(FlaskForm):
	username = StringField(validators=[DataRequired()], render_kw={"placeholder": "username"})
	first_name = StringField(validators=[DataRequired()], render_kw={"placeholder": "first name"})
	last_name = StringField(validators=[DataRequired()], render_kw={"placeholder": "last name"})
	password = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "password"})


def create_app():
	app = Flask(__name__)
	app.config['ASTRA_SECURE_CONNECT_BUNDLE'] = os.environ['ASTRA_SECURE_CONNECT_BUNDLE']
	app.config['CASSANDRA_KEYSPACE'] = os.environ['CASSANDRA_KEYSPACE']
	app.config['CASSANDRA_USERNAME'] = os.environ['CASSANDRA_USERNAME']
	app.config['CASSANDRA_PASSWORD'] = os.environ['CASSANDRA_PASSWORD']

	app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

	login_manager.init_app(app)
	db.init_app(app)
	with app.app_context():
		db.sync_db()

	@login_manager.user_loader
	def load_user(user_id):
		if user_id is not None:
			try:
				return Users.objects.get(uuid=user_id)
			except:
				pass
		return None


	@app.route('/')
	def index():
		if current_user.is_authenticated == False:
			return redirect( url_for( 'login' ))

		return render_template('index.html')
	
	@app.route('/logout/')
	def logout():
		logout_user()
		
		return redirect( url_for('index') )

	@app.route('/login/', methods=('GET', 'POST'))
	def login():
		login_form = LoginForm()
		if login_form.validate_on_submit():
			try:
				user_from_db = UserCredentials.objects.get(username=login_form.username.data)
				if sha256_crypt.verify(login_form.password.data, user_from_db.password):
					flash('login accepted')
					login_user(user_from_db)
				else:
					flash('Invalid credentials')
					
			except AttributeError as error:
				flash(str(error))
			except Exception as error:
				flash(str(error))

			return redirect( url_for('index' ))
		else:
			return render_template('login.html', form=login_form)


	@app.route('/reg/', methods=('GET', 'POST'))
	def registration():
		reg_form = RegistrationForm()
		if reg_form.validate_on_submit():
			# handle regsitration here
			try:
				user_from_db = UserCredentials.objects.get(username=reg_form.username.data)
				
				flash('Username already taken')
				return redirect( url_for('index' ))
			except:
				pass	
			
			# create the new user

			with BatchQuery() as b:
				new_user = Users.batch(b).create(username=reg_form.username.data,
							first_name=reg_form.first_name.data,
							last_name=reg_form.last_name.data,
							created_date=datetime.datetime.now(datetime.timezone.utc))
				new_user_creds = UserCredentials.batch(b).create(username=reg_form.username.data,
										password=sha256_crypt.hash(reg_form.password.data),
										uuid=new_user.uuid)

			
				b.execute()
			
						
				flash('User created')
				return redirect( url_for('index' ))
		else:
			return render_template('registration.html', form=reg_form)

	return app


if __name__ == '__main__':
	main()

"""
	@app.route('/create/<user>')
	def create_user(user):
		num = { "876-5309" : True, "410-1234" : False }
		u = User.create(username=user, phone_numbers=num)
		print(u)
		return '%s created' % user

			ixcept
	@app.route('/list')
	def list_users():
		s = ''
		users = User.objects.all()
		for u in users:
			s += u.username
			if u.phone_numbers != None:
				for k, v in u.phone_numbers.items():
					print('%s %d' % (k,v))

			s += '<br/>'
		return render_template('user_list.html', users=users) 

"""
