class RequestResetForm(FlaskForm):
	email = StringField('Email',
						validators=[DataRequired(), Email()])
	submit = SubmitField('Request Password Reset')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is None:
			raise ValidationError('There is no account with that email. You must register first.')

# Corey
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(15), unique=True)
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))

	def get_reset_token(self, expires_sec=1800):
		s = Serializer(app.config['SECRET_KEY'], expires_sec)
		return s.dumps({'user_id': self.id}).decode('utf-8')

	@staticmethod
	def verify_reset_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			user_id = s.loads(token)['user_id']
		except:
			return None
		return User.query.get(user_id)

	def __repr__(self):
		return f"User('{self.username}', '{self.email}', '{self.image_file}')"

#msknew

# class ForgotForm(FlaskForm):
# 	email = StringField('Email Address',
# 		[validators.DataRequired(), validators.Email()]
# 		)

# class PasswordResetForm(Form):
# 	current_password = PasswordField('Current Password',
# 		[validators.DataRequired(),
# 		validators.Length(min=4, max=80)]
# 		)

#-----------------------------------------------------------------------
# MSKnew
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

class EmailForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])

class PasswordForm(FlaskForm):
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])



def send_reset_email(user):
	token = user.get_reset_token()
	msg = Message('Password Reset Request',
				  sender='myemail@myemail.com',
				  recipients=[user.email])
	msg.body = '''To reset your password, visit the following link:
{url}
If you did not make this request then simply ignore this email and no changes will be made.
'''.format(url=url_for('reset_token', token=token, _external=True))

	mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RequestResetForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		send_reset_email(user)
		flash('An email has been sent with instructions to reset your password.', 'info')
		return redirect(url_for('login'))
	return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	user = User.verify_reset_token(token)
	if user is None:
		flash('That is an invalid or expired token', 'warning')
		return redirect(url_for('reset_request'))
	form = ResetPasswordForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password = hashed_password
		db.session.commit()
		flash('Your password has been updated! You are now able to log in', 'success')
		return redirect(url_for('login'))
	return render_template('reset_token.html', title='Reset Password', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
	form = EmailForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			# if check_password_hash(user.password, form.password.data):
			# 	login_user(user, remember=form.remember.data)
			# 	return redirect(url_for('scrapelist2'))

			email_list = 'myemail@myemail.com'

			user_name = form.username.data
			message_all = 'Hi ' + user_name + '!' + '\n' + '\n' + 'Heres your Password Reset link!' + '\n' + 'If you have any questions or things you would like to report, please email surfsendhelp@gmail.com.' + '\n' + '\n' + 'Warm Regards,' + '\n' + '	-Team SurfSend'

			msg = MIMEMultipart()
			msg['From'] = 'myemail@myemail.com'
			msg['To'] = 'myemail@myemail.com'
			msg['Subject'] = 'Thanks for Registering!'
			# message = j + 'ft' ' @ ' + k + ' on ' + l
			# print(message)
			msg.attach(MIMEText(message_all))

			mailserver = smtplib.SMTP('smtp.gmail.com',587)
			# identify ourselves to smtp gmail client
			mailserver.ehlo()
			# secure our email with tls encryption
			mailserver.starttls()
			# re-identify ourselves as an encrypted connection
			mailserver.ehlo()
			mailserver.login('myemail@myemail.com', 'Celtics123')

			mailserver.sendmail('myemail@myemail.com',email_list,msg.as_string())

			mailserver.quit()





		flash('Invalid Username/Password')
		#return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

	return render_template('reset_request.html', form=form)


@app.route('/reset', methods=["GET", "POST"])
def reset():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first_or_404()
		if user:

			subject = "Password reset requested"

			# Here we use the URLSafeTimedSerializer we created in `util` at the
			# beginning of the chapter
			token = ts.dumps(user.email, salt='recover-key')

			recover_url = url_for(
				'reset_with_token',
				token=token,
				_external=True)

			html = render_template(
				'email/recover.html',
				recover_url=recover_url)

			# Let's assume that send_email was defined in myapp/util.py
			send_email(user.email, subject, html)


			email_list = form.email.data

			msg = MIMEMultipart()
			msg['From'] = 'myemail@myemail.com'
			msg['To'] = 'myemail@myemail.com'
			msg['Subject'] = 'Password Reset Link'
			# message = j + 'ft' ' @ ' + k + ' on ' + l
			# print(message)
			msg.attach(MIMEText(html))

			mailserver = smtplib.SMTP('smtp.gmail.com',587)
			# identify ourselves to smtp gmail client
			mailserver.ehlo()
			# secure our email with tls encryption
			mailserver.starttls()
			# re-identify ourselves as an encrypted connection
			mailserver.ehlo()
			mailserver.login('myemail@myemail.com', 'Celtics123')

			mailserver.sendmail('myemail@myemail.com',email_list,msg.as_string())

			mailserver.quit()



			flash('Password Reset Email Sent!')
		else:
			flash('User Doesnt Exist!')
	return render_template('forgot.html', form=form)

@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
	try:
		email = ts.loads(token, salt="recover-key", max_age=86400)
	except:
		abort(404)

	form = PasswordForm()

	if form.validate_on_submit():
		user = User.query.filter_by(email=email).first_or_404()

		user.password = form.password.data

		db.session.add(user)
		db.session.commit()

		return redirect(url_for('signin'))

	return render_template('reset_with_token.html', form=form, token=token)


@app.route("/login", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('scrapelist2'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user and check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('scrapelist2'))
		else:
			flash('Login Unsuccessful. Please check email and password', 'danger')
	return render_template('login.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		flash(Markup('User Created! <a href="/login" class="alert-link">Sign In Now &#8594;</a>'))

				#Send A Welcome Email Upon Registering
		email_list = form.email.data

		user_name = form.username.data
		message_all = 'Hi ' + user_name + '!' + '\n' + '\n' + 'Thanks for registering for SurfSend!' + '\n' + 'If you have any questions or things you would like to report, please email surfsendhelp@gmail.com.' + '\n' + '\n' + 'Warm Regards,' + '\n' + '	-Team SurfSend'

		msg = MIMEMultipart()
		msg['From'] = 'myemail@myemail.com'
		msg['To'] = 'myemail@myemail.com'
		msg['Subject'] = 'Thanks for Registering!'
		# message = j + 'ft' ' @ ' + k + ' on ' + l
		# print(message)
		msg.attach(MIMEText(message_all))

		mailserver = smtplib.SMTP('smtp.gmail.com',587)
		# identify ourselves to smtp gmail client
		mailserver.ehlo()
		# secure our email with tls encryption
		mailserver.starttls()
		# re-identify ourselves as an encrypted connection
		mailserver.ehlo()
		mailserver.login('myemail@myemail.com', 'x')

		mailserver.sendmail('myemail@myemail.com',email_list,msg.as_string())

		mailserver.quit()
		#return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

	return render_template('register.html', form=form)