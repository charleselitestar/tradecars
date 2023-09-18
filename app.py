from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import logging
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_mail import Mail, Message
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tradecars.db'
app.config['UPLOAD_FOLDER'] = 'uploads'  # Define the folder for file uploads
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
# Replace with your email server
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Your email server's SMTP port
app.config['MAIL_USE_TLS'] = True  # Enable TLS
app.config['MAIL_USE_SSL'] = False  # Disable SSL
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_DEFAULT_SENDER'] = ''  # Default sender
# Set to True to suppress email sending during development
app.config['MAIL_SUPPRESS_SEND'] = False

mail = Mail(app)

# Configure logging
app.config['LOG_FILENAME'] = 'app.log'
app.config['LOG_LEVEL'] = logging.INFO

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(app.config['LOG_LEVEL'])

# Create a file handler
file_handler = logging.FileHandler(app.config['LOG_FILENAME'])
file_handler.setLevel(app.config['LOG_LEVEL'])

# Create a log format
log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(log_format)

# Add the file handler to the logger
logger.addHandler(file_handler)

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    user_name = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True,nullable=False)  # Add 'email' attribute
    db.relationship('CarListing', backref='user', lazy=True)


class CarListing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50))
    model = db.Column(db.String(50))
    year = db.Column(db.Integer)
    price = db.Column(db.Float)
    mileage = db.Column(db.Float)
    fuel_type = db.Column(db.String(50))
    image_filename = db.Column(db.String(100))
    description = db.Column(db.Text)
    contact_details = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



with app.app_context():
    db.create_all()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


def get_current_year():
    return datetime.now().year


@app.route('/')
def index():
    current_year = get_current_year()
    return render_template('index.html', current_year=current_year)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form['user_name']
        password = request.form['password']
        user = User.query.filter_by(user_name=user_name).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.user_name
            login_user(user)
            logger.info(f'User {user_name} logged in at {datetime.now()}')
            # Redirect to listings page upon login
            return redirect(url_for('listings', user=user))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        user_name = request.form['user_name']
        password = request.form['password']
        email = request.form['email']  # Add email field
        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')

        # Check if a user with the same username or email already exists
        existing_user = User.query.filter(
            (User.user_name == user_name) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists. Please choose different ones.', 'error')
        else:
            new_user = User(
                first_name=first_name,
                user_name=user_name,
                password=hashed_password,
                email=email
            )
            db.session.add(new_user)
            db.session.commit()

            logger.info(f'User {user_name} registered at {datetime.now()}')
            try:
            # Send a thank-you email to the user
                send_thank_you_email(email)
            except Exception as err:
                flash('Tahnks for Coming IN')
            finally:
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))

    return render_template('register.html')

# Function to send a thank-you email
def send_thank_you_email(email):
    msg = Message('Thank You for Registering!', sender='elitetechproit@gmail.com', recipients=[email])
    msg.html = 'thank_you_email.html'  # Create a HTML email template
    mail.send(msg)



@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'danger')
    return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    user_name = current_user.user_name
    logger.info(f'User {user_name} logged out at {datetime.now()}')
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/listings', methods=['GET'])
def listings():
    listings = CarListing.query.all()
    user = current_user  # You can access the current user using Flask-Login
    return render_template('listings.html', listings=listings, user=user)



@app.route('/listings/create', methods=['GET', 'POST'])
@login_required
def create_listing():
    if request.method == 'POST':
        make = request.form['make']
        model = request.form['model']


        year = int(request.form['year'])
        price = float(request.form['price'])
        mileage = float(request.form['mileage'])

        fuel_type = request.form['fuel_type']
        description = request.form['description']
        contact_details = request.form['contact_details']
        user_id = session.get('user_id')
        user_id = User.query.get(user_id)

        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        new_listing = CarListing(
            make=make,
            model=model,
            year=year,
            price=price,
            mileage=mileage,
            fuel_type=fuel_type,
            description=description,
            contact_details=contact_details,
            image_filename=filename,
            user_id=user_id
        )
        db.session.add(new_listing)
        db.session.commit()

        return redirect(url_for('listings'))

    return render_template('create_listing.html')


@app.route('/listings/update/<int:listing_id>', methods=['GET', 'POST'])
@login_required
def update_listing(listing_id):
    listing = CarListing.query.get(listing_id)
    user_id = session.get('user_id')

    if listing.user_id != user_id:
        flash('You do not have permission to update this listing.', 'danger')
        return redirect(url_for('listings'))

    if request.method == 'POST':
        # Update the listing
        listing.make = request.form['make']
        listing.model = request.form['model']
        listing.year = request.form['year']
        listing.price = request.form['price']
        listing.mileage = request.form['mileage']
        listing.fuel_type = request.form['fuel_type']
        listing.description = request.form['description']
        listing.contact_details = request.form['contact_details']

        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            listing.image_filename = filename

        db.session.commit()
        flash('Listing updated successfully!', 'success')
        return redirect(url_for('listings'))

    return render_template('update_listing.html', listing=listing)


@app.route('/listings/delete/<int:listing_id>', methods=['POST'])
@login_required
def delete_listing(listing_id):
    listing = CarListing.query.get(listing_id)
    user_id = session.get('user_id')

    if listing.user_id != user_id:
        flash('You do not have permission to delete this listing.', 'danger')
        return redirect(url_for('listings'))

    db.session.delete(listing)
    db.session.commit()
    flash('Listing deleted successfully!', 'success')
    return redirect(url_for('listings'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help():
    return render_template('help.html')


@app.route('/contact_us')
def contact():
    return render_template('contact_us.html')

if __name__ == '__main__':
    app.run(debug=True)
