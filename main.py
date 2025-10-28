from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
import re
import os
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from authlib.integrations.flask_client import OAuth
import json
from sqlalchemy import or_

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload folder config
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Flask-Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# OAuth Configuration
app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID', '')
app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET', '')
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET', '')

# Initialize extensions
mail = Mail(app)
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.secret_key)
oauth = OAuth(app)

# Initialize GitHub and Google OAuth
github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------------- MODELS ----------------------
class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Can be null for OAuth users
    phone = db.Column(db.String(20))
    profile_pic = db.Column(db.String(100))
    role = db.Column(db.String(10), default="user")  # 'admin' or 'user'
    is_verified = db.Column(db.Boolean, default=False)
    oauth_provider = db.Column(db.String(20), nullable=True)  # 'github', 'google', or None
    oauth_id = db.Column(db.String(100), nullable=True)
    contacts = db.relationship('Contact', backref='owner', lazy=True)
    
    @property
    def is_admin(self):
        return self.role == 'admin'


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    #work = db.Column(db.String(100))  # Added work field
    description = db.Column(db.Text)
    #date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ---------------------- UTILITIES ----------------------
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{4,20}$', username)

def is_valid_password(password):
    return len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create serializer for password reset
serializer = URLSafeTimedSerializer(app.secret_key)

# Function to create initial tables and add admin user
def create_tables_and_seed_admin():
    with app.app_context():
        db.create_all()
        # Add default admin if not present
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                is_verified=True
            )
            db.session.add(admin)
            db.session.commit()

# ---------------------- ROUTES ----------------------
@app.route('/')
def landing():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('landing.html')

@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "login":
            email = request.form.get("email")
            password = request.form.get("password")
            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password, password):
                if not user.is_verified:
                    flash("Please verify your email before logging in.", "error")
                    return redirect(url_for("auth"))
                
                login_user(user)
                
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("user_dashboard"))
            else:
                flash("Invalid email or password", "error")
                return redirect(url_for("auth"))

        elif action == "register":
            email = request.form.get("email")
            password = request.form.get("password")
            username = request.form.get("username")
            phone = request.form.get("phone")
            file = request.files.get("profile_pic")

            if not all([email, password, username, phone, file]):
                flash("All fields are required for registration.", "error")
                return redirect(url_for("auth"))

            if not file.filename.endswith(".png"):
                flash("Only PNG files are allowed!", "error")
                return redirect(url_for("auth"))

            # Check if user already exists
            existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
            if existing_user:
                flash("Username or Email already exists. Please login or use a different one.", "error")
                return redirect(url_for("auth"))

            # Save PNG file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            # Create user with hashed password
            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password),
                phone=phone,
                profile_pic=filename,
                role="user",
                is_verified=False
            )
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            token = s.dumps(email, salt='email-confirm')
            msg = Message('Confirm your Email', sender='your_email@gmail.com', recipients=[email])
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = f"Click the link to verify your email: {link}"
            
            try:
                mail.send(msg)
                flash("A verification email has been sent. Please verify before logging in.", "success")
            except Exception:
                flash("Failed to send verification email. Please contact support.", "error")
                
            return redirect(url_for("auth"))

    return render_template("login.html")

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            flash("Email verified. You can now login or use OAuth options.", "success")
        else:
            flash("Invalid verification link.", "error")
    except:
        flash("The verification link is invalid or has expired.", "error")
    
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
        
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for("login"))
                
            login_user(user)
            flash('Login successful!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials or unregistered user", "error")
            
    return render_template('login.html')

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard' if current_user.role != 'admin' else 'admin_dashboard'))

    if request.method == "POST":
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_token', token=token, _external=True)

            # Send reset email
            subject = "Password Reset Request"
            msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.html = render_template('reset_email.html',
                                       user=user,
                                       reset_link=reset_link,
                                       expiry_hours=2,
                                       support_email='support@yourapp.com',
                                       year=2025,
                                       company_name='Smart Contact Manager')
            mail.send(msg)
            flash("A password reset link has been sent to your email.", "info")
            return redirect(url_for("login"))
        else:
            flash("No account found with that email address.", "error")
    
    return render_template("forgot_password.html")

@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=7200)  # 2 hours
    except Exception:
        flash("The password reset link is invalid or has expired.", "error")
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Invalid reset request.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == "POST":
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(request.url)

        user.password = generate_password_hash(password)
        db.session.commit()
        flash("Your password has been updated successfully.", "success")
        return redirect(url_for('login'))

    return render_template("reset_password.html", token=token)


@app.route('/login/github')
def github_login():
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorize')
def github_authorize():
    token = github.authorize_access_token()
    resp = github.get('user', token=token)
    profile = resp.json()
    
    # Get user email
    emails_resp = github.get('user/emails', token=token)
    emails = emails_resp.json()
    email = next((email['email'] for email in emails if email['primary']), None)
    
    if not email:
        flash("Failed to get email from GitHub", "error")
        return redirect(url_for('login'))
    
    # Check if user exists
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Update OAuth info if needed
        if not user.oauth_provider:
            user.oauth_provider = 'github'
            user.oauth_id = str(profile['id'])
            db.session.commit()
            
        if not user.is_verified:
            flash("Please verify your email before logging in with GitHub.", "error")
            return redirect(url_for('login'))
            
        login_user(user)
    else:
        # Create new user
        username = profile['login']
        # Check if username exists
        if User.query.filter_by(username=username).first():
            username = f"{username}_{profile['id']}"
            
        new_user = User(
            username=username,
            email=email,
            password=None,
            oauth_provider='github',
            oauth_id=str(profile['id']),
            profile_pic='default.png',
            is_verified=True
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    email = user_info['email']
    
    # Check if user exists
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Update OAuth info if needed
        if not user.oauth_provider:
            user.oauth_provider = 'google'
            user.oauth_id = user_info['id']
            db.session.commit()
            
        if not user.is_verified:
            flash("Please verify your email before logging in with Google.", "error")
            return redirect(url_for('login'))
            
        login_user(user)
    else:
        # Create new user
        username = email.split('@')[0]
        # Check if username exists
        if User.query.filter_by(username=username).first():
            username = f"{username}_{user_info['id']}"
            
        new_user = User(
            username=username,
            email=email,
            password=None,
            oauth_provider='google',
            oauth_id=user_info['id'],
            profile_pic='default.png',
            is_verified=True
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
        
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        profile = request.files['profile_pic']

        # Validate input
        if not is_valid_username(username):
            flash("Username must be 4-20 characters and can only contain letters, numbers, and underscores", "error")
            return redirect(request.url)
            
        if not is_valid_password(password):
            flash("Password must be at least 8 characters and contain uppercase, lowercase, and numbers", "error")
            return redirect(request.url)

        if not profile.filename.lower().endswith('.png'):
            flash("Only PNG files allowed", "error")
            return redirect(request.url)

        # Check if user already exists
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists", "error")
            return redirect(request.url)

        # Save profile picture
        filename = secure_filename(profile.filename)
        profile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Create and add user
        new_user = User(
            username=username,
            email=email,
            phone=phone,
            password=generate_password_hash(password),
            profile_pic=filename
        )
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm your Email', sender='your_email@gmail.com', recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f"Click the link to verify your email: {link}"
        
        try:
            mail.send(msg)
            flash("Registration successful! Verification email sent.", "info")
        except Exception:
            flash("Registration successful! Failed to send verification email. Please contact support.", "warning")
            
        return redirect(url_for('login'))
        
    return render_template("register.html")

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

# Admin Dashboard
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("You don't have permission to access the admin dashboard", "error")
        return redirect(url_for('user_dashboard'))
        
    users = User.query.all()
    contacts = Contact.query.all()
    return render_template('admin_dashboard.html', users=users, contacts=contacts)

# Admin - Manage Users
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != "admin":
        flash("You don't have permission to access this page", "error")
        return redirect(url_for('user_dashboard'))
        
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Admin - Manage Contacts
@app.route('/admin/contacts')
@login_required
def admin_contacts():
    if current_user.role != "admin":
        flash("You don't have permission to access this page", "error")
        return redirect(url_for('user_dashboard'))
        
    contacts = Contact.query.all()
    return render_template('admin_contacts.html', contacts=contacts)

# Admin - Create Contact
@app.route('/admin/add_contact', methods=['GET', 'POST'])
@login_required
def admin_add_contact():
    if current_user.role != "admin":
        flash("You don't have permission to access this page", "error")
        return redirect(url_for('user_dashboard'))
        
    users = User.query.all()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        description = request.form['description']
        user_id = request.form['user_id']
        
        new_contact = Contact(
            name=name,
            email=email,
            phone=phone,
            description=description,
            user_id=user_id
        )
        db.session.add(new_contact)
        db.session.commit()
        
        flash("Contact added successfully!", "success")
        return redirect(url_for('admin_contacts'))
        
    return render_template('admin_add_contact.html', users=users)

# Admin - Edit Contact
@app.route('/admin/edit_contact/<int:id>', methods=['GET', 'POST'])
@login_required
def admin_edit_contact(id):
    if current_user.role != "admin":
        flash("You don't have permission to access this page", "error")
        return redirect(url_for('user_dashboard'))
        
    contact = Contact.query.get_or_404(id)
    users = User.query.all()
    
    if request.method == 'POST':
        contact.name = request.form['name']
        contact.email = request.form['email']
        contact.phone = request.form['phone']
        contact.description = request.form['description']
        contact.user_id = request.form['user_id']
        
        db.session.commit()
        flash("Contact updated successfully!", "success")
        return redirect(url_for('admin_contacts'))
        
    return render_template('admin_edit_contact.html', contact=contact, users=users)

# Admin - Delete Contact
@app.route('/admin/delete_contact/<int:id>')
@login_required
def admin_delete_contact(id):
    if current_user.role != "admin":
        flash("You don't have permission to delete this contact", "error")
        return redirect(url_for('user_dashboard'))
    
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    
    flash("Contact deleted successfully!", "info")
    return redirect(url_for('admin_contacts'))

# User Dashboard Route
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    search_query = request.args.get('search', '')
    
    if search_query:
        # If search query is provided, filter contacts
        search = f"%{search_query}%"
        contacts = Contact.query.filter(
            Contact.user_id == current_user.id,
            or_(
                Contact.name.ilike(search),
                Contact.email.ilike(search),
                Contact.phone.ilike(search),
            )
        ).all()
    else:
        # Otherwise, get all contacts for the user
        contacts = Contact.query.filter_by(user_id=current_user.id).all()
    
    return render_template('user_dashboard.html', contacts=contacts)

# View Contact Details
@app.route('/contact/<int:contact_id>')
@login_required
def view_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    # Ensure the current user owns this contact
    if contact.user_id != current_user.id:
        flash('You do not have permission to view this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('view_contact.html', contact=contact)

# Add New Contact
@app.route('/contact/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        #work = request.form.get('work')
        description = request.form.get('description')
        
        if not name:
            flash('Name is required!', 'danger')
            return redirect(url_for('add_contact'))
        
        new_contact = Contact(
            name=name,
            email=email,
            phone=phone,
            #work=work,
            description=description,
            user_id=current_user.id
        )
        
        try:
            db.session.add(new_contact)
            db.session.commit()
            flash('Contact added successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding contact: {str(e)}', 'danger')
    
    return render_template('add_contact.html')

# Edit Contact
@app.route('/contact/edit/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    # Ensure the current user owns this contact
    if contact.user_id != current_user.id:
        flash('You do not have permission to edit this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        contact.name = request.form.get('name')
        contact.email = request.form.get('email')
        contact.phone = request.form.get('phone')
        #contact.work = request.form.get('work')
        contact.description = request.form.get('description')
        
        if not contact.name:
            flash('Name is required!', 'danger')
            return redirect(url_for('edit_contact', contact_id=contact.id))
        
        try:
            db.session.commit()
            flash('Contact updated successfully!', 'success')
            return redirect(url_for('view_contact', contact_id=contact.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating contact: {str(e)}', 'danger')
    
    return render_template('edit_contact.html', contact=contact)

# Delete Contact
@app.route('/contact/delete/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    # Ensure the current user owns this contact
    if contact.user_id != current_user.id:
        flash('You do not have permission to delete this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contact deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting contact: {str(e)}', 'danger')
    
    return redirect(url_for('user_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/about')
def about():
    return render_template('about.html')

# ---------------------- SETUP ROUTES ----------------------
@app.route('/setup-test-users')
def setup_test_users():
    """
    Creates test users in the database - one regular user and one admin
    Access this route once to set up the users
    """
    try:
        # Check if users already exist
        vibhu_exists = User.query.filter_by(email='vibhu@example.com').first()
        admin_exists = User.query.filter_by(email='admin@example.com').first()
        
        if not vibhu_exists:
            # Create regular user - Vibhu
            regular_user = User(
                username='Vibhu',
                email='vibhu@example.com',
                password=generate_password_hash('password123'),
                role='user',
                is_verified=True
            )
            db.session.add(regular_user)
        
        if not admin_exists:
            # Create admin user
            admin_user = User(
                username='Admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                is_verified=True
            )
            db.session.add(admin_user)
        
        # Commit changes
        db.session.commit()
        
        # Add some sample contacts for Vibhu
        if not vibhu_exists:
            vibhu = User.query.filter_by(email='vibhu@example.com').first()
            
            # Add 3 sample contacts
            contacts = [
                Contact(
                    name='John Doe',
                    email='john@example.com',
                    phone='123-456-7890',
                    #work='Software Developer',
                    description='College friend',
                    user_id=vibhu.id
                ),
                Contact(
                    name='Jane Smith',
                    email='jane@example.com',
                    phone='987-654-3210',
                    #work='Designer',
                    description='Work colleague',
                    user_id=vibhu.id
                ),
                Contact(
                    name='Alice Johnson',
                    email='alice@example.com',
                    phone='555-123-4567',
                    #work='Teacher',
                    description='Neighbor',
                    user_id=vibhu.id
                )
            ]
            
            for contact in contacts:
                db.session.add(contact)
                
            db.session.commit()
        
        return 'Test users created: <br>Regular User - Email: vibhu@example.com, Password: password123 <br>Admin User - Email: admin@example.com, Password: admin123'
    
    except Exception as e:
        db.session.rollback()
        return f'Error creating test users: {str(e)}'

# Make sure this part is at the end of your file
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)