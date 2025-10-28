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
from functools import wraps

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
login_manager.login_message = "Please log in to access this page"
login_manager.login_message_category = "error"

# ---------------------- MODELS ----------------------

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Can be null for OAuth users
    phone = db.Column(db.String(20))
    profile_pic = db.Column(db.String(100), default='default.png')
    role = db.Column(db.String(10), default="user")  # 'admin' or 'user'
    is_verified = db.Column(db.Boolean, default=False)
    oauth_provider = db.Column(db.String(20), nullable=True)  # 'github', 'google', or None
    oauth_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    contacts = db.relationship('Contact', backref='owner', lazy=True)
    
    @property
    def is_admin(self):
        return self.role == 'admin'


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ---------------------- UTILITIES ----------------------
# Enhanced RBAC decorators
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page", "error")
                return redirect(url_for('login', next=request.url))
                
            if current_user.role != role:
                flash(f"You need {role} privileges to access this page", "error")
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Admin specific decorator - More readable version
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in to access this page", "error")
            return redirect(url_for('login', next=request.url))
            
        if current_user.role != 'admin':
            flash("You need admin privileges to access this page", "error")
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{4,20}$', username)

def is_valid_password(password):
    return len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create serializer for password reset and email verification
serializer = URLSafeTimedSerializer(app.secret_key)

# Send verification email function
def send_verification_email(user):
    token = serializer.dumps(user.email, salt='email-verification-salt')
    verify_link = url_for('verify_email', token=token, _external=True)
    
    # Create verification email
    subject = "Verify Your Email Address"
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.html = render_template('verification_email.html',
                             user=user,
                             verify_link=verify_link,
                             expiry_hours=24,
                             support_email='support@smartcontactmanager.com',
                             year=2025,
                             company_name='Smart Contact Manager')
    mail.send(msg)

# Function to create initial tables and add admin user
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
            print("Admin user created successfully!")
        
        # Add dummy users for testing RBAC
        test_users = [
            {
                'username': 'regularuser',
                'email': 'user@example.com',
                'password': generate_password_hash('Password123'),
                'phone': '555-123-4567',
                'role': 'user',
                'is_verified': True
            },
            {
                'username': 'testadmin',
                'email': 'testadmin@example.com',
                'password': generate_password_hash('Admin123'),
                'phone': '555-987-6543',
                'role': 'admin',
                'is_verified': True
            },
            {
                'username': 'unverifieduser',
                'email': 'unverified@example.com',
                'password': generate_password_hash('Password123'),
                'phone': '555-111-2222',
                'role': 'user',
                'is_verified': False
            },
            {
                'username': 'oauthuser',
                'email': 'oauth@example.com',
                'password': None,
                'phone': '555-333-4444',
                'role': 'user',
                'is_verified': True,
                'oauth_provider': 'github',
                'oauth_id': '12345'
            }
        ]
        
        # Add some sample contacts for testing
        sample_contacts = [
            {
                'name': 'John Doe',
                'email': 'john.doe@example.com',
                'phone': '555-111-3333',
                'description': 'Important business contact',
                'user_email': 'user@example.com'
            },
            {
                'name': 'Jane Smith',
                'email': 'jane.smith@example.com',
                'phone': '555-222-4444',
                'description': 'Project manager for ABC project',
                'user_email': 'user@example.com'
            },
            {
                'name': 'Bob Johnson',
                'email': 'bob@example.com',
                'phone': '555-333-5555',
                'description': 'Tech support',
                'user_email': 'testadmin@example.com'
            }
        ]
        
        # Add test users if they don't exist
        for user_data in test_users:
            if not User.query.filter_by(email=user_data['email']).first():
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password'],
                    phone=user_data.get('phone'),
                    role=user_data['role'],
                    is_verified=user_data['is_verified'],
                    oauth_provider=user_data.get('oauth_provider'),
                    oauth_id=user_data.get('oauth_id')
                )
                db.session.add(user)
                db.session.commit()
                print(f"Test user {user_data['username']} created successfully!")
        
        # Add sample contacts
        for contact_data in sample_contacts:
            user = User.query.filter_by(email=contact_data['user_email']).first()
            if user and not Contact.query.filter_by(email=contact_data['email'], user_id=user.id).first():
                contact = Contact(
                    name=contact_data['name'],
                    email=contact_data['email'],
                    phone=contact_data['phone'],
                    description=contact_data['description'],
                    user_id=user.id
                )
                db.session.add(contact)
                db.session.commit()
                print(f"Sample contact {contact_data['name']} created successfully for {user.username}!")

# ---------------------- ROUTES ----------------------
@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Debug print statements (remove in production)
        print(f"Login attempt: {email}")
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash("No account found with that email address", "error")
            return redirect(url_for('login'))
        
        if user.oauth_provider:
            flash("Please login using your OAuth provider", "error")
            return redirect(url_for('login'))
            
        if not user.password:
            flash("Invalid login method, please use OAuth", "error")
            return redirect(url_for('login'))
        
        if check_password_hash(user.password, password):
            if not user.is_verified:
                # Store email in session for the verification popup
                session['unverified_email'] = user.email
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for("login", show_verification=True))
                
            login_user(user)
            flash('Login successful!', 'success')
            
            # Get the next parameter or default to dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid password. Please try again.", "error")
            
    # Check if we should show verification popup
    show_verification = request.args.get('show_verification', False)
    unverified_email = session.get('unverified_email', None)
            
    return render_template('login.html', show_verification=show_verification, unverified_email=unverified_email)

@app.route('/verify/resend', methods=['POST'])
def resend_verification():
    email = request.form.get('email')
    if not email:
        email = session.get('unverified_email')
        
    if not email:
        flash("Email address is required", "error")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No account found with that email address", "error")
        return redirect(url_for('login'))
    
    if user.is_verified:
        flash("This account is already verified", "info")
        return redirect(url_for('login'))
    
    # Send verification email
    try:
        send_verification_email(user)
        flash("A new verification email has been sent!", "success")
    except Exception as e:
        flash(f"Error sending verification email: {str(e)}", "error")
    
    return redirect(url_for('login', show_verification=True))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=86400)  # 24 hours
    except:
        flash("The verification link is invalid or has expired", "error")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Invalid verification link", "error")
        return redirect(url_for('login'))
    
    if user.is_verified:
        flash("Your account is already verified", "info")
    else:
        user.is_verified = True
        db.session.commit()
        flash("Your email has been verified! You can now log in.", "success")
    
    # Clear any unverified email from session
    if 'unverified_email' in session:
        session.pop('unverified_email')
    
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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
                                       support_email='support@smartcontactmanager.com',
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

        if not is_valid_password(password):
            flash("Password must be at least 8 characters and contain uppercase, lowercase, and numbers", "error")
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
            # Store email in session for the verification popup
            session['unverified_email'] = user.email
            flash("Please verify your email before logging in with GitHub.", "error")
            return redirect(url_for('login', show_verification=True))
            
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
            is_verified=True  # OAuth users are auto-verified
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    
    return redirect(url_for('dashboard'))

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
            # Store email in session for the verification popup
            session['unverified_email'] = user.email
            flash("Please verify your email before logging in with Google.", "error")
            return redirect(url_for('login', show_verification=True))
            
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
            is_verified=True  # OAuth users are auto-verified
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    
    return redirect(url_for('dashboard'))

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        # Handle profile picture
        if 'profile_pic' in request.files and request.files['profile_pic'].filename:
            profile = request.files['profile_pic']
            if not profile.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                flash("Only PNG, JPG, and JPEG files allowed", "error")
                return redirect(request.url)
            filename = secure_filename(profile.filename)
            profile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = 'default.png'  # Default profile picture

        # Validate input
        if not is_valid_username(username):
            flash("Username must be 4-20 characters and can only contain letters, numbers, and underscores", "error")
            return redirect(request.url)
            
        if not is_valid_password(password):
            flash("Password must be at least 8 characters and contain uppercase, lowercase, and numbers", "error")
            return redirect(request.url)

        # Check if user already exists
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists", "error")
            return redirect(request.url)

        # Create and add user
        new_user = User(
            username=username,
            email=email,
            phone=phone,
            password=generate_password_hash(password),
            profile_pic=filename,
            is_verified=False  # Set to False by default, requiring verification
        )
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        try:
            send_verification_email(new_user)
            # Store email in session for verification popup
            session['unverified_email'] = new_user.email
            flash("Registration successful! Please check your email to verify your account.", "success")
        except Exception as e:
            flash(f"Registration successful, but there was an error sending verification email: {str(e)}", "warning")
            
        return redirect(url_for('login', show_verification=True))
        
    return render_template("register.html")

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main dashboard that redirects based on user role
    """
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

# Admin Dashboard - fixed with proper RBAC
# Admin Dashboard - fixed with proper pagination and tab handling
@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    # Get tab from query params, default to 'users'
    tab = request.args.get('tab', 'users')
    
    # Handle pagination
    user_page = int(request.args.get('page', 1))
    per_page = 10  # Number of items per page
    
    if tab == 'users':
        # Get paginated users
        users_pagination = User.query.paginate(page=user_page, per_page=per_page, error_out=False)
        users = users_pagination.items
        user_pages = users_pagination.pages
        
        # Get all contacts for the other tab (not paginated here as we'll use another route for that)
        contacts = []
        contact_pages = 1
        contact_page = 1
    else:
        # Get paginated contacts
        contact_page = int(request.args.get('page', 1))
        contacts_pagination = Contact.query.paginate(page=contact_page, per_page=per_page, error_out=False)
        contacts = contacts_pagination.items
        contact_pages = contacts_pagination.pages
        
        # Get all users for the other tab
        users = []
        user_pages = 1
    
    return render_template('admin_dashboard.html', 
                          users=users, 
                          contacts=contacts,
                          tab=tab,
                          user_page=user_page,
                          user_pages=user_pages,
                          contact_page=contact_page,
                          contact_pages=contact_pages)

# Admin - Search Users
@app.route('/admin/search_users')
@login_required
@admin_required
def admin_search_users():
    query = request.args.get('query', '')
    if query:
        search = f"%{query}%"
        users = User.query.filter(
            or_(
                User.username.ilike(search),
                User.email.ilike(search)
            )
        ).all()
    else:
        users = User.query.all()
    
    return render_template('admin_dashboard.html', 
                          users=users, 
                          contacts=[],
                          tab='users',
                          user_page=1,
                          user_pages=1,
                          contact_page=1,
                          contact_pages=1)

# Admin - Manage Users
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Admin - Toggle User Verification
@app.route('/admin/toggle_verification/<int:user_id>')
@login_required
@admin_required
def admin_toggle_verification(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()
    
    flash(f"User {user.username}'s verification status updated.", "success")
    return redirect(url_for('admin_users'))

# Admin - Manage User Roles
@app.route('/admin/update_role/<int:user_id>/<role>')
@login_required
@admin_required
def admin_update_role(user_id, role):
    if role not in ['user', 'admin']:
        flash("Invalid role specified", "error")
        return redirect(url_for('admin_users'))
        
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from changing their own role
    if user.id == current_user.id:
        flash("You cannot change your own role", "error")
        return redirect(url_for('admin_users'))
        
    user.role = role
    db.session.commit()
    flash(f"User {user.username}'s role updated to {role}", "success")
    return redirect(url_for('admin_users'))

# Admin - Manage Contacts
# Admin - Manage Contacts with search and pagination
@app.route('/admin/contacts')
@login_required
@admin_required
def admin_contacts():
    query = request.args.get('query', '')
    page = int(request.args.get('page', 1))
    per_page = 10
    
    if query:
        search = f"%{query}%"
        contacts_pagination = Contact.query.filter(
            or_(
                Contact.name.ilike(search),
                Contact.email.ilike(search),
                Contact.phone.ilike(search),
                Contact.description.ilike(search)
            )
        ).paginate(page=page, per_page=per_page, error_out=False)
    else:
        contacts_pagination = Contact.query.paginate(page=page, per_page=per_page, error_out=False)
    
    contacts = contacts_pagination.items
    contact_pages = contacts_pagination.pages
    
    return render_template('admin_dashboard.html', 
                          users=[],
                          contacts=contacts,
                          tab='contacts',
                          user_page=1,
                          user_pages=1,
                          contact_page=page,
                          contact_pages=contact_pages)

# Admin - Create Contact
@app.route('/admin/add_contact', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_contact():
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
        
    return render_template('add_contact.html', users=users)

# Admin - Edit Contact
@app.route('/admin/edit_contact/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_contact(id):
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
@admin_required
def admin_delete_contact(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    
    flash("Contact deleted successfully!", "info")
    return redirect(url_for('admin_contacts'))

# User Dashboard Route - Only search and view functionality
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
    
    # Ensure the current user owns this contact or is an admin
    if contact.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('view_contact.html', contact=contact)

# Add New Contact - Available to all users
@app.route('/contact/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        description = request.form.get('description')
        
        if not name:
            flash('Name is required!', 'danger')
            return redirect(url_for('add_contact'))
        
        new_contact = Contact(
            name=name,
            email=email,
            phone=phone,
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

# Edit Contact - Available only to admins for any contact, or users for their own contacts
@app.route('/contact/edit/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    # Ensure the current user has permission to edit this contact
    if contact.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        contact.name = request.form.get('name')
        contact.email = request.form.get('email')
        contact.phone = request.form.get('phone')
        contact.description = request.form.get('description')
        
        if not contact.name:
            flash('Name is required!', 'danger')
            return redirect(url_for('edit_user', contact_id=contact.id))
        
        try:
            db.session.commit()
            flash('Contact updated successfully!', 'success')
            
            if current_user.is_admin:
                return redirect(url_for('admin_contacts'))
            return redirect(url_for('view_contact', contact_id=contact.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating contact: {str(e)}', 'danger')
    
    return render_template('edit_user.html', contact=contact)

# Delete Contact - Available only to admins for any contact, or users for their own contacts
@app.route('/contact/delete/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    # Ensure the current user has permission to delete this contact
    if contact.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this contact.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contact deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting contact: {str(e)}', 'danger')
    
    if current_user.is_admin:
        return redirect(url_for('admin_contacts'))
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

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        
        # Check if username is valid
        if not is_valid_username(username):
            flash("Username must be 4-20 characters and can only contain letters, numbers, and underscores", "error")
            return redirect(url_for('edit_user'))
            
        # Check if username or email already exists for another user
        if username != current_user.username and User.query.filter_by(username=username).first():
            flash("Username is already taken", "error")
            return redirect(url_for('edit_user'))
            
        if email != current_user.email and User.query.filter_by(email=email).first():
            flash("Email is already taken", "error") 
            return redirect(url_for('edit_user'))
        
        # Handle password change if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            # If user has a password (not OAuth user)
            if current_user.password:
                if not check_password_hash(current_user.password, current_password):
                    flash("Current password is incorrect", "error")
                    return redirect(url_for('edit_user'))
                
                if new_password != confirm_password:
                    flash("New passwords do not match", "error")
                    return redirect(url_for('edit_user'))
                
                if not is_valid_password(new_password):
                    flash("Password must be at least 8 characters and contain uppercase, lowercase, and numbers", "error")
                    return redirect(url_for('edit_user'))
                
                current_user.password = generate_password_hash(new_password)
            else:
                flash("You cannot set a password as you're using OAuth login", "error")
                return redirect(url_for('edit_user'))
        
        # Handle profile picture update
        if 'profile_pic' in request.files and request.files['profile_pic'].filename:
            profile = request.files['profile_pic']
            if profile.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                # Delete old profile picture if it's not the default
                if current_user.profile_pic != 'default.png':
                    try:
                        old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic)
                        if os.path.exists(old_pic_path):
                            os.remove(old_pic_path)
                    except Exception as e:
                        print(f"Error removing old profile picture: {str(e)}")
                
                # Save new profile picture
                filename = secure_filename(f"{current_user.id}_{profile.filename}")
                profile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_pic = filename
            else:
                flash("Only PNG, JPG, and JPEG files allowed", "error")
                return redirect(url_for('edit_user'))
        
        # Update user information
        current_user.username = username
        
        # Handle email change - if email changed, require reverification
        if email != current_user.email:
            current_user.email = email
            current_user.is_verified = False
            db.session.commit()
            
            # Send verification email
            try:
                send_verification_email(current_user)
                flash("Profile updated! Please verify your new email address.", "success")
                return redirect(url_for('profile'))
            except Exception as e:
                flash(f"Profile updated, but there was an error sending verification email: {str(e)}", "warning")
                return redirect(url_for('profile'))
        
        current_user.phone = phone
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    
    return render_template('edit_user.html', user=current_user)

@app.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Check if user is using OAuth
        if current_user.oauth_provider:
            if request.form.get('confirm') == 'yes':
                # Delete all user's contacts
                Contact.query.filter_by(user_id=current_user.id).delete()
                
                # Delete user
                db.session.delete(current_user)
                db.session.commit()
                
                logout_user()
                flash("Your account has been permanently deleted.", "info")
                return redirect(url_for('landing'))
        else:
            # Password verification for regular users
            if check_password_hash(current_user.password, password):
                # Delete all user's contacts
                Contact.query.filter_by(user_id=current_user.id).delete()
                
                # Delete user
                db.session.delete(current_user)
                db.session.commit()
                
                logout_user()
                flash("Your account has been permanently deleted.", "info")
                return redirect(url_for('landing'))
            else:
                flash("Incorrect password. Account deletion canceled.", "error")
                return redirect(url_for('profile'))
    
    return render_template('delete_user.html', user=current_user)

@app.route('/api/contacts')
@login_required
def api_contacts():
    """API endpoint to get all contacts for the current user"""
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    result = []
    
    for contact in contacts:
        result.append({
            'id': contact.id,
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'description': contact.description
        })
    
    return json.dumps(result)

@app.route('/export')
@login_required
def export_contacts():
    """Export all contacts as JSON file"""
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    result = []
    
    for contact in contacts:
        result.append({
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'description': contact.description
        })
    
    return json.dumps(result)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact-us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

if __name__ == '__main__':
    create_tables_and_seed_admin()
    app.run(debug=True)