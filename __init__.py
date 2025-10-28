import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)

    # Load config from environment
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-key-for-dev')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contacts.db'

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Import and register routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app
