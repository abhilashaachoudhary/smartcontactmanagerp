# setup_db.py
import sys
import os

# Make sure the script's directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the app and models after setting up the path
from app import app, db, User, Contact
from werkzeug.security import generate_password_hash

def setup_database():
    """Set up the database with initial users and contacts."""
    print("Starting database setup...")
    
    # This is crucial - we need to work within the Flask app context
    with app.app_context():
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        print("Database tables created!")
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(email='admin@example.com').first()
        if not existing_admin:
            # Create admin user
            print("Creating admin user...")
            admin_user = User(
                username='Admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                phone='555-987-6543',
                profile_pic='default.png',
                role='admin',
                is_verified=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists, updating...")
            existing_admin.password = generate_password_hash('admin123')
            existing_admin.is_verified = True
            db.session.commit()
            print("Admin user updated!")
        
        # Check if test user already exists
        existing_user = User.query.filter_by(email='vibhu@example.com').first()
        if not existing_user:
            # Create regular user
            print("Creating regular user...")
            regular_user = User(
                username='Vibhu',
                email='vibhu@example.com',
                password=generate_password_hash('password123'),
                phone='555-123-4567',
                profile_pic='default.png',
                role='user',
                is_verified=True
            )
            db.session.add(regular_user)
            db.session.commit()
            print("Regular user created successfully!")
            
            # Add sample contacts for Vibhu
            vibhu = User.query.filter_by(email='vibhu@example.com').first()
            
            print("Creating sample contacts for Vibhu...")
            contacts = [
                Contact(
                    name='John Doe',
                    email='john@example.com',
                    phone='123-456-7890',
                    description='College friend',
                    user_id=vibhu.id
                ),
                Contact(
                    name='Jane Smith',
                    email='jane@example.com',
                    phone='987-654-3210',
                    description='Work colleague',
                    user_id=vibhu.id
                ),
                Contact(
                    name='Alice Johnson',
                    email='alice@example.com',
                    phone='555-123-4567',
                    description='Neighbor',
                    user_id=vibhu.id
                )
            ]
            
            for contact in contacts:
                db.session.add(contact)
                
            db.session.commit()
            print("Sample contacts created for Vibhu!")
        else:
            print("Test user already exists, updating...")
            existing_user.password = generate_password_hash('password123')
            existing_user.is_verified = True
            db.session.commit()
            print("Test user updated!")
        
        # Print summary
        user_count = User.query.count()
        contact_count = Contact.query.count()
        print(f"\nDatabase setup complete!")
        print(f"Total users: {user_count}")
        print(f"Total contacts: {contact_count}")
        print("\nYou can now login with:")
        print("- Admin: admin@example.com / admin123")
        print("- User: vibhu@example.com / password123")

if __name__ == "__main__":
    setup_database()