from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models import User, Contact
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

main_bp = Blueprint('main', __name__)

@main_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201

@main_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid credentials"), 401

@main_bp.route('/contacts', methods=['POST'])
@jwt_required()
def add_contact():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    new_contact = Contact(name=data['name'], email=data['email'], phone=data['phone'], user_id=current_user_id)
    db.session.add(new_contact)
    db.session.commit()
    return jsonify(message="Contact added successfully"), 201

@main_bp.route('/contacts', methods=['GET'])
@jwt_required()
def get_contacts():
    current_user_id = get_jwt_identity()
    contacts = Contact.query.filter_by(user_id=current_user_id).all()
    return jsonify(contacts=[{'name': contact.name, 'email': contact.email, 'phone': contact.phone} for contact in contacts])
