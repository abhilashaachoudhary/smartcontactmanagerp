from flask import request, jsonify

@main_bp.route('/contact', methods=['POST'])
def create_contact():
    data = request.get_json()

    # Ensure required fields are present
    if not data.get('name') or not data.get('email') or not data.get('phone'):
        return jsonify({"message": "Name, email, and phone are required."}), 400

    # Create a new contact
    new_contact = Contact(
        name=data['name'],
        email=data['email'],
        phone=data['phone']
    )

    db.session.add(new_contact)
    db.session.commit()

    return jsonify({
        'id': new_contact.id,
        'name': new_contact.name,
        'email': new_contact.email,
        'phone': new_contact.phone
    }), 201
