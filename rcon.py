@main_bp.route('/contact/<int:id>', methods=['GET'])
def get_contact(id):
    contact = Contact.query.get(id)

    if not contact:
        return jsonify({"message": "Contact not found."}), 404

    return jsonify({
        'id': contact.id,
        'name': contact.name,
        'email': contact.email,
        'phone': contact.phone
    }), 200
