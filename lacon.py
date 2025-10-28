@main_bp.route('/contacts', methods=['GET'])
def get_all_contacts():
    contacts = Contact.query.all()
    contacts_list = [
        {'id': contact.id, 'name': contact.name, 'email': contact.email, 'phone': contact.phone}
        for contact in contacts
    ]
    
    return jsonify(contacts_list), 200
