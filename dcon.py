@main_bp.route('/contact/<int:id>', methods=['DELETE'])
def delete_contact(id):
    contact = Contact.query.get(id)

    if not contact:
        return jsonify({"message": "Contact not found."}), 404

    db.session.delete(contact)
    db.session.commit()

    return jsonify({"message": "Contact deleted successfully."}), 200
