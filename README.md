# 🧠 Smart Contact Manager (Python Flask)

A secure and lightweight **Smart Contact Manager** built using **Python Flask**, designed to replicate key features of **Spring Boot Security** such as authentication, role-based access control, and OAuth integration.  
This project demonstrates how Flask can be used to build a secure and modular web application similar to Java’s Spring Boot architecture.

---

## 📘 Project Overview

This web application allows users to register, log in, and manage their personal contacts securely.  
The system implements two access levels — **Admin** and **User**:
- **Users** can add, search, and delete only their own contacts.
- **Admins** can view, edit, delete all contacts and manage user privileges.

It features **Flask-based authentication**, **bcrypt password hashing**, **role-based access control**, **secure file handling**, and **OAuth login** via Google and GitHub.  
The frontend is styled with **Tailwind CSS** for a clean and responsive interface.

---

## ⚙️ Tech Stack

**Backend:** Python Flask  
**Database:** SQLite (easily upgradable to PostgreSQL/MySQL)  
**Frontend:** Tailwind CSS, Jinja2 Templates  
**Authentication:** Flask-Login, Flask-WTF, Flask-Bcrypt  
**OAuth:** Flask-Dance (Google and GitHub Login)  
**Environment Management:** python-dotenv  
**Version Control:** Git & GitHub  

---

## 🧩 Features

- 🔐 **User Authentication** – Secure login & registration system  
- 👥 **Role-Based Access Control (RBAC)** – Separate Admin/User privileges  
- 📋 **CRUD Operations** – Manage contacts with validation  
- 🖼️ **Secure File Uploads** – Only PNG uploads are allowed  
- 🌐 **OAuth Integration** – Google and GitHub login  
- 💻 **Responsive Design** – Built with TailwindCSS  
- 🧱 **Modular Architecture** – Clean separation between routes, models, and templates  

---

## 📁 Project Structure

smartcontactmanagerp/
│
├── app1.py # Main Flask app file
├── requirements.txt # Python dependencies
├── README.md # Project documentation
├── static/ # CSS, JS, images
├── templates/ # HTML templates (Jinja2)
│ ├── layout.html
│ ├── login.html
│ ├── register.html
│ ├── dashboard.html
│ ├── admin_dashboard.html
│ └── view_contact.html
├── instance/
│ └── smart_contact.db # SQLite database (auto-generated)
└── .gitignore # Files to exclude from repo


---

## 🚀 Getting Started

### 🧱 Prerequisites
Ensure you have **Python 3.10+** installed.

Install dependencies:
```bash
pip install -r requirements.txt
or
Here’s what you should include in your requirements.txt:

Flask==3.0.3
Flask-Login==0.6.3
Flask-WTF==1.2.1
Flask-Mail==0.9.1
Flask-Bcrypt==1.0.1
Flask-SQLAlchemy==3.1.1
email-validator==2.1.0.post1
Werkzeug==3.0.1
itsdangerous==2.2.0
Jinja2==3.1.4
WTForms==3.1.2
Flask-Dance==7.0.0
python-dotenv==1.0.1

. Start the app:
   ```bash
   python main.py
