# CyberSOC Dashboard

CyberSOC Dashboard is an educational cybersecurity and networking platform that integrates multiple security administration tools into a unified console interface. This project is developed in stages and is intended for learning and portfolio purposes.

## Phase 1 Overview

Phase 1 establishes the core skeleton, routing blueprints, user database schemas, custom dark-theme styling, and responsive layout structure.

### Key Features
- **Role-Based Authentication**: Registration, secure hashed passwords, login session tracking, and automatic routing controls.
- **Default Seed User**: Pre-seeded user for easy initialization and portfolio review.
- **Enterprise Dark UI**: CSS variable-driven dark theme with custom responsive navbar, retractable sidebar, and clean typography.
- **Simulated Metrics Engine**: Chart.js lines representing real-time network threats.
- **Robust Error Handlers**: Custom styled error templates for 403, 404, and 500 status codes.

---

## Tech Stack

- **Backend**: Python 3, Flask, Flask-SQLAlchemy, Flask-Login
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript, Chart.js, Bootstrap Icons
- **Database**: SQLite3

---

## Folder Structure

```text
CyberSOC-Dashboard/
├── app.py
├── config.py
├── requirements.txt
├── .gitignore
├── README.md
├── database/            # Stores SQLite database files
├── models/              # SQLAlchemy model definitions
│   ├── db.py
│   └── user.py
├── routes/              # Flask Blueprints
│   ├── auth.py
│   ├── main.py
│   └── errors.py
├── static/              # Asset files (CSS, JS, Icons)
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
├── templates/           # HTML templates
│   ├── errors/
│   │   ├── 403.html
│   │   ├── 404.html
│   │   └── 500.html
│   ├── base.html
│   ├── landing.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
├── services/            # Extensible logic directories
├── uploads/             # Stores files uploaded by tools
├── reports/             # Generated security reports
└── logs/                # Application logs
```

---

## Default User Account

To ease manual verification and immediate review, the database is automatically seeded on the first startup with the following user:

- **Username**: `manager`
- **Password**: `Manager@123`
- **Role**: `SOC Manager`

---

## Quick Start & Installation

Follow these steps to run the application locally:

### 1. Prerequisites
Ensure you have **Python 3** installed on your system.

### 2. Setup Virtual Environment (Recommended)
```bash
# Create a virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

Access the dashboard at `http://127.0.0.1:5000`.
