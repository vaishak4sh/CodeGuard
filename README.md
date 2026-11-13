# 🛡️ CodeGuard – Python Code Security Analyzer

CodeGuard is a web-based Python security analyzer developed using Flask and Bandit. It scans Python code to identify potential security vulnerabilities and provides recommendations to improve code safety.

## 🚀 Features

- **Code Scanning:** Scan Python code by pasting it into the application.
- **File Upload:** Upload `.py` files for security analysis.
- **Vulnerability Detection:** Identify potentially unsafe coding practices using Bandit.
- **Severity Classification:** Categorize vulnerabilities as High, Medium, and Low.
- **Security Recommendations:** Display explanations and suggestions to improve code security.
- **Scan History:** Store and view previous scan results.
- **Analytics Dashboard:** View security scan statistics.
- **PDF Reports:** Download security analysis reports in PDF format.

## 🛠️ Technologies Used

- Python
- Flask
- Bandit
- SQLite
- HTML
- CSS
- JavaScript
- ReportLab

## 📂 Project Structure

```text
CodeGuard/
│
├── app.py
├── safe_test.py
├── test_security.py
├── vulnerable_test.py
│
├── templates/
│   ├── analytics.html
│   ├── history.html
│   ├── history_detail.html
│   └── index.html
│
├── .gitignore
└── README.md
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/vaishak4sh/CodeGuard.git
```

### 2. Open the project folder

```bash
cd CodeGuard
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

Windows:

```bash
venv\Scripts\activate
```

### 5. Install required packages

```bash
pip install Flask bandit reportlab
```

### 6. Run the application

```bash
python app.py
```

### 7. Open in your browser

```text
http://127.0.0.1:5000
```

## 🔍 How CodeGuard Works

1. The user enters Python code or uploads a Python file.
2. Flask receives the submitted code.
3. Bandit analyzes the code for potential security issues.
4. CodeGuard displays detected vulnerabilities.
5. Vulnerabilities are classified according to severity.
6. Security recommendations help users improve their code.
7. Scan history and analytics help track previous scans.
8. Users can download PDF security reports.

## 🎯 Project Objective

The main objective of CodeGuard is to help Python developers identify potential security vulnerabilities and understand safer coding practices.

## 🔮 Future Enhancements

- Support for additional programming languages.
- More advanced security analysis.
- Improved vulnerability detection.
- User authentication and personalized dashboards.
- Integration with development environments.

## ⚠️ Disclaimer

CodeGuard uses Bandit for static analysis. It identifies certain potentially insecure coding patterns but cannot detect every possible security vulnerability. Results should be reviewed by developers.

## 👨‍💻 Project

**Project Name:** CodeGuard – Python Code Security Analyzer

**Developed as:** Engineering Mini Project