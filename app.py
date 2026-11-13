from flask import (
    Flask,
    render_template,
    request,
    send_file,
    abort
)

from werkzeug.utils import secure_filename

import subprocess
import tempfile
import json
import sys
import os
import io
import sqlite3

from datetime import datetime


# =====================================
# APPLICATION CONFIGURATION
# =====================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "codeguard.db"
)


# =====================================
# DATABASE INITIALIZATION
# =====================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                total_issues INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                scanned_at TEXT,
                issues_json TEXT

            )
        """)

        conn.commit()

    finally:
        conn.close()


# =====================================
# SAVE SCAN HISTORY
# =====================================

def save_scan_history(filename, results, counts):

    conn = sqlite3.connect(DATABASE)

    try:

        total = sum(counts.values())

        scanned_at = datetime.now().astimezone().strftime(
            "%d-%m-%Y %H:%M:%S"
        )

        conn.execute("""
            INSERT INTO scan_history (
                filename,
                total_issues,
                high_count,
                medium_count,
                low_count,
                scanned_at,
                issues_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            total,
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
            scanned_at,
            json.dumps(results)
        ))

        conn.commit()

    finally:
        conn.close()


# =====================================
# BANDIT SECURITY SCANNER
# =====================================

def scan_code(code):

    file_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as temp:

            temp.write(code)
            file_path = temp.name

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                "-q",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        report = json.loads(result.stdout or "{}")

        return report.get("results", [])

    finally:

        if file_path and os.path.exists(file_path):
            os.remove(file_path)


# =====================================
# CALCULATE SEVERITY
# =====================================

def calculate_counts(results):

    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for issue in results:

        severity = issue.get(
            "issue_severity", ""
        ).upper()

        if severity in counts:
            counts[severity] += 1

    return counts


# =====================================
# SECURITY RECOMMENDATION ENGINE
# =====================================

def build_recommendations(results):

    recommendation_database = {

        "B307": {
            "title": "Avoid using eval()",
            "why": (
                "The eval() function evaluates strings as Python "
                "expressions. Using it with untrusted input can "
                "allow unwanted code execution."
            ),
            "fix": (
                "Avoid eval() for user input. Use ast.literal_eval() "
                "when you only need to process Python literal data. "
                "For numbers, consider int() or float()."
            ),
            "example": (
                "import ast\n\n"
                "user_input = \"[10, 20, 30]\"\n"
                "result = ast.literal_eval(user_input)\n\n"
                "print(result)"
            ),
            "note": (
                "ast.literal_eval() supports literal data structures, "
                "not arbitrary expressions such as 10 + 20."
            )
        },

        "B602": {
            "title": "Avoid unsafe shell execution",
            "why": (
                "Using subprocess with shell=True can expose an "
                "application to command injection when untrusted "
                "data is included in a command."
            ),
            "fix": (
                "Prefer subprocess.run() with a list of arguments "
                "and shell=False. Validate all user-controlled values."
            ),
            "example": (
                "import subprocess\n\n"
                "subprocess.run(\n"
                "    [\"your-program\", \"validated-argument\"],\n"
                "    check=True,\n"
                "    shell=False\n"
                ")"
            ),
            "note": (
                "The executable and arguments must still be "
                "validated for the intended operation."
            )
        },

        "B301": {
            "title": "Avoid untrusted pickle data",
            "why": (
                "Loading untrusted data using pickle can execute "
                "malicious Python code during deserialization."
            ),
            "fix": (
                "Do not load pickle files received from untrusted "
                "sources. Use JSON for simple data structures."
            ),
            "example": (
                "import json\n\n"
                "data = '{\"name\": \"John\", \"age\": 21}'\n"
                "result = json.loads(data)\n\n"
                "print(result)"
            ),
            "note": (
                "JSON supports common data types but not every "
                "Python object."
            )
        },

        "B403": {
            "title": "Review pickle usage",
            "why": (
                "Importing pickle is not automatically dangerous, "
                "but loading untrusted pickle data can execute "
                "malicious code."
            ),
            "fix": (
                "Avoid deserializing untrusted pickle files. "
                "Consider JSON for simple data exchange."
            ),
            "example": (
                "import json\n\n"
                "data = '{\"status\": \"success\"}'\n"
                "result = json.loads(data)"
            ),
            "note": (
                "Review where pickle is used before deciding "
                "whether it can safely be removed."
            )
        },

        "B105": {
            "title": "Avoid hardcoded passwords",
            "why": (
                "Hardcoded passwords or credentials inside source "
                "code can be exposed when code is shared, uploaded "
                "or committed to version control."
            ),
            "fix": (
                "Move application secrets into environment variables "
                "or a suitable secret manager. Rotate exposed secrets."
            ),
            "example": (
                "import os\n\n"
                "password = os.environ.get(\"APP_PASSWORD\")"
            ),
            "note": (
                "Environment variables are for application secrets. "
                "User passwords should be stored using a suitable "
                "password-hashing algorithm."
            )
        },

        "B324": {
            "title": "Use a stronger hash algorithm",
            "why": (
                "The detected hash algorithm may be weak for "
                "security-sensitive integrity or collision-resistance "
                "requirements."
            ),
            "fix": (
                "For general-purpose file integrity checks, consider "
                "SHA-256. For user passwords, use a dedicated "
                "password-hashing algorithm such as Argon2id, bcrypt "
                "or PBKDF2."
            ),
            "example": (
                "import hashlib\n\n"
                "data = b\"example data\"\n"
                "digest = hashlib.sha256(data).hexdigest()\n\n"
                "print(digest)"
            ),
            "note": (
                "SHA-256 is not a password-storage replacement. "
                "Use dedicated password hashing for passwords."
            )
        },

        "B608": {
            "title": "Prevent SQL injection",
            "why": (
                "Building SQL statements using string formatting "
                "or concatenation can allow malicious input "
                "to change the intended database query."
            ),
            "fix": (
                "Use parameterized SQL queries instead of joining "
                "user input directly into SQL statements."
            ),
            "example": (
                "cursor.execute(\n"
                "    \"SELECT * FROM users WHERE name = ?\",\n"
                "    (username,)\n"
                ")"
            ),
            "note": (
                "Use the parameter placeholder style supported "
                "by your database driver."
            )
        },

        "B101": {
            "title": "Avoid assert for security checks",
            "why": (
                "Python assertions can be disabled when running "
                "Python with optimization. Therefore, they should "
                "not be used for essential security checks."
            ),
            "fix": (
                "Use explicit if statements and raise appropriate "
                "exceptions for important validation."
            ),
            "example": (
                "if not user_is_authorized:\n"
                "    raise PermissionError(\"Access denied\")"
            ),
            "note": (
                "Assertions are useful for debugging, but not "
                "for enforcing access control."
            )
        }

    }

    recommendations = []

    for issue in results:

        test_id = issue.get("test_id", "")

        recommendation = recommendation_database.get(
            test_id,
            {
                "title": "Review this security finding",

                "why": (
                    issue.get("issue_text", "")
                ),

                "fix": (
                    "Review the detected code and Bandit "
                    "documentation. Determine whether the "
                    "finding is applicable and follow secure "
                    "programming practices."
                ),

                "example": (
                    "No automatic code example is available "
                    "for this finding."
                ),

                "note": (
                    "This recommendation is general guidance. "
                    "Review the actual code before applying a fix."
                )
            }
        )

        item = dict(issue)

        item.update(recommendation)

        recommendations.append(item)

    return recommendations


# =====================================
# HOME PAGE AND SCANNER
# =====================================

@app.route("/", methods=["GET", "POST"])
def home():

    results = None
    recommendations = []
    error = None
    code = ""

    filename = "Pasted code"

    history_saved = False
    scan_ran = False

    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    if request.method == "POST":

        uploaded_file = request.files.get("code_file")

        code = request.form.get("code", "")

        if uploaded_file and uploaded_file.filename:

            if not uploaded_file.filename.lower().endswith(".py"):

                error = "Please upload a Python (.py) file."

            else:

                filename = secure_filename(
                    uploaded_file.filename
                )

                file_content = uploaded_file.read()

                if not file_content:

                    error = "Uploaded file is empty."

                else:

                    code = file_content.decode(
                        "utf-8",
                        errors="replace"
                    )

        if not error:

            if not code.strip():

                error = (
                    "Please enter code or upload a Python file."
                )

            else:

                try:

                    results = scan_code(code)

                    counts = calculate_counts(results)

                    recommendations = build_recommendations(
                        results
                    )

                    scan_ran = True

                    try:

                        save_scan_history(
                            filename,
                            results,
                            counts
                        )

                        history_saved = True

                    except sqlite3.Error as db_error:

                        error = (
                            "Scan completed, but history could "
                            f"not be saved: {db_error}"
                        )

                except subprocess.TimeoutExpired:

                    error = "Scanning timed out."

                except FileNotFoundError:

                    error = (
                        "Bandit is not installed. "
                        "Run pip install bandit."
                    )

                except Exception as e:

                    error = f"Scanning failed: {str(e)}"

    return render_template(
        "index.html",
        results=results,
        recommendations=recommendations,
        error=error,
        code=code,
        counts=counts,
        scan_ran=scan_ran,
        history_saved=history_saved
    )


# =====================================
# SCAN HISTORY PAGE
# =====================================

@app.route("/history")
def scan_history():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    try:

        scans = conn.execute("""
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    finally:

        conn.close()

    return render_template(
        "history.html",
        scans=scans
    )


# =====================================
# INDIVIDUAL SCAN DETAILS
# =====================================

@app.route("/history/<int:scan_id>")
def scan_details(scan_id):

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    try:

        scan = conn.execute("""
            SELECT *
            FROM scan_history
            WHERE id = ?
        """, (scan_id,)).fetchone()

    finally:

        conn.close()

    if scan is None:

        abort(404)

    issues = json.loads(
        scan["issues_json"] or "[]"
    )

    recommendations = build_recommendations(issues)

    return render_template(
        "history_detail.html",
        scan=scan,
        issues=issues,
        recommendations=recommendations
    )


# =====================================
# DOWNLOAD SECURITY REPORT
# =====================================

@app.route("/download-report", methods=["POST"])
def download_report():

    code = request.form.get("code", "")

    if not code.strip():

        return "No scan data available.", 400

    try:

        results = scan_code(code)

        counts = calculate_counts(results)

        recommendations = build_recommendations(results)
        print("DEBUG - Vulnerabilities:", len(results))
        print("DEBUG - Recommendations:", len(recommendations))

        report = []

        report.append("===================================")
        report.append("       CODEGUARD SECURITY REPORT")
        report.append("===================================")

        report.append(
            f"\nGenerated: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
        )

        report.append("\n------ SCAN SUMMARY ------")

        report.append(
            f"Total Vulnerabilities: {sum(counts.values())}"
        )

        report.append(f"High Severity: {counts['HIGH']}")

        report.append(f"Medium Severity: {counts['MEDIUM']}")

        report.append(f"Low Severity: {counts['LOW']}")

        report.append("\n------ DETECTED ISSUES AND RECOMMENDATIONS ------")

        if recommendations:

            for number, item in enumerate(
                recommendations,
                start=1
            ):

                report.append(f"\nIssue {number}")

                report.append(
                    f"ID: {item.get('test_id', 'N/A')}"
                )

                report.append(
                    f"Description: {item.get('issue_text', 'N/A')}"
                )

                report.append(
                    f"Severity: {item.get('issue_severity', 'N/A')}"
                )

                report.append(
                    f"Line Number: {item.get('line_number', 'N/A')}"
                )

                report.append(
                    f"Recommendation: {item['title']}"
                )

                report.append(
                    f"Why: {item['why']}"
                )

                report.append(
                    f"How to fix: {item['fix']}"
                )

                report.append(
                    f"Example:\n{item['example']}"
                )

                report.append(
                    f"Note: {item['note']}"
                )

        else:

            report.append("No security issues detected.")

        report.append("\n===================================")
        report.append("            END OF REPORT")
        report.append("===================================")

        report.append(
            "\nNote: Automated findings should be reviewed by a developer."
        )

        report_text = "\n".join(report)

        file_data = io.BytesIO(
            report_text.encode("utf-8")
        )

        file_data.seek(0)

        return send_file(
            file_data,
            as_attachment=True,
            download_name="CodeGuard_Security_Report.txt",
            mimetype="text/plain"
        )

    except subprocess.TimeoutExpired:

        return "Report generation timed out.", 500

    except Exception as e:

        return f"Report generation failed: {str(e)}", 500
# =====================================
# DASHBOARD ANALYTICS
# =====================================

@app.route("/analytics")
def analytics():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        # Calculate overall statistics
        summary = conn.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(total_issues), 0) AS total_vulnerabilities,
                COALESCE(SUM(high_count), 0) AS high_count,
                COALESCE(SUM(medium_count), 0) AS medium_count,
                COALESCE(SUM(low_count), 0) AS low_count,
                COALESCE(AVG(total_issues), 0) AS average_issues
            FROM scan_history
        """).fetchone()

        # Get five recent scans
        recent_scans = conn.execute("""
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT 5
        """).fetchall()

    finally:

        conn.close()

    # Calculate severity percentages
    total = summary["total_vulnerabilities"]

    high_pct = round(
        summary["high_count"] / total * 100, 1
    ) if total else 0

    medium_pct = round(
        summary["medium_count"] / total * 100, 1
    ) if total else 0

    low_pct = round(
        summary["low_count"] / total * 100, 1
    ) if total else 0

    return render_template(
        "analytics.html",
        summary=summary,
        recent_scans=recent_scans,
        high_pct=high_pct,
        medium_pct=medium_pct,
        low_pct=low_pct
    )

# =====================================
# FILE SIZE ERROR
# =====================================

@app.errorhandler(413)
def file_too_large(error):

    return (
        "File is too large. Maximum allowed size is 2 MB.",
        413
    )


# =====================================
# INITIALIZE DATABASE
# =====================================

init_db()


# =====================================
# RUN APPLICATION
# =====================================

if __name__ == "__main__":

    app.run(debug=True)