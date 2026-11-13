"""CodeGuard - Python Code Security Analyzer Web Application."""

import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Generator, List
from xml.sax.saxutils import escape

from flask import (
    Flask,
    abort,
    render_template,
    request,
    send_file,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.utils import secure_filename

# =====================================================================
# APPLICATION CONFIGURATION
# =====================================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB limit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "codeguard.db")

# =====================================================================
# SECURITY RECOMMENDATION CATALOG
# =====================================================================

RECOMMENDATION_CATALOG: Dict[str, Dict[str, str]] = {
    "B307": {
        "title": "Avoid using eval()",
        "why": (
            "The eval() function evaluates strings as Python expressions. "
            "Using it with untrusted input can allow unwanted code execution."
        ),
        "fix": (
            "Avoid eval() for user input. Use ast.literal_eval() when you only need "
            "to process Python literal data. For numbers, consider int() or float()."
        ),
        "example": (
            "import ast\n\n"
            'user_input = "[10, 20, 30]"\n'
            "result = ast.literal_eval(user_input)\n\n"
            "print(result)"
        ),
        "note": (
            "ast.literal_eval() supports literal data structures, not arbitrary expressions such as 10 + 20."
        ),
    },
    "B602": {
        "title": "Avoid unsafe shell execution",
        "why": (
            "Using subprocess with shell=True can expose an application to command "
            "injection when untrusted data is included in a command."
        ),
        "fix": (
            "Prefer subprocess.run() with a list of arguments and shell=False. "
            "Validate all user-controlled values."
        ),
        "example": (
            "import subprocess\n\n"
            "subprocess.run(\n"
            '    ["your-program", "validated-argument"],\n'
            "    check=True,\n"
            "    shell=False\n"
            ")"
        ),
        "note": "The executable and arguments must still be validated for the intended operation.",
    },
    "B301": {
        "title": "Avoid untrusted pickle data",
        "why": (
            "Loading untrusted data using pickle can execute malicious Python code "
            "during deserialization."
        ),
        "fix": "Do not load pickle files received from untrusted sources. Use JSON for simple data structures.",
        "example": (
            "import json\n\n"
            'data = \'{"name": "John", "age": 21}\'\n'
            "result = json.loads(data)\n\n"
            "print(result)"
        ),
        "note": "JSON supports common data types but not every Python object.",
    },
    "B403": {
        "title": "Review pickle usage",
        "why": (
            "Importing pickle is not automatically dangerous, but loading untrusted "
            "pickle data can execute malicious code."
        ),
        "fix": "Avoid deserializing untrusted pickle files. Consider JSON for simple data exchange.",
        "example": (
            "import json\n\n"
            'data = \'{"status": "success"}\'\n'
            "result = json.loads(data)"
        ),
        "note": "Review where pickle is used before deciding whether it can safely be removed.",
    },
    "B105": {
        "title": "Avoid hardcoded passwords",
        "why": (
            "Hardcoded passwords or credentials inside source code can be exposed "
            "when code is shared, uploaded or committed to version control."
        ),
        "fix": (
            "Move application secrets into environment variables or a suitable secret "
            "manager. Rotate exposed secrets."
        ),
        "example": (
            "import os\n\n"
            'password = os.environ.get("APP_PASSWORD")'
        ),
        "note": (
            "Environment variables are for application secrets. User passwords should "
            "be stored using a suitable password-hashing algorithm."
        ),
    },
    "B324": {
        "title": "Use a stronger hash algorithm",
        "why": (
            "The detected hash algorithm may be weak for security-sensitive "
            "integrity or collision-resistance requirements."
        ),
        "fix": (
            "For general-purpose file integrity checks, consider SHA-256. For user passwords, "
            "use a dedicated password-hashing algorithm such as Argon2id, bcrypt or PBKDF2."
        ),
        "example": (
            "import hashlib\n\n"
            'data = b"example data"\n'
            "digest = hashlib.sha256(data).hexdigest()\n\n"
            "print(digest)"
        ),
        "note": "SHA-256 is not a password-storage replacement. Use dedicated password hashing for passwords.",
    },
    "B608": {
        "title": "Prevent SQL injection",
        "why": (
            "Building SQL statements using string formatting or concatenation can allow "
            "malicious input to change the intended database query."
        ),
        "fix": "Use parameterized SQL queries instead of joining user input directly into SQL statements.",
        "example": (
            'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))'
        ),
        "note": "Use the parameter placeholder style supported by your database driver.",
    },
    "B101": {
        "title": "Avoid assert for security checks",
        "why": (
            "Python assertions can be disabled when running Python with optimization. "
            "Therefore, they should not be used for essential security checks."
        ),
        "fix": "Use explicit if statements and raise appropriate exceptions for important validation.",
        "example": (
            "if not user_is_authorized:\n"
            '    raise PermissionError("Access denied")'
        ),
        "note": "Assertions are useful for debugging, but not for enforcing access control.",
    },
}

# =====================================================================
# DATABASE MANAGEMENT
# =====================================================================

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Provide a transactional database connection scope with row access."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create scan history table if not present."""
    with get_db() as conn:
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


def save_scan_history(
    filename: str,
    results: List[Dict[str, Any]],
    counts: Dict[str, int]
) -> None:
    """Persist scan summary and findings into the database."""
    scanned_at = datetime.now().astimezone().strftime("%d-%m-%Y %H:%M:%S")
    total = sum(counts.values())

    with get_db() as conn:
        conn.execute("""
            INSERT INTO scan_history (
                filename, total_issues, high_count, medium_count, low_count, scanned_at, issues_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            total,
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            scanned_at,
            json.dumps(results)
        ))

# =====================================================================
# BANDIT SCANNER & RECOMMENDATION SERVICES
# =====================================================================

def scan_code(code: str) -> List[Dict[str, Any]]:
    """Scan Python source code string with Bandit security scanner."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", temp_path],
            capture_output=True,
            text=True,
            timeout=20
        )

        # Bandit exit code: 0 = clean, 1 = issues found, others = error
        if result.returncode not in (0, 1):
            if "No module named bandit" in result.stderr:
                raise RuntimeError("Bandit is not installed. Run 'pip install bandit'.")
            if result.stderr.strip():
                raise RuntimeError(f"Bandit scan error: {result.stderr.strip()}")

        report = json.loads(result.stdout or "{}")
        return report.get("results", [])

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def calculate_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in results:
        severity = issue.get("issue_severity", "").upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def build_recommendations(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich Bandit findings with remediation guidelines."""
    recommendations = []
    for issue in results:
        test_id = issue.get("test_id", "")
        recommendation = RECOMMENDATION_CATALOG.get(
            test_id,
            {
                "title": "Review this security finding",
                "why": issue.get("issue_text", ""),
                "fix": (
                    "Review the detected code and Bandit documentation. "
                    "Determine whether the finding is applicable and follow secure programming practices."
                ),
                "example": "No automatic code example is available for this finding.",
                "note": "This recommendation is general guidance. Review actual code before applying a fix.",
            }
        )
        item = dict(issue)
        item.update(recommendation)
        recommendations.append(item)

    return recommendations

# =====================================================================
# PDF REPORT GENERATOR
# =====================================================================

def generate_pdf_report(
    counts: Dict[str, int],
    recommendations: List[Dict[str, Any]]
) -> io.BytesIO:
    """Generate in-memory PDF security analysis report using ReportLab."""
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.darkblue,
        spaceAfter=15
    )
    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        textColor=colors.darkblue,
        spaceBefore=15,
        spaceAfter=10
    )
    body_style = styles["BodyText"]

    story = [
        Paragraph("CODEGUARD SECURITY REPORT", title_style),
        Spacer(1, 10),
        Paragraph("Python Code Security Analysis", body_style),
        Spacer(1, 15),
        Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", body_style),
        Spacer(1, 20),
        Paragraph("1. SCAN SUMMARY", heading_style),
    ]

    summary_data = [
        ["Security Metric", "Result"],
        ["Total Vulnerabilities", str(sum(counts.values()))],
        ["High Severity", str(counts["HIGH"])],
        ["Medium Severity", str(counts["MEDIUM"])],
        ["Low Severity", str(counts["LOW"])],
    ]

    summary_table = Table(summary_data, colWidths=[260, 180])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("2. DETECTED VULNERABILITIES", heading_style))

    if recommendations:
        for index, item in enumerate(recommendations, start=1):
            story.append(Paragraph(f"Issue {index}", styles["Heading3"]))

            fields = [
                ("ID", item.get("test_id")),
                ("Description", item.get("issue_text")),
                ("Severity", item.get("issue_severity")),
                ("Line Number", item.get("line_number")),
                ("Recommendation", item.get("title")),
                ("Why", item.get("why")),
                ("How to Fix", item.get("fix")),
                ("Example", item.get("example")),
                ("Note", item.get("note")),
            ]

            for label, value in fields:
                safe_val = escape(str(value if value is not None else "N/A")).replace("\n", "<br/>")
                story.append(Paragraph(f"<b>{label}:</b> {safe_val}", body_style))
                story.append(Spacer(1, 6))

            story.append(Spacer(1, 15))
    else:
        story.append(Paragraph("No security issues detected!", body_style))

    story.extend([
        Spacer(1, 20),
        Paragraph("<b>Important:</b> Automated security findings should always be reviewed by a developer.", body_style),
        Spacer(1, 15),
        Paragraph("CodeGuard - Python Code Security Analyzer", body_style),
    ])

    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer

# =====================================================================
# ROUTE HANDLERS
# =====================================================================

@app.route("/", methods=["GET", "POST"])
def home():
    results = None
    recommendations = []
    error = None
    code = ""
    filename = "Pasted code"
    history_saved = False
    scan_ran = False
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if request.method == "POST":
        uploaded_file = request.files.get("code_file")
        code = request.form.get("code", "")

        if uploaded_file and uploaded_file.filename:
            if not uploaded_file.filename.lower().endswith(".py"):
                error = "Please upload a Python (.py) file."
            else:
                filename = secure_filename(uploaded_file.filename)
                file_content = uploaded_file.read()
                if not file_content:
                    error = "Uploaded file is empty."
                else:
                    code = file_content.decode("utf-8", errors="replace")

        if not error:
            if not code.strip():
                error = "Please enter code or upload a Python file."
            else:
                try:
                    results = scan_code(code)
                    counts = calculate_counts(results)
                    recommendations = build_recommendations(results)
                    scan_ran = True

                    try:
                        save_scan_history(filename, results, counts)
                        history_saved = True
                    except sqlite3.Error as db_error:
                        error = f"Scan completed, but history could not be saved: {db_error}"

                except subprocess.TimeoutExpired:
                    error = "Scanning timed out."
                except RuntimeError as re:
                    error = str(re)
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


@app.route("/history")
def scan_history():
    with get_db() as conn:
        scans = conn.execute("""
            SELECT * FROM scan_history ORDER BY id DESC LIMIT 100
        """).fetchall()

    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>")
def scan_details(scan_id: int):
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
        ).fetchone()

    if scan is None:
        abort(404)

    issues = json.loads(scan["issues_json"] or "[]")
    recommendations = build_recommendations(issues)

    return render_template(
        "history_detail.html",
        scan=scan,
        issues=issues,
        recommendations=recommendations
    )


@app.route("/download-report", methods=["POST"])
def download_report():
    code = request.form.get("code", "")
    if not code.strip():
        return "No scan data available.", 400

    try:
        results = scan_code(code)
        counts = calculate_counts(results)
        recommendations = build_recommendations(results)
        pdf_file = generate_pdf_report(counts, recommendations)

        return send_file(
            pdf_file,
            as_attachment=True,
            download_name="CodeGuard_Security_Report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        app.logger.error("PDF Generation Error: %s", e)
        return f"Report generation failed: {str(e)}", 500


@app.route("/analytics")
def analytics():
    with get_db() as conn:
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

        recent_scans = conn.execute("""
            SELECT * FROM scan_history ORDER BY id DESC LIMIT 5
        """).fetchall()

    total = summary["total_vulnerabilities"]
    high_pct = round(summary["high_count"] / total * 100, 1) if total else 0.0
    medium_pct = round(summary["medium_count"] / total * 100, 1) if total else 0.0
    low_pct = round(summary["low_count"] / total * 100, 1) if total else 0.0

    return render_template(
        "analytics.html",
        summary=summary,
        recent_scans=recent_scans,
        high_pct=high_pct,
        medium_pct=medium_pct,
        low_pct=low_pct
    )


@app.errorhandler(413)
def file_too_large(error):
    return "File is too large. Maximum allowed size is 2 MB.", 413


# =====================================================================
# APPLICATION ENTRYPOINT
# =====================================================================

init_db()

if __name__ == "__main__":
    app.run(debug=True)