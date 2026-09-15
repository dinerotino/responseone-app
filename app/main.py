from flask import Flask, request, jsonify
from datetime import datetime, timezone
import hashlib
import hmac
import os

import psycopg2
from dotenv import load_dotenv


# ============================================================
# Load environment variables
# ============================================================

load_dotenv()


app = Flask(__name__)


# ============================================================
# PostgreSQL connection
# ============================================================

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "responseone"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "")
    )


# ============================================================
# Ingestion authentication
# ============================================================

def is_ingestion_authenticated():
    configured_token = os.getenv("RESPONSEONE_INGEST_TOKEN", "")
    provided_token = request.headers.get("X-ResponseOne-Token", "")

    if not configured_token:
        return False

    return hmac.compare_digest(
        provided_token,
        configured_token
    )


# ============================================================
# Basic application routes
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "application": "ResponseOne Demo Application",
        "status": "running"
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy"
    })


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return jsonify({
        "query": query,
        "message": f"Search results for: {query}"
    })


@app.route("/api/user/<user_id>")
def get_user(user_id):
    return jsonify({
        "user_id": user_id,
        "username": "demo-user"
    })


# ============================================================
# Security Finding Ingestion
# ============================================================

@app.route("/api/findings", methods=["POST"])
def ingest_finding():

    # --------------------------------------------------------
    # Authenticate ingestion request
    # --------------------------------------------------------

    if not is_ingestion_authenticated():
        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Request body must contain JSON"
        }), 400

    scanner = data.get("scanner")
    severity = data.get("severity")
    title = data.get("title")

    if not scanner:
        return jsonify({
            "error": "scanner is required"
        }), 400

    if not severity:
        return jsonify({
            "error": "severity is required"
        }), 400

    if not title:
        return jsonify({
            "error": "title is required"
        }), 400

    vulnerability_type = data.get(
        "vulnerability_type",
        "Unknown"
    )

    description = data.get(
        "description",
        ""
    )

    cve = data.get("cve")

    cvss = data.get("cvss")

    # --------------------------------------------------------
    # Generate deterministic finding fingerprint
    # --------------------------------------------------------

    fingerprint_source = (
        f"{scanner}|"
        f"{severity}|"
        f"{title}|"
        f"{data.get('file', '')}|"
        f"{data.get('line', '')}"
    )

    finding_id = hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()

    now = datetime.now(timezone.utc)

    connection = None
    cursor = None

    try:

        # ----------------------------------------------------
        # Connect to PostgreSQL
        # ----------------------------------------------------

        connection = get_db_connection()
        cursor = connection.cursor()

        # ----------------------------------------------------
        # Check for duplicate finding
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT finding_id
            FROM findings
            WHERE finding_id = %s
            """,
            (finding_id,)
        )

        existing = cursor.fetchone()

        if existing:

            return jsonify({
                "message": "Duplicate finding",
                "finding_id": finding_id,
                "duplicate": True
            }), 200

        # ----------------------------------------------------
        # Insert new finding
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO findings (
                finding_id,
                scanner,
                severity,
                vulnerability_type,
                title,
                description,
                status,
                cve,
                cvss,
                detected_at,
                received_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                finding_id,
                scanner,
                severity.upper(),
                vulnerability_type,
                title,
                description,
                "OPEN",
                cve,
                cvss,
                now,
                now
            )
        )

        connection.commit()

        return jsonify({
            "message": "Security finding stored",
            "finding_id": finding_id,
            "scanner": scanner,
            "severity": severity.upper(),
            "status": "OPEN",
            "duplicate": False
        }), 201

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "error": "Failed to store security finding",
            "details": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# Run application
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
