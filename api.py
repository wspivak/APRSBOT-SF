#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
APRS Store-Forward API
- Presents deduped logs, users, blacklist, health, JSON dashboard, and HTML dashboard
- Robust to mixed schemas: uses COALESCE(retry_count, retries, 0) everywhere
- Times shown in America/New_York on the HTML dashboard
"""

from flask import Flask, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import re
from datetime import datetime, timedelta
from pytz import timezone, utc
from collections import defaultdict
import configparser
import os

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

APRS_CONF = os.environ.get("APRSBOT_CONF", "/opt/aprsbot/aprsbot.conf")

# Main ERLI bot DB (audit_log, users, blacklist, etc.)
DB_FILE = "/opt/aprsbot/erli.db"
# Timezone for display
ET_ZONE = timezone("America/New_York")

_cfg = configparser.ConfigParser()
_cfg.read(APRS_CONF)
STORE_DB = _cfg.get("store_forward", "store_db", fallback="/opt/aprsbot/store_forward.db")

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def clean_message(raw_msg: str):
    """
    Normalize incoming text for deduping:
    - drop telemetry/ACK/position formats
    - drop leading "<CALL>" or "ERLI :" style prefixes
    - extract proword (netmsg|netmrg|msg|mrg|cq) and body
    - strip trailing {ID} (even malformed)
    """
    if not raw_msg:
        return None
    msg = raw_msg.strip()
    if not msg:
        return None

    # Skip telemetry/ACKs/position junk quickly
    if msg[0] in ("@", "!", "=", "/", "_", ";", "`", ":"):
        return None
    if re.match(r"^T#\d+", msg):
        return None
    if re.match(r"^ack\d+\}?$", msg, re.IGNORECASE):
        return None

    # Remove call aliases like <KC2NJV-7> or prefaces like ERLI :
    msg = re.sub(r"^<[^>]{3,10}>\s*", "", msg)
    msg = re.sub(r"^[A-Z0-9\-]{3,9}\s*:\s*", "", msg)

    # Proword and body
    m = re.match(r"^(netmsg|netmrg|msg|mrg|cq)\b\s+(.*)", msg, re.IGNORECASE)
    if not m:
        return None

    proword = m.group(1).lower()
    body = (m.group(2) or "").strip()
    if not body:
        return None

    # Strip trailing {xxx}, even malformed like {97 or {77}
    body = re.sub(r"\s*\{[^\s{}]{1,6}\}?\s*$", "", body).strip()
    if not body:
        return None

    return f"CQ {body}" if proword == "cq" else body


def _rows_to_dicts(cur):
    """Convert sqlite rows to dicts (named columns)."""
    colnames = [d[0] for d in cur.description]
    for row in cur.fetchall():
        yield {col: row[idx] for idx, col in enumerate(colnames)}


def _connect(db_path):
    # Note: check_same_thread=False so gunicorn/uwsgi threads can read safely
    return sqlite3.connect(db_path, check_same_thread=False)


# -----------------------------------------------------------------------------
# Data access
# -----------------------------------------------------------------------------
def fetch_audit_rows():
    q = """
        SELECT
            STRFTIME('%Y-%m-%d %H:%M:%S', timestamp) AS ts_utc,
            direction,
            source,
            destination,
            message,
            msgid,
            transport
        FROM audit_log
        WHERE timestamp >= datetime('now', 'utc', '-7 days')
          AND COALESCE(rejected, 0) = 0
        ORDER BY timestamp ASC
    """
    with _connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute(q)
        return cur.fetchall()


def get_known_users():
    with _connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT callsign FROM users")
        return {r[0] for r in cur.fetchall()}


def deduplicate(rows):
    """
    Dedup messages (by (source, trimmed_msg)) in 3-minute buckets,
    skipping CQ messages from unknown users. Result newest-first (ET).
    """
    known_users = get_known_users()
    grouped = defaultdict(list)

    for ts_utc, direction, source, dest, raw_msg, msgid, transport in rows:
        trimmed = clean_message(raw_msg)
        if not trimmed:
            continue

        if trimmed.startswith("CQ ") and source not in known_users:
            app.logger.info(f"Skipping CQ from unknown user: {source}")
            continue

        grouped[(source, trimmed)].append(
            {
                "timestamp_utc": ts_utc,
                "source": source,
                "destination": dest,
                "transport": transport,
                "trimmed_message": trimmed,
            }
        )

    deduped = []
    for (source, trimmed), msgs in grouped.items():
        msgs.sort(key=lambda x: x["timestamp_utc"])
        bucket = None
        destinations = set()

        for msg in msgs:
            msg_time = datetime.strptime(msg["timestamp_utc"], "%Y-%m-%d %H:%M:%S")
            if bucket is None:
                bucket = msg.copy()
                bucket_time = msg_time
                destinations = {msg["destination"]}
            elif msg_time - bucket_time <= timedelta(minutes=3):
                destinations.add(msg["destination"])
            else:
                utc_dt = utc.localize(bucket_time)
                et_dt = utc_dt.astimezone(ET_ZONE)
                deduped.append(
                    {
                        "timestamp": et_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "source": bucket["source"],
                        "transport": bucket["transport"],
                        "trimmed_message": bucket["trimmed_message"],
                        "destinations": " | ".join(sorted(destinations)),
                    }
                )
                bucket = msg.copy()
                bucket_time = msg_time
                destinations = {msg["destination"]}

        if bucket:
            utc_dt = utc.localize(bucket_time)
            et_dt = utc_dt.astimezone(ET_ZONE)
            deduped.append(
                {
                    "timestamp": et_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "source": bucket["source"],
                    "transport": bucket["transport"],
                    "trimmed_message": bucket["trimmed_message"],
                    "destinations": " | ".join(sorted(destinations)),
                }
            )

    return sorted(deduped, key=lambda x: x["timestamp"], reverse=True)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/logs")
def get_logs():
    try:
        rows = fetch_audit_rows()
        logs = deduplicate(rows)
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /logs: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/users")
def get_users():
    try:
        with _connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT callsign,
                       timestamp,
                       COALESCE(SF, 1) AS SF
                FROM users
                ORDER BY timestamp DESC
                """
            )
            users = [
                {"callsign": r[0], "timestamp": r[1], "sf": bool(r[2])}
                for r in cur.fetchall()
            ]
        return jsonify({"users": users})
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /users: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/blist")
def get_blacklist():
    try:
        with _connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT callsign, timestamp FROM blacklist ORDER BY timestamp DESC"
            )
            users = [{"callsign": r[0], "timestamp": r[1]} for r in cur.fetchall()]
        return jsonify({"users": users})
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /blist: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/health")
def health_check():
    return jsonify({"status": "ok"}), 200


@app.route("/dashboard")
def get_dashboard_json():
    """
    Compact JSON dashboard: per-recipient pending counts and retry stats.
    Uses COALESCE(retry_count, retries, 0).
    """
    try:
        with _connect(STORE_DB) as conn:
            cur = conn.cursor()

            # last_heard
            cur.execute("SELECT callsign, timestamp FROM last_heard")
            last_heard = {r[0].upper(): r[1] for r in cur.fetchall()}

            # pending
            cur.execute(
                """
                SELECT recipient,
                       msgid,
                       last_sent,
                       COALESCE(retry_count, retries, 0) AS retries_canon
                FROM message
                WHERE ack = 0 AND msgid IS NOT NULL AND msgid != ''
                """
            )
            rows = cur.fetchall()

        pending = {}
        for recipient, msgid, last_sent, retries_canon in rows:
            key = (recipient or "").upper()
            pending.setdefault(key, []).append(
                {
                    "msgid": msgid,
                    "last_sent": last_sent,
                    "retry_count": retries_canon,
                }
            )

        dashboard = []
        now_utc = datetime.utcnow()

        for recipient in sorted(pending.keys()):
            # last heard age
            heard_iso = last_heard.get(recipient)
            heard_age = "never"
            if heard_iso:
                try:
                    dt = datetime.fromisoformat(heard_iso)
                    delta = now_utc - dt
                    heard_age = f"{int(delta.total_seconds() / 60)} min ago"
                except Exception:
                    heard_age = "invalid"

            last_sent_iso = pending[recipient][-1]["last_sent"]
            sent_age = "never"
            if last_sent_iso:
                try:
                    dt = datetime.fromisoformat(last_sent_iso)
                    delta = now_utc - dt
                    sent_age = f"{int(delta.total_seconds() / 60)} min ago"
                except Exception:
                    sent_age = "invalid"

            dashboard.append(
                {
                    "recipient": recipient,
                    "last_heard": heard_age,
                    "pending_count": len(pending[recipient]),
                    "last_sent": sent_age,
                    "max_retries": max(p["retry_count"] for p in pending[recipient]),
                }
            )

        return jsonify({"dashboard": dashboard})

    except Exception as e:
        app.logger.error(f"🚨 ERROR in /dashboard: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/dashboard.html")
def dashboard_html():
    """
    Full HTML dashboard with delivery summary and per-recipient pending details.
    Clarifies first-send vs retry:
      - 'Last ReSent' shows last_attempt_ts only when retries>0, else '—'
      - 'Retries' = COALESCE(retry_count, retries, 0)
      - 'Attempts' = Retries + (1 if we've sent at least once)
    """
    try:
        config = configparser.ConfigParser()
        config.read(APRS_CONF)
        MAX_RETRIES = config.getint("store_forward", "max_retries", fallback=3)

        with _connect(STORE_DB) as conn:
            cur = conn.cursor()

            # Delivery summary by msgid (unchanged except for clarity)
            cur.execute(
                f"""
                SELECT msgid,
                       COUNT(*) AS total,
                       SUM(CASE WHEN ack = 1 THEN 1 ELSE 0 END) AS acked,
                       SUM(CASE WHEN (COALESCE(retry_count, retries, 0)) >= {MAX_RETRIES} THEN 1 ELSE 0 END) AS maxed,
                       MAX(timestamp) AS last_ts
                FROM message
                WHERE msgid IS NOT NULL AND msgid != ''
                GROUP BY msgid
                ORDER BY last_ts DESC
                """
            )
            delivery_rows = cur.fetchall()

            delivery_summary = []
            for msgid, total, acked, maxed, timestamp in delivery_rows:
                if acked == total:
                    status = "✅ Fully ACK’d"
                elif acked > 0:
                    status = "⚠️ Partial ACK"
                elif acked == 0 and maxed > 0:
                    status = "❌ No ACK"
                else:
                    status = "⏳ Pending"

                age = "unknown"
                ts_txt = timestamp
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        dt = utc.localize(dt).astimezone(ET_ZONE)
                        delta = datetime.now(ET_ZONE) - dt
                        age = f"{int(delta.total_seconds() / 60)} min ago"
                        ts_txt = dt.strftime("%Y-%m-%d %H:%M:%S %Z")
                    except Exception:
                        age = "invalid"

                delivery_summary.append(
                    {
                        "msgid": msgid,
                        "total": total,
                        "acked": acked,
                        "maxed": maxed,
                        "status": status,
                        "timestamp": ts_txt,
                        "age": age,
                    }
                )

            # Last heard
            cur.execute("SELECT callsign, timestamp FROM last_heard")
            last_heard = {r[0].upper(): r[1] for r in cur.fetchall()}

            # Pending messages (details) — NOTE: we also select last_attempt_ts
            cur.execute(
                """
                SELECT recipient,
                       msgid,
                       message,
                       timestamp,
                       last_sent,
                       last_attempt_ts,
                       COALESCE(retry_count, retries, 0) AS retries_canon
                FROM message
                WHERE ack = 0 AND msgid IS NOT NULL AND msgid != ''
                """
            )
            rows = list(_rows_to_dicts(cur))

        # Assemble details
        pending_summary = defaultdict(list)
        pending_details = defaultdict(list)

        for r in rows:
            key = (r["recipient"] or "").upper()
            # For the top table
            pending_summary[key].append((r["msgid"], r["last_sent"], r["retries_canon"]))

            # Queued time (ET)
            queued_age = "unknown"
            ts_txt = r["timestamp"]
            if r["timestamp"]:
                try:
                    dt = datetime.fromisoformat(r["timestamp"])
                    dt_et = utc.localize(dt).astimezone(ET_ZONE)
                    delta = datetime.now(ET_ZONE) - dt_et
                    queued_age = f"{int(delta.total_seconds() / 60)} min ago"
                    ts_txt = dt_et.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    queued_age = "invalid"

            # Last Sent (any attempt) in ET
            last_sent_txt = "never"
            if r["last_sent"]:
                try:
                    dt2 = datetime.fromisoformat(r["last_sent"])
                    dt2_et = utc.localize(dt2).astimezone(ET_ZONE)
                    last_sent_txt = dt2_et.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    pass

            # Last ReSent (retry only) in ET — show only if retries>0; else "—"
            last_resend_txt = "—"
            if (r["retries_canon"] or 0) > 0 and r["last_attempt_ts"]:
                try:
                    dt3 = datetime.fromisoformat(r["last_attempt_ts"])
                    dt3_et = utc.localize(dt3).astimezone(ET_ZONE)
                    last_resend_txt = dt3_et.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    last_resend_txt = "invalid"

            # Attempts = retries + 1 if we have at least one send
            attempts = (r["retries_canon"] or 0) + (1 if r["last_sent"] else 0)

            pending_details[key].append(
                {
                    "msgid": r["msgid"],
                    "message": r["message"],
                    "timestamp": ts_txt,
                    "queued_age": queued_age,
                    "last_sent": last_sent_txt,      # any attempt (first or later)
                    "last_resend": last_resend_txt,  # retries only
                    "retry_count": r["retries_canon"],
                    "attempts": attempts,
                }
            )

        # Recipient summary table (ages computed vs ET "now")
        dashboard = []
        for recipient in sorted(pending_summary.keys()):
            heard_iso = last_heard.get(recipient)
            heard_age = "never"
            if heard_iso:
                try:
                    dt = datetime.fromisoformat(heard_iso)
                    dt_et = utc.localize(dt).astimezone(ET_ZONE)
                    delta = datetime.now(ET_ZONE) - dt_et
                    heard_age = f"{int(delta.total_seconds() / 60)} min ago"
                except Exception:
                    heard_age = "invalid"

            last_sent_iso = pending_summary[recipient][-1][1]
            sent_age = "never"
            if last_sent_iso:
                try:
                    dt = datetime.fromisoformat(last_sent_iso)
                    dt_et = utc.localize(dt).astimezone(ET_ZONE)
                    delta = datetime.now(ET_ZONE) - dt_et
                    sent_age = f"{int(delta.total_seconds() / 60)} min ago"
                except Exception:
                    sent_age = "invalid"

            dashboard.append(
                {
                    "recipient": recipient,
                    "last_heard": heard_age,
                    "pending_count": len(pending_summary[recipient]),
                    "last_sent": sent_age,
                    "max_retries": max(p[2] for p in pending_summary[recipient]),
                }
            )

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>APRS Store-Forward Dashboard</title>
            <meta http-equiv="refresh" content="30">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 40px; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .stale { background-color: #ffe0e0; }
                .fresh { background-color: #e0ffe0; }
                .neutral { background-color: #ffffe0; }
                h2 { margin-top: 40px; }
                h3 { margin-top: 20px; }
            </style>
        </head>
        <body>
            <h2>📡 APRS Store-Forward Dashboard</h2>
            <p>Updated: {{ timestamp }}</p>
            <table>
                <tr>
                    <th>Recipient</th>
                    <th>Last Heard</th>
                    <th>Pending</th>
                    <th>Last Attempt</th>
                    <th>Max Retries</th>
                </tr>
                {% for row in dashboard %}
                <tr class="{{ 'stale' if row.last_heard == 'never' else 'fresh' }}">
                    <td>{{ row.recipient }}</td>
                    <td>{{ row.last_heard }}</td>
                    <td>{{ row.pending_count }}</td>
                    <td>{{ row.last_sent }}</td>
                    <td>{{ row.max_retries }}</td>
                </tr>
                {% endfor %}
            </table>

            <h2>📬 Message Delivery Summary</h2>
            <table>
                <tr>
                    <th>MsgID</th>
                    <th>Queued At</th>
                    <th>Age</th>
                    <th>Recipients</th>
                    <th>ACK’d</th>
                    <th>Maxed Retries</th>
                    <th>Status</th>
                </tr>
                {% for row in delivery_summary %}
                <tr class="{% if row.status.startswith('✅') %}fresh{% elif row.status.startswith('❌') %}stale{% else %}neutral{% endif %}">
                    <td>{{ row.msgid }}</td>
                    <td>{{ row.timestamp }}</td>
                    <td>{{ row.age }}</td>
                    <td>{{ row.total }}</td>
                    <td>{{ row.acked }}</td>
                    <td>{{ row.maxed }}</td>
                    <td>{{ row.status }}</td>
                </tr>
                {% endfor %}
            </table>

            <h2>📦 Pending Messages by Recipient</h2>
            <h5>Last Sent → first or any transmission
            <BR>
             Last ReSent → only populated if it’s actually been retried (retries > 0)</h5>
            {% for recipient, messages in pending_details.items() %}
            <h3>{{ recipient }}</h3>
            <table>
                <tr>
                    <th>MsgID</th>
                    <th>Message</th>
                    <th>Queued At</th>
                    <th>Age</th>
                    <th>Last Attempt</th>
                    <th>Last ReSent</th>
                    <th>Retries</th>
                    <th>Attempts</th>
                </tr>
                {% for msg in messages %}
                <tr>
                    <td>{{ msg.msgid }}</td>
                    <td>{{ msg.message }}</td>
                    <td>{{ msg.timestamp }}</td>
                    <td>{{ msg.queued_age }}</td>
                    <td>{{ msg.last_sent }}</td>
                    <td>{{ msg.last_resend }}</td>
                    <td>{{ msg.retry_count }}</td>
                    <td>{{ msg.attempts }}</td>
                </tr>
                {% endfor %}
                            </table>
            {% endfor %}
        </body>
        </html>
        """

        return render_template_string(
            html_template,
            dashboard=dashboard,
            delivery_summary=delivery_summary,
            pending_details=pending_details,
            timestamp=datetime.now(ET_ZONE).strftime("%Y-%m-%d %H:%M:%S %Z"),
        )
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /dashboard.html: {e}")
        return "<h1>Internal Server Error</h1>", 500


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)

print("✅ Flask app loaded")
print("✅ Registered routes:")
for rule in app.url_map.iter_rules():
    print(f"🔗 {rule.endpoint}: {rule.rule}")
