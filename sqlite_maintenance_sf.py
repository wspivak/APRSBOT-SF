import sqlite3
from datetime import datetime

DB_PATH = "/opt/aprsbot/store_forward.db"
LOG_PATH = "/opt/aprsbot/sqlite_SF_maintenance_log.txt"

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def run_checks():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    log("Starting SQLite maintenance checks.")

    # Integrity check
    cursor.execute("PRAGMA integrity_check;")
    result = cursor.fetchone()[0]
    log(f"Integrity check result: {result}")

    # List indexes
    cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type = 'index';")
    indexes = cursor.fetchall()
    if indexes:
        log("Indexes found:")
        for name, table in indexes:
            log(f"  - Index: {name} on Table: {table}")
    else:
        log("No indexes found.")

    # Run ANALYZE
    try:
        cursor.execute("ANALYZE;")
        log("ANALYZE completed successfully.")
    except Exception as e:
        log(f"ANALYZE failed: {e}")

    # Run VACUUM
    try:
        cursor.execute("VACUUM;")
        log("VACUUM completed successfully.")
    except Exception as e:
        log(f"VACUUM failed: {e}")

    conn.close()
    log("SQLite maintenance checks completed.\n")

if __name__ == "__main__":
    run_checks()
