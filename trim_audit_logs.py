import sqlite3
import sys
import os
import datetime # While not strictly needed for datetime('now', '-7 days'), good for clarity

DATABASE = '/opt/aprsbot/erli.db' # Ensure this path is correct relative to where you run the script

def trim_old_audit_logs():
    """
    Connects to the SQLite database and deletes audit_log entries older than 7 days.
    """
    # Check if the database file exists
    if not os.path.exists(DATABASE):
        print(f"ERROR: Database file '{DATABASE}' not found.", file=sys.stderr)
        return {"status": "error", "message": f"Database file '{DATABASE}' not found."}

    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # SQL to delete entries where the timestamp is older than 7 days from now
        # The 'timestamp' column in audit_log should be stored in a format
        # that SQLite's datetime functions can parse (e.g., 'YYYY-MM-DD HH:MM:SS').
        cursor.execute("""
            DELETE FROM audit_log
            WHERE timestamp < datetime('now', '-7 days');
        """)
        conn.commit()
        deleted_count = cursor.rowcount
        print(f"INFO: Successfully trimmed {deleted_count} audit_log entries older than 7 days.", file=sys.stdout)
        return {"status": "success", "deleted_count": deleted_count}

    except sqlite3.Error as e:
        error_msg = f"ERROR: Database error during trimming: {e}"
        print(error_msg, file=sys.stderr)
        return {"status": "error", "message": error_msg}
    except Exception as e:
        error_msg = f"ERROR: An unexpected error occurred during trimming: {e}"
        print(error_msg, file=sys.stderr)
        return {"status": "error", "message": error_msg}
    finally:
        if conn:
            conn.close()
            print(f"INFO: Database connection to '{DATABASE}' closed.", file=sys.stdout)

if __name__ == "__main__":
    print(f"INFO: Starting audit log trimming process at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stdout)
    result = trim_old_audit_logs()
    if result["status"] == "success":
        sys.exit(0) # Exit with success code
    else:
        sys.exit(1) # Exit with error code