import sqlite3
from datetime import datetime, UTC

STORE_DB = "/opt/aprsbot/store_forward.db"
PURGE_DAYS = 1  # 1 day = 24 hours
AUDIT_TRIM_DAYS = 7  # 7 days for audit logs

NEVER_ATTEMPTED_WHERE = """
COALESCE(ack,0)=0
AND (last_attempt_ts IS NULL OR last_attempt_ts = '')
AND (last_sent       IS NULL OR last_sent       = '')
"""

def trim_audit_logs(db, days):
    now_iso = datetime.now(UTC).isoformat()
    conn = sqlite3.connect(db)
    c = conn.cursor()
    
    # === Count before deletion ===
    c.execute("""
        SELECT COUNT(*) FROM audit_log
         WHERE julianday(replace(timestamp, 'T', ' ')) < julianday(datetime('now', ?))
    """, (f"-{days} days",))
    (cnt_old,) = c.fetchone()
    
    # === Delete old audit_log entries ===
    c.execute("""
        DELETE FROM audit_log
         WHERE julianday(replace(timestamp, 'T', ' ')) < julianday(datetime('now', ?))
    """, (f"-{days} days",))
    deleted = c.rowcount
    
    conn.commit()
    conn.close()
    
    # === Show results ===
    print(f"[{now_iso}] Audit trim summary:")
    print(f"  Old entries (>{days} days): {cnt_old}")
    print(f"[{now_iso}] Deleted {deleted} audit_log entries older than {days} days")
    print()

def purge_old_acks(db, days):
    hours = int(days * 24)
    now_iso = datetime.now(UTC).isoformat()
    conn = sqlite3.connect(db)
    c = conn.cursor()
    
    # === Count by category (before deletion) ===
    c.execute("SELECT COUNT(*) FROM message WHERE ack=1")
    (cnt_acked,) = c.fetchone()
    
    c.execute("SELECT COUNT(*) FROM message WHERE msgid IS NULL OR msgid=''")
    (cnt_nomsgid,) = c.fetchone()
    
    c.execute("""
        SELECT COUNT(*) FROM message
         WHERE julianday(replace(timestamp, 'T', ' ')) < julianday(datetime('now', ?))
    """, (f"-{hours} hours",))
    (cnt_expired,) = c.fetchone()
    
    c.execute("SELECT COUNT(*) FROM message WHERE COALESCE(retry_count,0) >= 4")
    (cnt_retries,) = c.fetchone()
    
    c.execute("SELECT COUNT(*) FROM message WHERE upper(recipient)='APRS' OR upper(recipient) GLOB 'BLN*'")
    (cnt_bulletins,) = c.fetchone()
    
    c.execute("SELECT COUNT(*) FROM message WHERE UPPER(recipient) = 'KC2NJV-10'")
    (cnt_tnc,) = c.fetchone()
    
    # === Purge step 1: original delete logic ===
    c.execute("""
        DELETE FROM message
         WHERE ack = 1
            OR msgid IS NULL
            OR msgid = ''
            OR julianday(replace(timestamp, 'T', ' ')) < julianday(datetime('now', ?))
            OR COALESCE(retry_count, 0) >= 4
    """, (f"-{hours} hours",))
    deleted_main = c.rowcount
    
    # === Purge step 2: always delete bulletins/APRS ===
    c.execute("""
        DELETE FROM message
         WHERE upper(recipient)='APRS'
            OR upper(recipient) GLOB 'BLN*'
    """)
    deleted_bulletins = c.rowcount
    
    # === Purge step 3: clear KC2NJV-10 ===
    c.execute("DELETE FROM message WHERE UPPER(recipient) = 'KC2NJV-10'")
    deleted_tnc = c.rowcount
    
    conn.commit()
    total_deleted = (deleted_main or 0) + (deleted_bulletins or 0) + (deleted_tnc or 0)
    
    # === Show results ===
    print(f"[{now_iso}] Purge summary (counts before purge):")
    print(f"  ACKed rows       : {cnt_acked}")
    print(f"  Missing msgid    : {cnt_nomsgid}")
    print(f"  Expired timestamp: {cnt_expired}")
    print(f"  Retries >= 4     : {cnt_retries}")
    print(f"  Bulletins/APRS   : {cnt_bulletins}")
    print(f"  KC2NJV-10 queued : {cnt_tnc}")
    print()
    print(f"[{now_iso}] Deleted {deleted_main} rows (acked/expired/missing msgid/retries>=4)")
    print(f"[{now_iso}] Deleted {deleted_bulletins} bulletin/APRS rows (all)")
    print(f"[{now_iso}] Deleted {deleted_tnc} rows for KC2NJV-10")
    print(f"[{now_iso}] Total deleted this run: {total_deleted}")
    
    # === Show first 20 never-attempted rows AFTER purge ===
    c.execute(f"""
        SELECT id, recipient, msgid, last_sent, last_attempt_ts
          FROM message
         WHERE {NEVER_ATTEMPTED_WHERE}
         ORDER BY id ASC
         LIMIT 20
    """)
    remaining = c.fetchall()
    conn.close()
    
    if remaining:
        print("\nRemaining never-attempted rows (first 20 after purge):")
        for rid, recip, mid, ls, la in remaining:
            print(f"  id={rid:<6} recipient={recip:<10} msgid={mid or ''} last_sent={ls or ''} last_attempt_ts={la or ''}")
    else:
        print("\nNo remaining never-attempted rows after purge.")

if __name__ == "__main__":
    # Trim audit logs
    trim_audit_logs(STORE_DB, AUDIT_TRIM_DAYS)
    
    # Purge old messages
    purge_old_acks(STORE_DB, PURGE_DAYS)
