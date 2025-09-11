#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import configparser
from datetime import datetime, timedelta
import random
import os
import subprocess
import shlex

# -----------------------------
# Config / Defaults
# -----------------------------
DB_FILE = "/opt/aprsbot/store_forward.db"
CONF_FILE = "/opt/aprsbot/aprsbot.conf"
DEFAULT_SEND_SCRIPT = "/opt/aprsbot/at_aprs_send.sh"

# -----------------------------
# Load configuration
# -----------------------------
def load_config(path=CONF_FILE):
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    cfg.read(path)
    return cfg

# -----------------------------
# Fetch eligible texts
# -----------------------------
def fetch_enabled_texts(conn):
    """Return eligible texts (enabled + cooldown passed)"""
    cur = conn.cursor()
    cur.execute("SELECT * FROM texts WHERE enabled=1")
    rows = cur.fetchall()
    eligible = []

    now = datetime.utcnow()  # naive UTC

    for r in rows:
        last_ts = r["last_sent_ts"]
        gap_days = r["min_gap_days"] if r["min_gap_days"] is not None else 0
        last_dt = None

        if last_ts:
            try:
                dt = datetime.fromisoformat(last_ts.replace("Z", ""))
                last_dt = dt.replace(tzinfo=None)
            except Exception:
                last_dt = None

        if last_dt is None or (now - last_dt).days >= gap_days:
            eligible.append(r)

    return eligible

# -----------------------------
# FIXED MODE: SCHEDULES MESSAGES
# -----------------------------
def schedule_fixed(texts, num_messages, start_hour, end_hour):
    """
    Fixed mode: assign one message per hour within remaining hours today.
    Any messages beyond remaining hours are ignored.
    """
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total_hours = list(range(start_hour, end_hour))

    # Only hours still in the future
    future_hours = [h for h in total_hours if h > now.hour]
    if not future_hours:
        print("No future hours left today. Nothing scheduled.")
        return []

    # Limit num_messages to number of future hours
    num_to_schedule = min(num_messages, len(future_hours))
    selected_texts = texts[:num_to_schedule] if len(texts) >= num_to_schedule else texts

    # Shuffle hours to randomize
    random.shuffle(future_hours)
    schedule = []

    for text, hour in zip(selected_texts, future_hours):
        minute = random.randint(3,57)
        send_time = today.replace(hour=hour, minute=minute)
        # Ensure send_time is in the future
        if send_time <= now:
            send_time = now + timedelta(minutes=1 + random.randint(0,2))
        schedule.append((text["id"], text["text"], send_time))

    return schedule

# -----------------------------
# COVERAGE MODE: SCHEDULES MESSAGES
# -----------------------------
def schedule_coverage(texts, coverage_days, coverage_pct, max_per_day=None):
    total = len(texts)
    target = int(total * coverage_pct)
    scheduled = []

    start_day = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)
    index = 0
    remaining = target

    for d in range(coverage_days):
        if remaining <= 0:
            break
        day_base = start_day + timedelta(days=d)
        per_day = min(
            remaining,
            max_per_day if max_per_day else remaining,
            max(1, target // coverage_days)
        )
        for i in range(per_day):
            if index >= total:
                break
            hour = 9 + (i % 12)
            send_time = day_base.replace(hour=hour, minute=random.randint(0, 59))
            scheduled.append((texts[index]["id"], texts[index]["text"], send_time))
            index += 1
            remaining -= 1

    return scheduled

# -----------------------------
# Update min_gap_days based on mode and total messages (NEW ROUTINE)
# -----------------------------
def update_min_gap_days(conn, mode, config_data):
    """
    Dynamically updates the min_gap_days for all messages.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM texts WHERE enabled = 1")
    total_messages = cursor.fetchone()[0]

    if total_messages == 0:
        print("No enabled messages found to update.")
        return

    new_gap = 0
    if mode == 'fixed':
        num_messages = config_data.getint("scheduler", "num_messages", fallback=12)
        if num_messages > 0:
            new_gap = total_messages / num_messages
            
    elif mode == 'coverage':
        coverage_days = config_data.getint("scheduler", "coverage_days", fallback=5)
        if coverage_days > 0:
            new_gap = coverage_days / total_messages
            
    else:
        print(f"Invalid mode: {mode}. Min_gap_days not updated.")
        return

    cursor.execute("UPDATE texts SET min_gap_days = ? WHERE enabled = 1", (new_gap,))
    conn.commit()
    print(f"Updated min_gap_days to {new_gap:.2f} based on '{mode}' mode.")


# -----------------------------
# Apply schedule in DB
# -----------------------------
def update_db(conn, schedule):
    now_iso = datetime.utcnow().isoformat()
    cur = conn.cursor()
    for tid, text, ts in schedule:
        cur.execute("""
            UPDATE texts
                SET last_sent_ts = ?,
                    sent_count = COALESCE(sent_count,0)+1,
                    updated_ts = ?
            WHERE id = ?
        """, (ts.isoformat(), now_iso, tid))
    conn.commit()

# -----------------------------
# Schedule via at
# -----------------------------
def schedule_with_at(text, send_time, send_script=DEFAULT_SEND_SCRIPT):
    now = datetime.utcnow()
    # Ensure send_time is in the future
    if send_time <= now:
        send_time = now + timedelta(minutes=1 + random.randint(0,5))

    delta = send_time - now
    delay_minutes = max(1, int(delta.total_seconds() // 60))
    # Slight random jitter within ±2 min to avoid collisions
    delay_minutes += random.randint(0,2)

    cmd = f"{shlex.quote(send_script)} {shlex.quote(text)} {delay_minutes}"
    subprocess.run(["bash", "-c", cmd], check=True)


# -----------------------------
# Main
# -----------------------------
def main(dry_run=False):
    cfg = load_config()
    mode = cfg.get("scheduler", "mode", fallback="fixed").strip().lower()
    send_script = cfg.get("scheduler", "send_script", fallback=DEFAULT_SEND_SCRIPT)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    # NEW: Update min_gap_days before fetching texts
    update_min_gap_days(conn, mode, cfg)
    
    texts = fetch_enabled_texts(conn)
    if not texts:
        print("No eligible texts to schedule.")
        return

    if mode == "fixed":
        num_messages = cfg.getint("scheduler", "num_messages", fallback=12)
        start_hour = cfg.getint("scheduler", "start_hour", fallback=9)
        end_hour = cfg.getint("scheduler", "end_hour", fallback=22)
        schedule = schedule_fixed(texts, num_messages, start_hour, end_hour)
        print(f"Fixed mode: scheduled {len(schedule)} texts.")

    elif mode == "coverage":
        coverage_days = cfg.getint("scheduler", "coverage_days", fallback=5)
        coverage_pct = cfg.getfloat("scheduler", "coverage_pct", fallback=0.9)
        max_per_day = cfg.getint("scheduler", "max_per_day", fallback=0)
        max_per_day = max_per_day if max_per_day > 0 else None
        schedule = schedule_coverage(texts, coverage_days, coverage_pct, max_per_day)
        print(f"Coverage mode: scheduled {len(schedule)} texts (max/day={max_per_day}).")

    else:
        raise ValueError(f"Unknown scheduler mode: {mode}")

    update_db(conn, schedule)

    for tid, text, send_time in schedule:
        if dry_run:
            print(f"DRY-RUN: {send_time} -> {text}")
        else:
            schedule_with_at(text, send_time, send_script)

    conn.close()

# -----------------------------
if __name__ == "__main__":
    random.seed()
    main(dry_run=False)