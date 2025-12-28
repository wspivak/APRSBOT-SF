#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Store-and-Forward APRS Daemon (simplified, resilient)

Key behaviors:
- Messages addressed TO your aliases/calls => sender is treated as eligible immediately (no users-table prerequisite).
- Single combined APRS-IS filter: base_filter (or filter) + m/ + b/ + p/.
- Robust DB schema migration; retry counters and timestamps handled sanely.
- Bulk resend on a UTC-aligned clock; per-destination and global pacing.
- Optional tail of replybot.log for extra ACK/seen hints (does not gate core RX path).

Config sections used:
  [tnc_rf]      addr, port
  [tnc_aprsis]  addr, port, callsign, passcode, base_filter (or filter)
  [aprs]        callsign, aliases, dbfile
  [store_forward]
        store_db=/opt/aprsbot/store_forward.db
        log_file=/opt/aprsbot/logs/sf.log
        bot_log_tail=/opt/aprsbot/logs/replybot.log
        max_retries=3
        resend_delay=60           # minutes between attempts per message
        delay_send=5.0            # global spacing seconds
        per_dest_gap_sec=5.0
        users_refresh_secs=1800
        filter_heartbeat_secs=1800
        filter_min_gap_secs=60
        prefer_rf_minutes=180
        resend_clock=6            # hours; clock aligned to UTC blocks
"""

import os
import re
import sys
import time
import queue
import sqlite3
import logging
import threading
import configparser
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timedelta

# ---- Project imports (present in your environment) ----
from ioreth.aprs import Handler as AprsHandler
from ioreth.clients import AprsIsClient, RfKissClient

CONFIG_FILE = os.environ.get("APRSBOT_CONF", "/opt/aprsbot/aprsbot.conf")

# =============================================================================
# Logging
# =============================================================================

def build_logger(path: str) -> logging.Logger:
    lg = logging.getLogger("storeforward")
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    lg.propagate = False
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    sh = logging.StreamHandler(sys.stdout); sh.setFormatter(fmt)
    lg.addHandler(sh)
    if path:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fh = logging.FileHandler(path); fh.setFormatter(fmt)
            lg.addHandler(fh)
        except Exception:
            pass
    for noisy in ("urllib3", "asyncio", "websockets"):
        try: logging.getLogger(noisy).setLevel(logging.WARNING)
        except Exception: pass
    return lg

# =============================================================================
# Small helpers
# =============================================================================

def utc_iso() -> str:
    return datetime.utcnow().isoformat()

def _utcnow_iso_us():
    return datetime.utcnow().isoformat(timespec="microseconds")

def norm_cs(cs) -> str:
    return str(cs or "").replace("*", "").strip().upper()

def base_call(cs) -> str:
    csu = norm_cs(cs)
    return csu.split("-", 1)[0] if "-" in csu else csu

def sanitize_msgid(raw: str) -> str:
    s = "".join(ch for ch in (raw or "").upper() if ch.isalnum())
    return s[:5]

def strip_any_tail_or_braces(text: str) -> str:
    p = (text or "").rstrip()
    p = re.sub(r"\{[A-Za-z0-9]{1,5}\}\s*$", "", p)  # {ABCDE}
    p = re.sub(r"\{[A-Za-z0-9]{1,5}\s*$",    "", p)  # {ABCDE
    p = re.sub(r"[A-Za-z0-9]{1,5}\}\s*$",    "", p)  # ABCDE}
    p = re.sub(r"[\}\s]+$",                  "", p)
    return p

def build_payload_strict(message: str, msgid: str) -> str:
    base = strip_any_tail_or_braces(message)
    mid  = sanitize_msgid(msgid or "")
    return (f"{base}{{{mid}" if mid else base).encode("ascii", "ignore").decode("ascii", "ignore")

ACK_RES = [
    re.compile(r'ack[^A-Za-z0-9{]*([A-Za-z0-9]{1,10})', re.I),
    re.compile(r'\{([A-Za-z0-9]{1,10})\}\s*$'),
    re.compile(r'([A-Za-z0-9]{1,10})\}\s*$'),
    re.compile(r'([A-Za-z0-9]{1,10})')
]
def extract_ack_token(text: str) -> str:
    t = text or ""
    for rx in ACK_RES:
        m = rx.search(t)
        if m: return sanitize_msgid(m.group(1))
    return ""

# =============================================================================
# DB schema & bookkeeping
# =============================================================================

def ensure_sf_schema(conn: sqlite3.Connection, logger: Optional[logging.Logger] = None) -> None:
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            message TEXT NOT NULL,
            msgid TEXT,
            ack INTEGER DEFAULT 0,
            retries INTEGER DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            last_attempt_ts TEXT,
            last_error TEXT,
            last_sent TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS last_heard (
            callsign TEXT PRIMARY KEY,
            timestamp TEXT,
            via TEXT DEFAULT 'IS'
        )
    """)

    # Add audit_log table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            direction TEXT,
            source TEXT,
            destination TEXT,
            message TEXT,
            msgid TEXT,
            rejected INTEGER DEFAULT 0,
            note TEXT,
            transport TEXT
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_ack_recipient ON message(ack, recipient)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_ack_msgid     ON message(ack, msgid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_pending       ON message(ack, recipient, last_attempt_ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_log(timestamp)")
    conn.commit()
    if logger: logger.info("Schema ensured/migrated for store_forward.db")

def mark_first_send(conn, mid: int) -> None:
    ts = _utcnow_iso_us()
    conn.execute("""
        UPDATE message
           SET last_sent       = :ts,
               last_attempt_ts = :ts,
               last_error      = NULL,
               retry_count     = COALESCE(retry_count, 0),
               retries         = COALESCE(retries, 0)
         WHERE id = :mid AND ack = 0
    """, {"ts": ts, "mid": mid})
    conn.commit()

def mark_resend(conn, mid: int) -> None:
    ts = _utcnow_iso_us()
    conn.execute("""
        UPDATE message
           SET last_sent       = :ts,
               last_attempt_ts = :ts,
               last_error      = last_error,
               retry_count     = COALESCE(retry_count, 0) + 1,
               retries         = COALESCE(retries, 0) + 1
         WHERE id = :mid AND ack = 0
    """, {"ts": ts, "mid": mid})
    conn.commit()

def mark_ack(conn, msgid: str) -> None:
    conn.execute("UPDATE message SET ack=1 WHERE msgid=?", (msgid,))
    conn.commit()

# =============================================================================
# Config
# =============================================================================

def load_cfg():
    cfg = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
    cfg.optionxform = str
    cfg.read(CONFIG_FILE)
    def _f(section, key, default):
        try:
            return cfg.get(section, key, fallback=default)
        except Exception:
            return default
    def _fi(section, key, default: int):
        try:
            raw = cfg.get(section, key, fallback=str(default))
            return int(str(raw).split()[0])
        except Exception:
            return int(default)
    def _ff(section, key, default: float):
        try:
            return float(cfg.get(section, key, fallback=str(default)))
        except Exception:
            return float(default)
    # APRS core
    mycall    = _f("aprs", "callsign", "N0CALL").strip().upper()
    aliases   = {a.strip().upper() for a in _f("aprs", "aliases", "").split(",") if a.strip()}
    aliases.add(mycall)
    users_db  = _f("aprs", "dbfile", "/opt/aprsbot/erli.db").strip()
    # SF
    store_db  = _f("store_forward", "store_db", "/opt/aprsbot/store_forward.db").strip()
    log_file  = _f("store_forward", "log_file", "/opt/aprsbot/logs/sf.log").strip()
    bot_tail  = _f("store_forward", "bot_log_tail", "/opt/aprsbot/logs/replybot.log").strip()
    # READ THE 'enabled' FLAG:
    sf_enabled = cfg.getboolean("store_forward", "enabled", fallback=True)
    max_ret   = _fi("store_forward", "max_retries", 3)
    resend_m  = max(1, _fi("store_forward", "resend_delay", 60))
    g_delay   = _ff("store_forward", "delay_send", 5.0)
    d_gap     = _ff("store_forward", "per_dest_gap_sec", 5.0)
    u_ref     = _fi("store_forward", "users_refresh_secs", 1800)
    f_hb      = _fi("store_forward", "filter_heartbeat_secs", 1800)
    f_gap     = _fi("store_forward", "filter_min_gap_secs", 60)
    prefer_rf = _fi("store_forward", "prefer_rf_minutes", 180)
    rclock_h  = max(1, min(24, _fi("store_forward", "resend_clock", 6)))

    # TNC RF
    rf = {}
    if cfg.has_section("tnc_rf"):
        rf = {
            "addr": _f("tnc_rf", "addr", ""),
            "port": _fi("tnc_rf", "port", 0),
        }
    # TNC APRS-IS
    isec = {}
    if cfg.has_section("tnc_aprsis"):
        isec = {
            "addr": _f("tnc_aprsis", "addr", ""),
            "port": _fi("tnc_aprsis", "port", 0),
            "callsign": _f("tnc_aprsis", "callsign", mycall),
            "passcode": _f("tnc_aprsis", "passcode", "00000"),
            "base_filter": _f("tnc_aprsis", "base_filter", _f("tnc_aprsis", "filter", "t/pmso")).strip(),
        }

    return {
        "cfg": cfg,
        "mycall": mycall,
        "aliases": aliases,
        "users_db": users_db,
        "store_db": store_db,
        "log_file": log_file,
        "bot_tail": bot_tail,
        "max_retries": max_ret,
        "sf_enabled": sf_enabled,  # Pass the value as sf_enabled
        "resend_delay_min": resend_m,
        "delay_send_sec": g_delay,
        "per_dest_gap_sec": d_gap,
        "users_refresh_secs": u_ref,
        "filter_heartbeat_secs": f_hb,
        "filter_min_gap_secs": f_gap,
        "prefer_rf_minutes": prefer_rf,
        "resend_clock_hours": rclock_h,
        "tnc_rf": rf,
        "tnc_is": isec,
    }

# =============================================================================
# Log tailer (optional)
# =============================================================================

LOG_PARSED_SRC_PAYLOAD_RE = re.compile(
    r"\[Parsed\]\s+source=([A-Z0-9\-]+)\*?,.*?payload=([^\n\r]*)",
    re.IGNORECASE,
)

def tail_file(path: str, cb_seen, cb_ack, logger: logging.Logger):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2); continue
                m = LOG_PARSED_SRC_PAYLOAD_RE.search(line)
                if m:
                    src = m.group(1)
                    payload = (m.group(2) or "").strip()
                    cb_seen(src)
                    tok = extract_ack_token(payload)
                    if tok:
                        cb_ack(src, tok)
    except Exception as e:
        logger.debug("log tailer ended: %s", e)

# =============================================================================
# APRS handler
# =============================================================================

class SFHandler(AprsHandler):
    def __init__(self, svc, my_callsign: str):
        super().__init__(callsign=my_callsign)
        self.svc = svc


    def _log_audit(self, direction, source, destination, message, msgid=None, rejected=False, note=None, transport=None):
        """Audit logging to store_forward.db"""
        try:
            cur = self.svc.sf_conn.cursor()
            cur.execute("""
                INSERT INTO audit_log (timestamp,direction, source, destination, message, msgid, rejected, note, transport)
                VALUES (CURRENT_TIMESTAMP,?, ?, ?, ?, ?, ?, ?, ?)
            """, (direction, source, destination, message, msgid, int(rejected), note, transport))
            self.svc.sf_conn.commit()
        except Exception as e:
            self.svc.logger.error(f"Audit log failed: {e}")


    # Mark stations as heard for any packet types
    def _heard(self, source, via=None):
        csu = norm_cs(source)
        if csu:
            try:
                self.svc._mark_seen_generic(csu)
            except Exception as e:
                self.svc.logger.error("on_seen failed for %s: %s", csu, e)

    def on_aprs_packet(self, origframe, source, payload, via=None):
        # route to base class after tagging path and seen
        try:
            via_is = bool(getattr(origframe, "from_aprsis", False))
            self.svc._mark_heard_path(norm_cs(source), "is" if via_is else "rf")
        except Exception:
            pass
        self._heard(source, via or [])
        try:
            return super().on_aprs_packet(origframe, source, payload, via)
        except Exception as e:
            self.svc.logger.exception("Frame handling error: %s", e)

    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        # Any message addressed to our alias/calls: force eligible immediately
        try:
            via_is = bool(getattr(origframe, "from_aprsis", False))
            self.svc._mark_heard_path(norm_cs(source), "is" if via_is else "rf")
        except Exception:
            pass

        self._heard(source, via or [])
        try:
            dst = norm_cs(addressee)
            if dst in self.svc.aliases:
                # Treat sender as eligible immediately
                self.svc._promote_direct_sender(norm_cs(source))
                # Handle ACK token opportunistically
                tok = extract_ack_token(text or "")
                if tok:
                    self.svc.on_ack_received(from_callsign=source, msgid=tok)
        except Exception as e:
            self.svc.logger.error("direct-msg/ack handling failed: %s", e)

        try:
            return super().on_aprs_message(source, addressee, text, origframe, msgid=msgid, via=via)
        except Exception as e:
            self.svc.logger.exception("Base on_aprs_message failed: %s", e)

    # For other types, just mark heard
    def on_aprs_status(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_object(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_item(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_position_msg(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_position_ts(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_position_ts_msg(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_position_wtr(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_mic_e(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_old_mic_e(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_telemetry(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_query(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_third_party(self, origframe, source, payload, via=None): self._heard(source, via or [])
    def on_aprs_others(self, origframe, source, payload, via=None): self._heard(source, via or [])

# =============================================================================
# Service
# =============================================================================

MSGID_TAIL_RE = re.compile(r"\{[A-Z0-9]{1,5}$")

class StoreForwardService:
    def __init__(self):
        P = load_cfg()
        self.cfg_all = P["cfg"]
        self.my_callsign = P["mycall"]
        self.aliases     = set(P["aliases"])
        self.aliases_base= {base_call(x) for x in self.aliases}
        self.users_db    = P["users_db"]

        self.store_db_path = P["store_db"]
        self.logger = build_logger(P["log_file"])
        self.bot_log_tail  = P["bot_tail"]
        self.sf_enabled         = P["sf_enabled"] # STORE THE FLAG HERE

        self.max_retries        = P["max_retries"]
        self.resend_delay_min   = P["resend_delay_min"]
        self.delay_send_sec     = P["delay_send_sec"]
        self.per_dest_gap_sec   = P["per_dest_gap_sec"]
        self.users_refresh_secs = P["users_refresh_secs"]
        self.filter_heartbeat_secs = P["filter_heartbeat_secs"]
        self.filter_min_gap_secs   = P["filter_min_gap_secs"]
        self.prefer_rf_minutes  = P["prefer_rf_minutes"]
        self.resend_clock_hours = P["resend_clock_hours"]

        # DB
        self.sf_conn = sqlite3.connect(self.store_db_path, timeout=5.0, check_same_thread=False)
        ensure_sf_schema(self.sf_conn, self.logger)

        # Users cache
        self.users = set()
        self.users_base = set()
        self._next_users_refresh = 0.0

        # Heard path and debounces
        self._heard_path: Dict[str, Tuple[str, float]] = {}
        self._seen_log_ts: Dict[str, float] = {}
        self._seen_enq_ts: Dict[str, float] = {}
        self._last_heard_log_ts: Dict[str, float] = {}

        # Queues
        self.seen_queue = queue.Queue()

        # Pacing
        self._last_any_send_ts = 0.0
        self._last_send_ts: Dict[str, float] = {}

        # Bulk clock
        self._next_bulk_resend = 0
        self._last_bulk_run_ts = 0

        # Clients
        self.clients: Dict[str, object] = {}
        self._init_clients(P["tnc_rf"], P["tnc_is"])

        # Handler
        self.handler = SFHandler(self, self.my_callsign)

        # Filters state
        self._filter_dirty = True
        self._last_filter_apply_ts = 0.0
        self._next_filter_heartbeat = 0.0
        self._last_filter_sig = ""

        # Initial users
        self._refresh_users_if_due(force=True)

    # ---- Users ----
    def _refresh_users_if_due(self, force: bool = False):
        now = time.monotonic()
        if not force and now < self._next_users_refresh:
            return
        fresh = read_users_set(self.users_db)
        if fresh != self.users:
            self.users = fresh
            self.users_base = {base_call(u) for u in self.users}
            self._filter_dirty = True
        self._next_users_refresh = now + float(self.users_refresh_secs)
        self.logger.info("Users refreshed: %d", len(self.users))

    # ---- Heard path ----
    def _mark_heard_path(self, callsign: str, via: str):
        csu = norm_cs(callsign)
        if not csu: return
        self._heard_path[csu] = (via, time.time())

    def _via_label(self, csu: str) -> str:
        info = self._heard_path.get(csu)
        if not info: return "?"
        return "APRS-IS" if info[0] == "is" else ("RF" if info[0] == "rf" else "?")

    def last_heard_via_rf_recent(self, callsign: str) -> bool:
        csu = norm_cs(callsign)
        info = self._heard_path.get(csu)
        if not info or info[0] != "rf": return False
        return (time.time() - info[1]) <= (self.prefer_rf_minutes * 60)


    # ---- Seen/eligible management ----
    def _update_last_heard_row(self, csu: str):
        try:
            now_iso = utc_iso()
            self.sf_conn.execute(
                "INSERT INTO last_heard(callsign,timestamp) VALUES(?,?) "
                "ON CONFLICT(callsign) DO UPDATE SET timestamp=excluded.timestamp",
                (csu, now_iso)
            )
            self.sf_conn.commit()
            now_m = time.monotonic()
            if now_m - self._last_heard_log_ts.get(csu, 0.0) >= 5.0:
                self.logger.info("last_heard upsert [%s]: %s -> %s", self._via_label(csu), csu, now_iso)
                self._last_heard_log_ts[csu] = now_m
        except Exception as e:
            self.logger.warning("last_heard update failed: %s", e)
    
    def _enqueue_seen_once_per_window(self, csu: str):
        now = time.monotonic()
        if now - self._seen_enq_ts.get(csu, 0.0) >= 5.0:
            try:
                self.seen_queue.put_nowait(csu)
                self._seen_enq_ts[csu] = now
            except queue.Full:
                pass

    def _mark_seen_generic(self, csu: str):
        csu = norm_cs(csu)
        if not csu: return
        b = base_call(csu)
        eligible = (csu in self.users or b in self.users_base or csu in self.aliases or b in self.aliases_base)
        if not eligible:  # generic packets from unknowns do not trigger resend checks
            return
        if time.monotonic() - self._seen_log_ts.get(csu, 0.0) >= 2.0:
            self.logger.info("HEARD eligible [%s]: %s", self._via_label(csu), csu)
            self._seen_log_ts[csu] = time.monotonic()
        self._update_last_heard_row(csu)
        self._enqueue_seen_once_per_window(csu)

    def _promote_direct_sender(self, csu: str):
        """Called when we receive a direct message addressed to our alias/calls."""
        if time.monotonic() - self._seen_log_ts.get(csu, 0.0) >= 2.0:
            self.logger.info("HEARD (direct-to-alias): %s", csu)
            self._seen_log_ts[csu] = time.monotonic()
        self._update_last_heard_row(csu)
        self._enqueue_seen_once_per_window(csu)

    # ---- Clients ----
    def _init_clients(self, rf_cfg: dict, is_cfg: dict):
        # RF
        if rf_cfg and rf_cfg.get("addr") and rf_cfg.get("port"):
            try:
                rf = RfKissClient(addr=rf_cfg["addr"], port=int(rf_cfg["port"]))
                rf.callsign = self.my_callsign
                rf.on_recv_frame = lambda frame: self._on_frame(frame, from_aprsis=False)
                self.clients["rf"] = rf
                self.logger.info("RF TNC client ready at %s:%s", rf_cfg["addr"], rf_cfg["port"])
            except Exception as e:
                self.logger.warning("RF client init failed: %s", e)
        # APRS-IS
        if is_cfg and is_cfg.get("addr") and is_cfg.get("port"):
            try:
                is_client = AprsIsClient(
                    addr=is_cfg["addr"],
                    port=int(is_cfg["port"]),
                    callsign=is_cfg.get("callsign", self.my_callsign).strip(),
                    passcode=is_cfg.get("passcode", "00000").strip(),
                    aprs_filter=None,  # we will send combined filter after connect
                )
                is_client.on_recv_frame = lambda frame: self._on_frame(frame, from_aprsis=True)
                self.clients["aprsis"] = is_client
                # record base filter raw
                self._base_filter_raw = is_cfg.get("base_filter", "t/pmso")
            except Exception as e:
                self.logger.warning("APRS-IS client init failed: %s", e)

    def _ensure_connected(self):
        for label, c in self.clients.items():
            try:
                if not c.is_connected():
                    c.connect()
                    self.logger.info("%s connected: %s", label, c.is_connected())
                    if label == "aprsis" and c.is_connected():
                        self._filter_dirty = True
            except Exception as e:
                self.logger.warning("%s connect failed: %s", label, e)

    def _extract_source(self, frame) -> Optional[str]:
        try:
            if isinstance(frame, str):
                return frame.split('>', 1)[0].strip() if '>' in frame else frame.strip().split(':', 1)[0][:15]
            for attr in ("source", "src", "from_call", "fromcall", "from_", "sender"):
                if hasattr(frame, attr):
                    val = getattr(frame, attr)
                    if val:
                        return str(val).strip()
            s = str(frame)
            return s.split('>', 1)[0].strip() if '>' in s else s.strip().split(':', 1)[0][:15]
        except Exception:
            return None

    def _on_frame(self, frame, from_aprsis: bool):
        label = "APRS-IS" if from_aprsis else "RF"
        try:
            try: setattr(frame, "from_aprsis", bool(from_aprsis))
            except Exception: pass
            src = self._extract_source(frame)
            self.logger.debug("RX [%s] src=%s frame=%s", label, src or "?", str(frame)[:160])
            if src:
                self._mark_heard_path(src, "is" if from_aprsis else "rf")
            self.handler.handle_frame(frame, from_aprsis=from_aprsis)
        except Exception as e:
            self.logger.exception("RX handling error [%s]: %s", label, e)

    # ---- Filters ----
    def _sanitize_filter_token(self, tok: str) -> str:
        tok = (tok or "").strip()
        if not tok: return ""
        if tok.startswith("t/"):
            letters = tok[2:].replace(",", "")
            return f"t/{letters}" if letters else ""
        if tok.startswith(("r/", "b/", "p/", "m/")):
            return tok
        return tok

    def _compute_filter_tokens(self) -> List[str]:
        """
        Compute APRS-IS filter tokens.
        
        For wide-area nets with large radius filters (r/lat/lon/radius),
        we rely solely on the base filter and handle user eligibility 
        in Python via _mark_seen_generic(). This avoids filter complexity
        issues with APRS-IS servers.
        
        Individual user filters (b/, p/, m/) are only added if there's 
        no range filter present in the base configuration.
        """
        base = self._base_filter_raw or "t/pmso"
        base_toks = [self._sanitize_filter_token(t) for t in base.split() if t.strip()]
        base_toks = [t for t in base_toks if t]
        
        # Check if base filter contains a range filter (r/lat/lon/radius)
        has_range_filter = any(tok.startswith('r/') for tok in base_toks)
        
        if has_range_filter:
            # Wide-area coverage mode: base filter only
            # User eligibility is handled in _mark_seen_generic()
            self.logger.info(
                "Range filter detected in base - using simplified filter "
                "(%d tokens). User filtering handled in Python.",
                len(base_toks)
            )
            return base_toks
        
        # No range filter: add specific user/alias filters for targeted coverage
        self.logger.info("No range filter - building user-specific filters")
        
        calls_full = set(self.users) | set(self.aliases)
        bases = {base_call(c) for c in calls_full}
        
        # Budlist/prefix filters
        b_tokens = [f"b/{u}" for u in sorted(calls_full)]
        p_tokens = [f"p/{b}" for b in sorted(bases)]
        
        # Messages addressed TO any of our calls/aliases/users
        m_tokens = [f"m/{c}" for c in sorted(calls_full | bases)]
        
        combined = base_toks + b_tokens + p_tokens + m_tokens
        self.logger.info(
            "Built targeted filter with %d tokens "
            "(%d base + %d budlist + %d prefix + %d message)",
            len(combined), len(base_toks), len(b_tokens), len(p_tokens), len(m_tokens)
        )
        
        return combined

    def _apply_combined_filter_if_needed(self):
        ic = self.clients.get("aprsis")
        if not ic or not ic.is_connected():
            return
        now = time.monotonic()
        if (now - self._last_filter_apply_ts) < max(5.0, float(self.filter_min_gap_secs)):
            return
        heartbeat_due = now >= self._next_filter_heartbeat
        if not self._filter_dirty and not heartbeat_due:
            return

        toks = self._compute_filter_tokens()
        sig  = " ".join(sorted(toks))
        if not self._filter_dirty and heartbeat_due and sig == self._last_filter_sig:
            self._next_filter_heartbeat = now + float(self.filter_heartbeat_secs)
            return

        flt = " ".join(toks)
        sent = False
        # Try raw socket first
        try:
            sock = getattr(ic, "sock", None)
            if sock and callable(getattr(sock, "sendall", None)):
                sock.sendall(f"filter {flt}\n".encode("utf-8", "ignore"))
                self.logger.info("APRS-IS combined filter sent (%d tokens)", len(toks))
                sent = True
        except Exception as e:
            self.logger.warning("Socket filter send failed: %s", e)
        # Fallback to client APIs
        if not sent:
            for meth in ("set_filter", "send_filter"):
                try:
                    fn = getattr(ic, meth, None)
                    if callable(fn):
                        fn(flt)
                        self.logger.info("APRS-IS combined filter applied via %s", meth)
                        sent = True
                        break
                except Exception as e:
                    self.logger.warning("%s failed: %s", meth, e)
        if not sent:
            # As last resort, stash on attribute
            try:
                setattr(ic, "filter", flt if not getattr(ic, "filter", "") else (ic.filter + " " + flt))
                self.logger.info("APRS-IS filter recorded on client.filter")
            except Exception:
                pass

        self._last_filter_apply_ts = now
        self._last_filter_sig = sig
        self._filter_dirty = False
        self._next_filter_heartbeat = now + float(self.filter_heartbeat_secs)

    # ---- Outbound ----
    def _choose_tx_path(self, to_call: str) -> str:
        if self.last_heard_via_rf_recent(to_call) and self.clients.get("rf") and self.clients["rf"].is_connected():
            return "rf"
        if self.clients.get("aprsis") and self.clients["aprsis"].is_connected():
            return "aprsis"
        if self.clients.get("rf") and self.clients["rf"].is_connected():
            return "rf"
        return ""

    def _send_text(self, to_call: str, payload: str) -> bool:
        # pacing global
        gap = time.monotonic() - self._last_any_send_ts
        if gap < float(self.delay_send_sec):
            time.sleep(float(self.delay_send_sec) - gap)
        self._last_any_send_ts = time.monotonic()
        # per-dest gap
        last_ts = self._last_send_ts.get(to_call, 0.0)
        now = time.monotonic()
        if now - last_ts < float(self.per_dest_gap_sec):
            time.sleep(float(self.per_dest_gap_sec) - (now - last_ts))
        self._last_send_ts[to_call] = time.monotonic()
        
        if ("{" in payload) and not MSGID_TAIL_RE.search(payload):
            self.logger.error("Refusing malformed tail: %r", payload[-64:])
            self.handler._log_audit("send", self.my_callsign, to_call, payload,
                                   rejected=True, note="Malformed msgid tail", transport="NONE")
            return False
        
        frame = self.handler.make_aprs_msg(to_call, payload)
        path = self._choose_tx_path(to_call)
        if not path:
            self.logger.error("No TX path available for %s", to_call)
            self.handler._log_audit("send", self.my_callsign, to_call, payload,
                                   rejected=True, note="No TX path available", transport="NONE")
            return False
        
        client = self.clients.get(path)
        try:
            if client and client.is_connected():
                client.enqueue_frame(frame)
                transport = "RF" if path == "rf" else "APRS-IS"
                self.logger.info("TX [%s]: %s -> %s", transport, to_call, payload)
                # Extract msgid from payload for audit log
                msgid_match = re.search(r'\{([A-Za-z0-9]{1,5})', payload)
                msgid = msgid_match.group(1) if msgid_match else None
                self.handler._log_audit("send", self.my_callsign, to_call, payload,
                                       msgid=msgid, rejected=False, transport=transport)
                return True
        except Exception as e:
            self.logger.error("Send error via %s: %s", path, e)
            transport = "RF" if path == "rf" else "APRS-IS"
            self.handler._log_audit("send", self.my_callsign, to_call, payload,
                                   rejected=True, note=f"Send error: {str(e)[:100]}", transport=transport)
        return False
    def _attempts_expr(self) -> str:
        return "MAX(COALESCE(retries,0), COALESCE(retry_count,0))"

    def _last_ts_expr(self) -> str:
        return "COALESCE(last_attempt_ts, last_sent, '')"

    def _eligible_pending_for(self, csu: str):
        cur = self.sf_conn.cursor()
        cutoff = (datetime.utcnow() - timedelta(minutes=self.resend_delay_min)).isoformat()
        b = base_call(csu)
        aexpr = self._attempts_expr()
        lexpr = self._last_ts_expr()
        if b == csu:
            params = (csu, self.max_retries, cutoff)
            where_r = "UPPER(recipient)=?"
        else:
            params = (csu, b, self.max_retries, cutoff)
            where_r = "UPPER(recipient) IN (?,?)"
        cur.execute(f"""
            SELECT id, message, msgid,
                   {aexpr} AS tries,
                   {lexpr}  AS last_ts
              FROM message
             WHERE {where_r}
               AND COALESCE(ack,0)=0
               AND {aexpr} < ?
               AND ({lexpr} IS NULL OR {lexpr}='' OR {lexpr} < ?)
             ORDER BY id ASC
        """, params)
        return cur.fetchall()

    def _record_attempt_log(self, row_id: int, ok: bool, is_retry: bool, error: str = ""):
        try:
            if not ok and error:
                self.sf_conn.execute("UPDATE message SET last_error=? WHERE id=?", (error[:200], row_id))
                self.sf_conn.commit()
        except Exception:
            pass
        try:
            cur = self.sf_conn.cursor()
            cur.execute("SELECT COALESCE(retries,0), COALESCE(retry_count,0), last_sent, last_attempt_ts FROM message WHERE id=?",(row_id,))
            r, rc, ls, la = cur.fetchone() or (None, None, None, None)
            self.logger.info("message %d: %s; ok=%s (retries=%s retry_count=%s last_sent=%s last_attempt_ts=%s)",
                             row_id, ("retry" if is_retry else "first-send"), ok, r, rc, ls, la)
        except Exception:
            pass

    def process_resends_for(self, csu: str):
        if not self.sf_enabled: # ADD THIS CHECK
            self.logger.info("SF OFF: Skipping triggered resend for %s", csu)
            return
        rows = self._eligible_pending_for(csu)
        if not rows:
            return
        self.logger.info("Resend trigger: %s has %d eligible message(s)", csu, len(rows))
        for row_id, message, msgid, tries, last_ts in rows:
            is_retry = bool(last_ts and str(last_ts).strip())
            if is_retry: mark_resend(self.sf_conn, row_id)
            else:        mark_first_send(self.sf_conn, row_id)
            payload = build_payload_strict(message, msgid or "")
            ok = self._send_text(csu, payload)
            self._record_attempt_log(row_id, ok, is_retry, error=("enqueue failed" if not ok else ""))

    # ---- ACK handling (tolerant) ----
    def on_ack_received(self, from_callsign: str, msgid: str):
        a = sanitize_msgid(msgid)
        if not a: return
        src = norm_cs(from_callsign); b = base_call(src)
        cur = self.sf_conn.cursor()
        # Try recipient-scope recent rows
        try:
            cur.execute("""
                SELECT id, msgid FROM message
                 WHERE COALESCE(ack,0)=0
                   AND UPPER(recipient) IN (?,?)
                 ORDER BY id DESC LIMIT 800
            """, (src, b))
            rows = cur.fetchall()
        except Exception:
            rows = []
        for row_id, mid in rows:
            if sanitize_msgid(mid or "") == a:
                cur.execute("UPDATE message SET ack=1 WHERE id=?", (row_id,))
                self.sf_conn.commit()
                self.logger.info("ACK matched(recipient exact): %s -> id %s", a, row_id)
                return
        # Fuzzy fallbacks
        def _score(x: str) -> int:
            X = sanitize_msgid(x or "")
            if not X or not a: return 0
            if X == a: return 100
            if X.endswith(a) and len(a) >= 2: return 90
            if X.startswith(a) and len(a) >= 2: return 85
            t = "".join(ch for ch in X if ch.isdigit())
            return 80 if len(a) >= 2 and a == (t[-3:] if len(t) >= 3 else t) else 0
        best = None; bestmid=None; sc=0
        for row_id, mid in rows:
            s=_score(mid or "")
            if s>sc: sc, best, bestmid = s, row_id, mid
        if best is not None and sc >= 60:
            cur.execute("UPDATE message SET ack=1 WHERE id=?", (best,))
            self.sf_conn.commit()
            self.logger.info("ACK matched(recipient fuzzy): %s -> id %s (mid=%s score=%s)", a, best, bestmid, sc)
            return
        # Global exact
        try:
            cur.execute("""
                SELECT id, msgid, recipient FROM message
                 WHERE COALESCE(ack,0)=0
                 ORDER BY id DESC LIMIT 1500
            """)
            grows = cur.fetchall()
        except Exception:
            grows = []
        for row_id, mid, recip in grows:
            if sanitize_msgid(mid or "") == a:
                cur.execute("UPDATE message SET ack=1 WHERE id=?", (row_id,))
                self.sf_conn.commit()
                self.logger.info("ACK matched(global exact): %s -> id %s recip=%s", a, row_id, recip)
                return

    # ---- Bulk resend clock ----
    def _next_h_utc_epoch(self, hours: int, start_epoch: Optional[float] = None) -> int:
        if start_epoch is None: start_epoch = time.time()
        t = datetime.utcfromtimestamp(start_epoch)
        block = (t.hour // hours) * hours
        start = datetime(t.year, t.month, t.day, block)
        nxt = start + timedelta(hours=hours)
        return int(nxt.timestamp())

    def _schedule_next_bulk_from(self, ref_epoch: Optional[float] = None):
        h = self.resend_clock_hours or 6
        self._next_bulk_resend = self._next_h_utc_epoch(h, ref_epoch)
        self.logger.info("Bulk sweep (%dh) scheduled at %sZ", h, datetime.utcfromtimestamp(self._next_bulk_resend).isoformat())

    def process_bulk_resend(self):
        if not self.sf_enabled:
            # CORRECTED LOG MESSAGE:
            self.logger.info("SF OFF: Skipping bulk resend sweep.") 
            return
        self.logger.info("Starting bulk resend sweep for all recipients")
        cur = self.sf_conn.cursor()
        cur.execute("SELECT DISTINCT recipient FROM message WHERE COALESCE(ack,0)=0")
        recips = [norm_cs(r[0]) for r in cur.fetchall() if r and r[0]]
        for csu in recips:
            rows = self._eligible_pending_for(csu)
            if not rows: continue
            self.logger.info("Bulk resend: %s has %d eligible message(s)", csu, len(rows))
            for row_id, message, msgid, tries, last_ts in rows:
                is_retry = bool(last_ts and str(last_ts).strip())
                (mark_resend if is_retry else mark_first_send)(self.sf_conn, row_id)
                payload = build_payload_strict(message, msgid or "")
                ok = self._send_text(csu, payload)
                self._record_attempt_log(row_id, ok, is_retry, error=("enqueue failed" if not ok else ""))

    # ---- Loop ----
    def run(self):
        self.logger.info("Store-Forward service starting (RF + APRS-IS)")
        self._ensure_connected()

        # Optional log tailer
        if self.bot_log_tail and os.path.exists(self.bot_log_tail):
            threading.Thread(
                target=tail_file,
                args=(self.bot_log_tail, self._mark_seen_generic, lambda src, tok: self.on_ack_received(src, tok), self.logger),
                daemon=True
            ).start()

        # Initial bulk catch-up if pending exists
        try:
            cur = self.sf_conn.cursor()
            cur.execute("SELECT 1 FROM message WHERE COALESCE(ack,0)=0 LIMIT 1")
            if cur.fetchone():
                self.logger.info("=== bulk resend START (initial) ===")
                self.process_bulk_resend()
                self._last_bulk_run_ts = time.time()
                self._schedule_next_bulk_from(self._last_bulk_run_ts)
                self.logger.info("=== bulk resend END   (initial) ===")
            else:
                self._schedule_next_bulk_from(time.time())
        except Exception as e:
            self.logger.warning("Initial bulk check failed: %s", e)
            self._schedule_next_bulk_from(time.time())

        watchdog_hours = max(2, int(self.resend_clock_hours) * 2)

        while True:
            # Connectivity
            self._ensure_connected()

            # Pump I/O
            for label, c in self.clients.items():
                try: c.loop()
                except Exception as e: self.logger.error("%s loop err: %s", label, e)

            # Background tasks
            self._refresh_users_if_due()
            self._apply_combined_filter_if_needed()

            # Process seen queue
            try:
                while True:
                    csu = norm_cs(self.seen_queue.get_nowait())
                    if csu:
                        self.process_resends_for(csu)
            except queue.Empty:
                pass

            # Bulk clock
            try:
                now = time.time()
                if now >= self._next_bulk_resend:
                    self.logger.info("=== bulk resend START ===")
                    self.process_bulk_resend()
                    self.logger.info("=== bulk resend END   ===")
                    self._last_bulk_run_ts = now
                    # advance to next boundary (skip if late)
                    while now >= self._next_bulk_resend:
                        self._next_bulk_resend = self._next_h_utc_epoch(self.resend_clock_hours, self._next_bulk_resend + 1)
                    self.logger.info("Next bulk sweep (%dh) at %sZ", self.resend_clock_hours,
                                     datetime.utcfromtimestamp(self._next_bulk_resend).isoformat())
                else:
                    if self._last_bulk_run_ts and (now - self._last_bulk_run_ts > watchdog_hours * 3600):
                        self.logger.warning("Bulk sweep watchdog fired (%dh); forcing run", watchdog_hours)
                        self.process_bulk_resend()
                        self._last_bulk_run_ts = now
                        self._schedule_next_bulk_from(now)
            except Exception as e:
                self.logger.warning("Bulk check failed: %s", e)

            time.sleep(0.5)

# =============================================================================
# Users DB reader
# =============================================================================

def read_users_set(db_path: str) -> set:
    users = set()
    try:
        full = os.path.abspath(db_path)
        if not os.path.exists(full):
            logging.getLogger("storeforward").warning("Users DB not found: %s", full)
            return users
        conn = sqlite3.connect(full, timeout=5.0)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cur.fetchone() is None:
                logging.getLogger("storeforward").warning("Table 'users' not in %s", full)
                return users
            cur.execute("SELECT callsign FROM users WHERE COALESCE(callsign,'')!=''")
            for (cs,) in cur.fetchall():
                users.add(norm_cs(cs))
            logging.getLogger("storeforward").info("Users DB loaded: %d", len(users))
        finally:
            conn.close()
    except Exception as e:
        logging.getLogger("storeforward").error("Users DB read error: %s", e)
    return users

# =============================================================================
# Entrypoint
# =============================================================================

def main():
    svc = StoreForwardService()
    svc.run()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        main()
    except Exception:
        logging.exception("Fatal: Store-Forward crashed; sleeping instead of exiting")
        while True:
            time.sleep(60)
