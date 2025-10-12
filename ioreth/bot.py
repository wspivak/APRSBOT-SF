# ioreth/bot.py
import sys
import time
import logging
import configparser
import os
import re
import random
import sqlite3
import difflib
from datetime import datetime, timedelta
import signal
import threading
import hashlib

from cronex import CronExpression

from .clients import AprsIsClient, RfKissClient
from . import aprs
from . import remotecmd
from . import utils

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# Persistent paths / DBs
# --------------------------------------------------------------------
DEDUP_TTL = 3600  # 60 minutes
DEDUP_DB = "/opt/aprsbot/dedup.db"
SF_DB_PATH = "/opt/aprsbot/store_forward.db"

# Ensure base dirs
os.makedirs("/opt/aprsbot", exist_ok=True)
os.makedirs("/opt/aprsbot/logs", exist_ok=True)

# --------------------------------------------------------------------
# Dedup cache (persistent, autocommit)
# --------------------------------------------------------------------
_dedup_conn = sqlite3.connect(DEDUP_DB, isolation_level=None, check_same_thread=False)
_dedup_conn.execute("""
CREATE TABLE IF NOT EXISTS dedup_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    destination TEXT,
    text TEXT,
    msg_time INTEGER
)
""")

def _is_duplicate(conn, source, dest, text):
    now = int(time.time())
    key = (str(source).strip().lower(), str(dest).strip().lower(), str(text).strip().lower())
    try:
        conn.execute("DELETE FROM dedup_cache WHERE ? - msg_time > ?", (now, DEDUP_TTL))
        cur = conn.execute("SELECT 1 FROM dedup_cache WHERE source=? AND destination=? AND text=?", key)
        if cur.fetchone():
            logger.debug(f"[DEDUP-TRACE] Duplicate hit, key={key}")
            return True
        conn.execute("INSERT INTO dedup_cache (source, destination, text, msg_time) VALUES (?, ?, ?, ?)", (*key, now))
        logger.debug(f"[DEDUP-TRACE] New dedup key inserted: {key}")
        return False
    except Exception as e:
        logger.warning(f"[DEDUP] error: {e}")
        return False

def _is_loopback(_to_call, _message):
    # Rely on dedup + audit
    return False

def _is_br_callsign(callsign):
    return bool(re.match(r"P[PTUY][0-9].+", str(callsign).upper()))

def _classify_transport(via):
    if not via:
        return None
    if isinstance(via, str):
        path_elements = [item.strip().lower() for item in via.split(",")]
    elif isinstance(via, (list, tuple)):
        path_elements = [str(item).strip().lower() for item in via]
    else:
        return None
    aprsis_ids = {"tcpip", "qac", "qas", "qar", "qao", "qax"}
    if any(elem in aprsis_ids or (elem.startswith("q") and len(elem) <= 3) for elem in path_elements):
        return "APRS-IS"
    return "RF"


class BotAprsHandler(aprs.Handler):
    def __init__(self, callsign, client, config_file="aprsbot.conf"):
        super().__init__(callsign)
        self.callsign = callsign
        self._client = client
        self._config_file = config_file

        self.db = None
        self._dbfile = None

        # Commands map (lowercased trigger → canonical command)
        self.KNOWN_COMMANDS = {}

        # Config-derived values
        self.netname = ""
        self.aliases = set()
        self.beacon_message_template = "APRS Bot active"
        self.user_defined_beacon_alias = "NoAlias"

        # Response strings (load from [responses])
        self.netcheckout_response = "NETCheckOUT Successful"
        self.response_store_on = "Store and Forward Turned On"
        self.response_store_off = "Store and Forward Turned Off"
        self.response_welcome_message = ""

        # Will be injected by ReplyBot
        self.clients = {}

        self._load_config()

        if not self._dbfile:
            raise ValueError("Missing 'dbfile' in [aprs] config")
        self.db = sqlite3.connect(self._dbfile, check_same_thread=False)
        self._init_db()

    # ---------------- config / schema ----------------
    def _load_config(self):
        # IMPORTANT: honor inline ';' and '#' comments like your aprsbot.conf
        cfg = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))

        cfg.optionxform = str
        cfg.read(self._config_file)

        self.netname = cfg.get("aprs", "netname").strip().upper()
        self.response_welcome_message = cfg.get("responses", "welcome_message", fallback="").strip()

        # Aliases: include real callsign + configured aliases
        self.aliases = {self.callsign.upper()}
        aliases_from_config = cfg.get("aprs", "aliases", fallback="")
        self.aliases.update(
            alias.strip().strip('"').upper()
            for alias in aliases_from_config.split(",")
            if alias.strip()
        )

        # DB file path (ensure dir exists)
        self._dbfile = cfg.get("aprs", "dbfile", fallback="erli.db").strip()
        db_dir = os.path.dirname(self._dbfile) or "."
        if not os.path.isdir(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        if not os.access(db_dir, os.W_OK):
            raise RuntimeError(f"Cannot write to database directory: {db_dir}")

        # commands
        self.KNOWN_COMMANDS = {}
        if cfg.has_section("commands"):
            for cmd_key, canonical_name in cfg.items("commands"):
                self.KNOWN_COMMANDS[cmd_key.lower()] = canonical_name.strip()
        # ensure essentials
        self.KNOWN_COMMANDS.setdefault("help", "help")
        self.KNOWN_COMMANDS.setdefault("sf-on", "sf-on")
        self.KNOWN_COMMANDS.setdefault("sf-off", "sf-off")
        self.KNOWN_COMMANDS.setdefault("release", "release")

        # beacon text
        self.beacon_message_template = cfg.get("aprs", "beacon_message", fallback="APRS Bot active").strip()
        self.user_defined_beacon_alias = cfg.get("aprs", "beacon_alias", fallback="NoAlias").strip()

        # responses
        self.netcheckout_response = cfg.get("responses", "netcheckout_success", fallback=self.netcheckout_response).strip()
        self.response_store_on = cfg.get("responses", "store_on", fallback=self.response_store_on).strip()
        self.response_store_off = cfg.get("responses", "store_off", fallback=self.response_store_off).strip()

        logger.info(f"Using database file: {self._dbfile}")
        logger.info(f"Loaded commands: {list(self.KNOWN_COMMANDS.keys())}")

    def _init_db(self):
        cur = self.db.cursor()

        # -------- PRAGMAs (best effort) --------
        for pragma_sql, label in [
            ("PRAGMA journal_mode = WAL;", "journal_mode=WAL"),
            ("PRAGMA synchronous = NORMAL;", "synchronous=NORMAL"),
            ("PRAGMA temp_store = MEMORY;", "temp_store=MEMORY"),
            ("PRAGMA mmap_size = 67108864;", "mmap_size=64MiB"),
        ]:
            try:
                cur.execute(pragma_sql)
            except Exception as e:
                logger.warning(f"[DB] PRAGMA {label} failed: {e}")

        # -------- Helpers --------
        def _table_exists(name: str) -> bool:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (name,))
            return cur.fetchone() is not None

        def _col_exists(table: str, col: str) -> bool:
            try:
                cur.execute(f"PRAGMA table_info('{table}');")
                return any(row[1].lower() == col.lower() for row in cur.fetchall())
            except Exception as e:
                logger.error(f"[DB] Failed PRAGMA table_info('{table}'): {e}")
                return False

        # -------- Create base tables (idempotent) --------
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    callsign   TEXT PRIMARY KEY,
                    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
                    SF         INTEGER NOT NULL DEFAULT 1
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    callsign TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    callsign TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
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
            self.db.commit()
        except Exception as e:
            logger.exception("[DB] Table creation failed")
            self.db.rollback()
            raise

        # -------- Migrate existing audit_log missing 'ts' --------
        try:
            if _table_exists("audit_log") and not _col_exists("audit_log", "ts"):
                logger.info("[DB] Migrating audit_log: adding 'ts' column")
                cur.execute("ALTER TABLE audit_log ADD COLUMN ts DATETIME;")
                if _col_exists("audit_log", "timestamp"):
                    logger.info("[DB] Backfilling audit_log.ts from legacy 'timestamp'")
                    cur.execute("UPDATE audit_log SET ts = timestamp WHERE ts IS NULL;")
                else:
                    logger.info("[DB] Initializing audit_log.ts with CURRENT_TIMESTAMP")
                    cur.execute("UPDATE audit_log SET ts = COALESCE(ts, CURRENT_TIMESTAMP);")
                self.db.commit()
        except Exception as e:
            logger.exception("[DB] audit_log migration failed")
            self.db.rollback()
            raise

        # -------- Indexes --------
        try:
            if _table_exists("users"):
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_callsign ON users (callsign);")
            if _table_exists("blacklist"):
                cur.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_callsign ON blacklist (callsign);")
            if _table_exists("audit_log"):
                if _col_exists("audit_log", "ts"):
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);")
                elif _col_exists("audit_log", "timestamp"):
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts_legacy ON audit_log (timestamp);")
            self.db.commit()
        except Exception as e:
            logger.exception("[DB] Index creation failed")
            self.db.rollback()
            raise

        # -------- ANALYZE (optional) --------
        try:
            cur.execute("ANALYZE;")
            self.db.commit()
        except Exception as e:
            logger.warning(f"[DB] ANALYZE failed (non-fatal): {e}")

        # Version log
        try:
            cur.execute("SELECT sqlite_version();")
            ver = cur.fetchone()
            logger.info(f"[DB] SQLite version: {ver[0] if ver else 'unknown'}")
        except Exception:
            pass

    # ---------------- small DB helpers ----------------
    def exec_db(self, query, args=()):
        try:
            cur = self.db.cursor()
            cur.execute(query, args)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error: {e}")

    def _log_audit(self, direction, source, destination, message, msgid=None, rejected=False, note=None, transport=None):
        try:
            cur = self.db.cursor()
            cur.execute("""
                INSERT INTO audit_log (direction, source, destination, message, msgid, rejected, note, transport)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (direction, source, destination, message, msgid, int(rejected), note, transport))
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def is_admin(self, callsign):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM admins WHERE callsign = ?", (callsign.upper(),))
        return cur.fetchone() is not None

    def sanitize_text(self, text):
        text = re.sub(r"\{\d+\}$", "", text.strip())
        return re.sub(r"\s+", " ", text)

    def is_blacklisted(self, callsign):
        normalized = callsign.strip().lower().replace("*", "")
        base_callsign = normalized.split("-")[0]
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM blacklist WHERE callsign = ?", (base_callsign,))
        return cur.fetchone() is not None

    def detect_and_correct_command(self, input_qry: str) -> str:
        try:
            triggers = list(self.KNOWN_COMMANDS.keys())
            matches = difflib.get_close_matches(input_qry, triggers, n=1, cutoff=0.8)
            if matches:
                return self.KNOWN_COMMANDS[matches[0]]
            return input_qry
        except Exception as e:
            logger.debug(f"[CMD] detect_and_correct_command error: {e}")
            return input_qry

    def detect_typo_command(self, qry: str):
        try:
            triggers = list(self.KNOWN_COMMANDS.keys())
            matches = difflib.get_close_matches(qry, triggers, n=1, cutoff=0.8)
            return matches[0] if matches else None
        except Exception as e:
            logger.debug(f"[CMD] detect_typo_command error: {e}")
            return None

    # ---------------- SF helpers ----------------
    def set_sf_flag(self, callsign, flag):
        cs = callsign.strip().upper().split("-")[0]
        flag = 1 if int(flag) == 1 else 0
        cur = self.db.cursor()
        cur.execute("""
            INSERT INTO users (callsign, SF)
            VALUES (?, ?)
            ON CONFLICT(callsign) DO UPDATE SET SF=excluded.SF
        """, (cs, flag))
        self.db.commit()
        logger.info(f"[SF] Set users.SF={flag} for {cs}")

    def get_sf_flag(self, callsign):
        cs = callsign.strip().upper().split("-")[0]
        cur = self.db.cursor()
        cur.execute("SELECT SF FROM users WHERE callsign = ?", (cs,))
        row = cur.fetchone()
        return 1 if row is None else (1 if int(row[0]) == 1 else 0)

    # ---------------- inbound path ----------------
    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        clean_source_l = str(source).replace("*", "").strip().lower()
        addressee_u = re.sub(r"\s+", "", str(addressee).strip().upper())
        cleaned_text_l = str(text).strip().lower()

        # De-dup
        if _is_duplicate(_dedup_conn, clean_source_l, addressee_u.lower(), cleaned_text_l):
            logger.info(f"[DEDUP] Duplicate suppressed: {clean_source_l}->{addressee_u}: '{cleaned_text_l}'")
            return

        logger.debug(f"[DEDUP-TRACE] Checking key: ({clean_source_l}, {addressee_u.lower()}, {cleaned_text_l})")
        logger.info(f"Sanitized text: '{cleaned_text_l}'")

        audit_source = source.replace("*", "").strip()
        audit_addressee = addressee_u
        audit_message = text.strip()

        # Loopback
        if _is_loopback(source, text):
            if addressee_u in self.aliases:
                logger.debug(f"Allowing looped-back message to alias {addressee_u}")
            else:
                logger.warning(f"Ignoring loopback message from {source} to {addressee_u}: {text}")
                self._log_audit(
                    direction="recv",
                    source=audit_source,
                    destination=audit_addressee,
                    message=audit_message,
                    msgid=msgid,
                    rejected=True,
                    note="Loopback detected and rejected",
                    transport=_classify_transport(via) if via else "RF"
                )
                return

        # Alias filtering
        logger.info(f"Checking if addressee '{addressee_u}' is in aliases: {self.aliases}")
        if addressee_u not in self.aliases:
            logger.warning(f"Ignoring message to {addressee_u} — not in aliases.")
            self._log_audit(
                direction="recv",
                source=audit_source,
                destination=audit_addressee,
                message=audit_message,
                msgid=msgid,
                rejected=True,
                note="Addressee not in aliases",
                transport=_classify_transport(via) if via else "RF"
            )
            return

        # Blacklist (direct)
        if self.is_blacklisted(clean_source_l):
            logger.info(f"Ignoring message from blacklisted callsign: {clean_source_l}")
            self._log_audit(
                direction="recv",
                source=audit_source,
                destination=audit_addressee,
                message=audit_message,
                msgid=msgid,
                rejected=True,
                note="Blacklisted direct source",
                transport=_classify_transport(via) if via else "RF"
            )
            return

        # Blacklist (encapsulated)
        if "}" in text:
            try:
                payload = text.split("}", 1)[1]
                if ">" in payload and ":" in payload:
                    encaps_src, _rest = payload.split(">", 1)
                    if self.is_blacklisted(encaps_src.strip().lower()):
                        logger.info(f"Ignoring encapsulated message from blacklisted callsign: {encaps_src}")
                        self._log_audit(
                            direction="recv",
                            source=encaps_src.strip(),
                            destination=audit_addressee,
                            message=audit_message,
                            msgid=msgid,
                            rejected=True,
                            note="Blacklisted encapsulated source",
                            transport=_classify_transport(via) if via else "RF"
                        )
                        return
            except Exception as e:
                logger.warning(f"Could not parse encapsulated frame: {e}")

        # Main processing
        was_command_handled = self.handle_aprs_query(
            audit_source,
            audit_message,
            origframe=origframe,
            via=via,
            dest=addressee_u
        )

        # Ack if msgid present
        if msgid:
            logger.info(f"Sending ack to message {msgid} from {audit_source}")
            self.send_aprs_msg(audit_source, f"ack{msgid}", is_ack=True)

        # Audit
        self._log_audit(
            direction="recv",
            source=audit_source,
            destination=audit_addressee,
            message=audit_message,
            msgid=msgid,
            rejected=False,
            note=f"Received and processed. Command handled: {was_command_handled}",
            transport=_classify_transport(via) if via else "RF"
        )

    def handle_aprs_query(self, source, text, origframe, via=None, dest=None):
        logger.info(f"handle_aprs_query text from {source}: '{text}'")

        clean_source = source.replace("*", "")
        text = self.sanitize_text(text).strip()
        parts = text.split(" ", 1)
        qry = parts[0]
        args = parts[1] if len(parts) == 2 else ""

        qry_lower = qry.lower()
        corrected_qry = self.detect_and_correct_command(qry_lower)

        # Choose command
        if corrected_qry != qry_lower and corrected_qry in self.KNOWN_COMMANDS.values():
            actual = corrected_qry
        elif qry_lower in self.KNOWN_COMMANDS:
            actual = self.KNOWN_COMMANDS[qry_lower]
        else:
            # Unknown: suppress intro if addressed to NET alias
            if dest and dest in self.aliases:
                logger.info(f"[UX] Unknown/typo command '{qry}' to net alias '{dest}' — suppressing bot intro.")
                return False
            if _is_br_callsign(clean_source):
                self.send_aprs_msg(clean_source, "Sou um bot. Envie 'help' para a lista de comandos")
            else:
                self.send_aprs_msg(clean_source, "I'm a bot. Send 'help' for command list or see http://sbanetweb.com:8080")
            return False

        # Built-ins
        if actual == "help":
            display = sorted(list(set(self.KNOWN_COMMANDS.keys())))
            self.send_aprs_msg(clean_source, "Commands: " + ", ".join(display))
            return True

        if actual == "ping":
            self.send_aprs_msg(clean_source, "Pong! " + args)
            return True

        if actual in ["?aprst", "?ping?"]:
            try:
                frame_str = origframe.to_aprs_string().decode("utf-8", errors="replace")
                self.send_aprs_msg(clean_source, frame_str.split("::", 2)[0] + ":")
                return True
            except Exception as e:
                logger.error("Error responding to ?aprst: %s", e)
                return False

        if actual == "version":
            self.send_aprs_msg(clean_source, "Python " + sys.version.replace("\n", " "))
            return True

        if actual == "time":
            self.send_aprs_msg(clean_source, "Localtime is " + time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"))
            return True
            
            
# Weather forecast command
        if actual in ["wx", "weather", "forecast"]:
            if not args:
                self.send_aprs_msg(clean_source, "Usage: wx <zipcode> or wx <city,state>")
                return True
            
            try:
                # Import weather module (lazy load)
                from .weather import WeatherForecast
                
                # Get API key from config if available
                api_key = None
                # Re-read config to get weather section
                cfg = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
                cfg.optionxform = str
                cfg.read(self._config_file)
                
                if cfg.has_section("weather"):
                    api_key = cfg.get("weather", "openweathermap_api_key", fallback=None)
                    if api_key:
                        api_key = api_key.strip() or None
                
                # Create weather service and get forecast
                wx_service = WeatherForecast(openweathermap_api_key=api_key)
                forecast = wx_service.get_forecast(args)
                
                self.send_aprs_msg(clean_source, forecast)
                return True
                
            except ImportError as e:
                logger.error(f"Weather module not found: {e}")
                self.send_aprs_msg(clean_source, "Weather service not available")
                return False
            except Exception as e:
                logger.error(f"Weather command error: {e}", exc_info=True)
                self.send_aprs_msg(clean_source, "Weather service error. Try again later.")
                return False
                
                
        if actual.lower() == "netusers":
            cur = self.db.cursor()
            cur.execute("SELECT callsign FROM users ORDER BY timestamp DESC LIMIT 10")
            rows = cur.fetchall()
            self.send_aprs_msg(clean_source, ("Last 10 users: " + ", ".join(r[0] for r in rows)) if rows else "No users found.")
            return True

        # CQ (requires netname prefix)
        if actual == "cq" and args.upper().startswith(self.netname.upper()):
            mtxt = f"{actual} {args}"
            m = re.match(rf"^{re.escape(actual)}\s+{re.escape(self.netname)}\s+(.+)", mtxt, re.IGNORECASE)
            if m:
                msg_text = m.group(1).strip()
                self._broadcast_to_net(clean_source, msg_text)

                welcome_msg = (self.response_welcome_message or "").strip()
                if welcome_msg:
                    # allow {netname} macro like in your conf
                    try:
                        welcome_msg = welcome_msg.format(netname=self.netname)
                    except Exception:
                        pass
                    self.send_aprs_msg(clean_source, welcome_msg)
                    logger.info(f"[CQ] Sent welcome message to {clean_source}")
                return True
            return False

        # NETMSG
        if actual == "netmsg":
            cur = self.db.cursor()
            cur.execute("SELECT 1 FROM users WHERE callsign = ?", (clean_source,))
            if not cur.fetchone():
                self._log_audit(
                    direction="recv",
                    source=clean_source,
                    destination=self.callsign,
                    message=text,
                    msgid=None,
                    rejected=True,
                    note="NETMSG attempt by unregistered user",
                    transport=_classify_transport(via) if via else "RF"
                )
                self.send_aprs_msg(clean_source, f"You're not registered on {self.netname}. Send 'CQ {self.netname} <msg>' first.")
                return False

            self._broadcast_message(clean_source, args.strip())
            return True

        # NETCHECKOUT
        if actual == "netcheckout":
            self._remove_user(clean_source)
            return True

        # SF toggles
        if actual == "sf-on":
            self.set_sf_flag(clean_source, 1)
            self.send_aprs_msg(clean_source, self.response_store_on or "Store and Forward Turned On")
            return True

        if actual == "sf-off":
            self.set_sf_flag(clean_source, 0)
            self.send_aprs_msg(clean_source, self.response_store_off or "Store and Forward Turned Off")
            return True

        # Admin list mgmt
        if actual in ["blacklist_add", "blacklist_del", "admin_add", "admin_del"] and args:
            if not self.is_admin(clean_source):
                self.send_aprs_msg(clean_source, "Admin privileges required for this command.")
                self._log_audit(
                    direction="recv",
                    source=clean_source,
                    destination=self.callsign,
                    message=text,
                    msgid=None,
                    rejected=True,
                    note=f"Unauthorized attempt to '{actual}' by non-admin",
                    transport=_classify_transport(via) if via else "RF"
                )
                return False

            if actual == "blacklist_add":
                self.exec_db("INSERT OR IGNORE INTO blacklist (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} has been blacklisted.")
                return True
            if actual == "blacklist_del":
                self.exec_db("DELETE FROM blacklist WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from blacklist.")
                return True
            if actual == "admin_add":
                self.exec_db("INSERT OR IGNORE INTO admins (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} is now an admin.")
                return True
            if actual == "admin_del":
                self.exec_db("DELETE FROM admins WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from admins.")
                return True
        
                return False


        # RELEASE command - force immediate resend of stored messages
        if actual == "release":
            cur = self.db.cursor()
            cur.execute("SELECT 1 FROM users WHERE callsign = ?", (clean_source,))
            if not cur.fetchone():
                self.send_aprs_msg(clean_source, f"You're not registered on {self.netname}. Send 'CQ {self.netname} <msg>' first.")
                self._log_audit(
                    direction="recv",
                    source=clean_source,
                    destination=self.callsign,
                    message=text,
                    msgid=None,
                    rejected=True,
                    note="RELEASE attempt by unregistered user",
                    transport=_classify_transport(via) if via else "RF"
                )
                return False
            
            # Trigger immediate resend by updating store_forward.db timestamps
            try:
                self._ensure_sf_table()
                sf_conn = sqlite3.connect(SF_DB_PATH)
                sf_cur = sf_conn.cursor()
                
                # Count pending messages for this user
                sf_cur.execute("""
                    SELECT COUNT(*) FROM message 
                    WHERE UPPER(recipient) = ? 
                    AND COALESCE(ack, 0) = 0
                """, (clean_source.upper(),))
                count = sf_cur.fetchone()[0]
                
                if count == 0:
                    self.send_aprs_msg(clean_source, "No stored messages pending.")
                    sf_conn.close()
                    return True
                
                # Reset last_attempt_ts to force immediate eligibility
                # Set to a timestamp old enough to bypass resend_delay
                old_timestamp = (datetime.utcnow() - timedelta(hours=24)).isoformat()
                sf_cur.execute("""
                    UPDATE message 
                    SET last_attempt_ts = ?
                    WHERE UPPER(recipient) = ? 
                    AND COALESCE(ack, 0) = 0
                """, (old_timestamp, clean_source.upper()))
                sf_conn.commit()
                sf_conn.close()
                
                self.send_aprs_msg(clean_source, f"Release: {count} message(s) queued for immediate delivery.")
                logger.info(f"[RELEASE] {clean_source} triggered resend of {count} message(s)")
                
                self._log_audit(
                    direction="recv",
                    source=clean_source,
                    destination=self.callsign,
                    message=text,
                    msgid=None,
                    rejected=False,
                    note=f"RELEASE command: {count} messages queued",
                    transport=_classify_transport(via) if via else "RF"
                )
                return True
                
            except Exception as e:
                logger.error(f"[RELEASE] Failed for {clean_source}: {e}")
                self.send_aprs_msg(clean_source, "Release failed. Try again later.")
                return False
                
    # ---------------- outbound helpers ----------------
    def beacon_as_botnet(self, text=None):
        if text is None:
            text = f"{self.netname} tactical alias active"
        original_callsign = self.callsign
        self.callsign = self.netname
        frame = self.make_aprs_status(text)
        for label, client in self.clients.items():
            if client.is_connected():
                client.enqueue_frame(frame)
                logger.info(f"Beaconed as {self.netname} via {label}: {text}")
        self.callsign = original_callsign

    def _broadcast_to_net(self, source, payload):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM users WHERE callsign = ?", (source,))
        if not cur.fetchone():
            cur.execute("INSERT INTO users (callsign) VALUES (?)", (source,))
            logger.info(f"Added {source} to {self.netname} heard list")
        self.db.commit()

        cur.execute("SELECT callsign FROM users")
        for (cs,) in cur.fetchall():
            msg = f"<{source}> {payload}"
            self.send_aprs_msg(cs, msg, is_ack=False)

    def send_aprs_status(self, status):
        frame = self.make_aprs_status(status)
        for label, client in self.clients.items():
            if client.is_connected():
                client.enqueue_frame(frame)
                logger.info(f"Status frame sent via {label}: {status}")
        self.send_aprs_msg("APRS", f">The {self.netname} Net is active at {self.callsign}.", is_ack=False)

    def _rf_client(self):
        c = self.clients.get("rf")
        return c if (c and c.is_connected()) else None

    def _broadcast_message(self, source, message):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM users WHERE callsign = ?", (source,))
        is_registered = cur.fetchone()

        stripped = re.sub(r"^(NETMSG|MSG)\s*", "", message.strip(), flags=re.IGNORECASE)
        base_msg = f"<{source}> {stripped}" if is_registered else stripped

        # APRS-compliant 1..5 char ID
        msgid = self._new_msgid(5)
        full_msg = f"{base_msg}{{{msgid}}}"

        cur.execute("SELECT callsign FROM users")
        for (cs,) in cur.fetchall():
            self.send_aprs_msg(cs, full_msg, is_ack=False)
            self._log_audit("sent", self.callsign, cs, full_msg, msgid, False, None, "RF+IS")
            logger.info(f"Broadcast from {source} to {cs}: {full_msg}")

    def _remove_user(self, source):
        self.db.cursor().execute("DELETE FROM users WHERE callsign = ?", (source,))
        self.db.commit()
        logger.info(f"Removed {source} from {self.netname}")
        self.send_aprs_msg(source, self.netcheckout_response, is_ack=False)

    def _ensure_sf_table(self):
        try:
            sf_conn = sqlite3.connect(SF_DB_PATH)
            sf_cur = sf_conn.cursor()
            sf_cur.execute("""
                CREATE TABLE IF NOT EXISTS message (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient TEXT,
                    timestamp DATETIME,
                    message TEXT,
                    msgid TEXT,
                    ack INTEGER DEFAULT 0
                )
            """)
            sf_conn.commit()
            sf_conn.close()
        except Exception as e:
            logger.error(f"[SF] Failed ensuring store_forward table: {e}")

    def _new_msgid(self, length: int = 5) -> str:
        import random as _r
        length = max(1, min(5, int(length)))
        n = _r.getrandbits(30)
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        out = ""
        while n:
            n, r = divmod(n, 36)
            out = digits[r] + out
        if not out:
            out = "0"
        return out[-length:].rjust(length, "0")

    def send_aprs_msg(self, to_call, text, is_ack=False):
        frame = self.make_aprs_msg(to_call, text)

        transports_used = []
        # Try RF first so the radio actually transmits
        rf = self._rf_client()
        if rf:
            try:
                rf.enqueue_frame(frame)
                transports_used.append("RF")
                logger.info(f"Sent via rf: {to_call} -> {text}")
            except Exception as e:
                logger.error(f"RF enqueue failed, will try other clients: {e}")

        # If no RF (or RF failed), fall back to others (APRS-IS)
        if not transports_used:
            for label, client in self.clients.items():
                try:
                    if client.is_connected():
                        client.enqueue_frame(frame)
                        transports_used.append("RF" if label.lower() == "rf" else "APRS-IS")
                        logger.info(f"Sent via {label}: {to_call} -> {text}")
                except Exception as e:
                    logger.error(f"{label} enqueue error: {e}")

        if not is_ack and transports_used:
            transport = "+".join(sorted(set(transports_used)))

            mid_match = re.search(r"\{([A-Za-z0-9]{1,5})\}", text)
            msgid = mid_match.group(1) if mid_match else ""
            clean_text = re.sub(r"\{.*?\}", "", text).strip()

            # 🚫 Do not inject bulletins or system/general addressees into store_forward.db
            sys_dests = {"APRS", "MAIL", "WX", "BLN"}  # base set
            if (
                to_call.upper() in sys_dests
                or to_call.upper().startswith("BLN")   # BLN1..BLN9 etc
                or to_call.upper().startswith("NWS")   # weather bulletins
                or to_call.upper().startswith("WX")    # weather
            ):
                logger.info(f"[SF] Skipping store_forward insert for {to_call} (system/general)")
                self._log_audit("sent", self.callsign, to_call, text, msgid, False, None, transport)
                return
        
        
            # Store&Forward only if recipient’s SF=1 (default ON)
            try:
                sf_allowed = (self.get_sf_flag(to_call) == 1)
            except Exception as e:
                logger.error(f"[SF] Failed to read users.SF for {to_call}: {e}")
                sf_allowed = True

            if sf_allowed:
                try:
                    self._ensure_sf_table()
                    sf_conn = sqlite3.connect(SF_DB_PATH)
                    sf_cur = sf_conn.cursor()
                    timestamp = datetime.utcnow().isoformat()
                    sf_cur.execute("""
                        INSERT INTO message (recipient, timestamp, message, msgid, ack)
                        VALUES (?, ?, ?, ?, 0)
                    """, (to_call, timestamp, clean_text, msgid))
                    sf_conn.commit()
                    sf_conn.close()
                    logger.info(f"[SF] Inserted message into store_forward.db for {to_call} (msgid={msgid})")
                except Exception as e:
                    logger.error(f"[SF] Failed to insert into store_forward.db for {to_call}: {e}")
            else:
                logger.info(f"[SF] Skipping store_forward insert for {to_call}: users.SF=0")

            self._log_audit("sent", self.callsign, to_call, text, msgid, False, None, transport)


class SystemStatusCommand(remotecmd.BaseRemoteCommand):
    def __init__(self, cfg):
        super().__init__("system-status")
        self._cfg = cfg
        self.status_str = ""

    def run(self):
        net_status = (
            self._check_host_scope("Eth", "eth_host")
            + self._check_host_scope("Inet", "inet_host")
            + self._check_host_scope("DNS", "dns_host")
            + self._check_host_scope("VPN", "vpn_host")
        )
        self.status_str = "At %s: Uptime %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"),
            utils.human_time_interval(utils.get_uptime()),
        )
        if len(net_status) > 0:
            self.status_str += "," + net_status

    def _check_host_scope(self, label, cfg_key):
        if cfg_key not in self._cfg:
            return ""
        ret = utils.simple_ping(self._cfg[cfg_key])
        return " " + label + (":Ok" if ret else ":Err")



class ReplyBot:
    """
    Public surface used by your launcher:
      b = ReplyBot("/opt/aprsbot/aprsbot.conf")
      while True: b.on_loop_hook(); time.sleep(1)
    """
    def __init__(self, config_file):
        self._config_file = config_file

        # ✅ always create the parser on self._cfg
        self._cfg = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
        self._cfg.optionxform = str
        self._cfg.read(self._config_file)

        # Pick callsign from config
        if self._cfg.has_section("aprs"):
            callsign_from_cfg = self._cfg["aprs"].get("callsign", "N0CALL").strip()
        else:
            logger.warning("[aprs] section missing in config — defaulting to N0CALL")
            callsign_from_cfg = "N0CALL"

        # Handler
        self._aprs_handler = BotAprsHandler(callsign_from_cfg, None, config_file=config_file)

        # TNC clients dictionary shared with handler
        self.clients = {}
        self._aprs_handler.clients = self.clients

        # Load and connect clients
        self._load_clients()
        for label, client in self.clients.items():
            try:
                client.connect()
                logger.info("%s client connected: %s", label, client.is_connected())
            except Exception as e:
                logger.error("%s client failed to connect: %s", label, e)

        # Init runtime state
        self._last_blns = time.monotonic()
        self._last_cron_blns = 0
        self._last_status = time.monotonic()
        self._last_reconnect_attempt = 0
        self._rem = remotecmd.RemoteCommandHandler()
        self._config_mtime = 0.0
        self._config_hash = None
        self._check_updated_config()

    def _load_clients(self):
        """Set up RF and APRS-IS clients and wire their on_recv_frame to handler."""
        # RF
        if self._cfg.has_section("tnc_rf"):
            rf_addr = self._cfg["tnc_rf"]["addr"]
            rf_port = int(self._cfg["tnc_rf"]["port"])
            rf_callsign = self._cfg["aprs"].get("callsign", "RF").strip()

            rf_client = RfKissClient(addr=rf_addr, port=rf_port)
            rf_client.callsign = rf_callsign
            rf_client.on_recv_frame = lambda frame: self._aprs_handler.handle_frame(frame, from_aprsis=False)
            self.clients["rf"] = rf_client
            logger.info("ReplyBot: wired RF client to handler (from_aprsis=False)")

        # APRS-IS
        if self._cfg.has_section("tnc_aprsis"):
            is_addr = self._cfg["tnc_aprsis"]["addr"]
            is_port = int(self._cfg["tnc_aprsis"]["port"])
            callsign = self._cfg["tnc_aprsis"].get("callsign", self._cfg["aprs"].get("callsign", "N0CALL")).strip()
            passcode = self._cfg["tnc_aprsis"].get("passcode", "00000").strip()
            filter_str = self._cfg["tnc_aprsis"].get("filter", "")

            aprsis_client = AprsIsClient(
                addr=is_addr,
                port=is_port,
                callsign=callsign,
                passcode=passcode,
                aprs_filter=filter_str
            )
            aprsis_client.filter = filter_str
            aprsis_client.on_recv_frame = lambda frame: self._aprs_handler.handle_frame(frame, from_aprsis=True)
            self.clients["aprsis"] = aprsis_client
            logger.info("ReplyBot: wired APRS-IS client to handler (from_aprsis=True)")

        logger.info("Loaded RF/APRS-IS client definitions")


    def _check_updated_config(self):
        try:
            mtime = os.stat(self._config_file).st_mtime
        except Exception as exc:
            logger.error(exc)
            return

        def _hash_file(file_path):
            try:
                with open(file_path, "rb") as f:
                    return hashlib.md5(f.read()).hexdigest()
            except Exception as e:
                logger.error(f"Failed to hash config file: {e}")
                return None

        try:
            new_hash = _hash_file(self._config_file)
            if self._config_mtime != mtime and new_hash != self._config_hash:
                self._cfg.read(self._config_file)
                self._load_clients()  # reload client configs
                self._config_mtime = mtime
                self._config_hash = new_hash
                logger.info("Configuration reloaded")
        except Exception as exc:
            logger.error(exc)

    def is_connected(self):
        return any(client.is_connected() for client in self.clients.values())

    def on_connect(self):
        logger.info("Connected")

    def on_disconnect(self):
        logger.warning("Disconnected! Will try again soon...")

    def on_recv_frame(self, frame):
        logger.debug("Received frame object: %s", frame)
        try:
            frame_str = frame.to_aprs_string().decode(errors="replace")
            logger.debug("RECV FRAME: %s", frame_str)
        except Exception as e:
            logger.debug("RECV FRAME (decode err): %s", e)
        self._aprs_handler.handle_frame(frame, from_aprsis=True)

    def _update_bulletins(self):
        if not self._cfg.has_section("bulletins"):
            return
        try:
            max_age = int(self._cfg.get("bulletins", "send_freq", fallback="600"))
        except Exception:
            max_age = 600

        now_mono = time.monotonic()
        now_time = time.time()
        try:
            self._last_blns = float(self._last_blns)
        except Exception:
            self._last_blns = 0.0

        if (now_mono <= (self._last_blns + max_age)) and (now_time <= (self._last_cron_blns + 60)):
            return

        bln_map = {}
        keys = self._cfg.options("bulletins")
        keys.sort()
        std_blns = [k for k in keys if k.startswith("BLN") and len(k) > 3 and "_" not in k]

        time_was_set = time.gmtime().tm_year > 2000

        if time_was_set and now_time > (self._last_cron_blns + 60):
            self._last_cron_blns = 60 * int(now_time / 60.0) + random.randint(0, 30)
            cur_time = time.localtime()
            try:
                utc_offset = int(cur_time.tm_gmtoff) / 3600
            except Exception:
                utc_offset = 0
            ref_time = cur_time[:5]
            for k in keys:
                lst = k.split("_", 3)
                if len(lst) == 3 and lst[0].startswith("BLN") and lst[1] == "rule" and (lst[0] not in std_blns):
                    expr = CronExpression(self._cfg.get("bulletins", k))
                    if expr.check_trigger(ref_time, utc_offset):
                        bln_map[lst[0]] = expr.comment

        if now_mono > (self._last_blns + max_age):
            self._last_blns = now_mono
            for k in std_blns:
                bln_map[k] = self._cfg.get("bulletins", k)

        if bln_map:
            to_send = sorted(list(bln_map.items()))
            for (bln, text) in to_send:
                logger.info("Posting bulletin: %s=%s", bln, text)
                self._aprs_handler.send_aprs_msg(bln, text)

    def _update_status(self):
        if not self._cfg.has_section("status"):
            return
        max_age = self._cfg.getint("status", "send_freq", fallback=600)
        now_mono = time.monotonic()
        try:
            self._last_status = float(self._last_status)
        except Exception:
            self._last_status = 0.0
        if now_mono < (self._last_status + max_age):
            return
        self._last_status = now_mono
        self._rem.post_cmd(SystemStatusCommand(self._cfg["status"]))

    def _check_reconnection(self):
        try:
            self._last_reconnect_attempt = float(self._last_reconnect_attempt)
        except Exception:
            self._last_reconnect_attempt = 0.0
        if time.monotonic() < self._last_reconnect_attempt + 5:
            return
        self._last_reconnect_attempt = time.monotonic()
        for label, client in self.clients.items():
            if not client.is_connected():
                try:
                    logger.info(f"Trying to reconnect {label}")
                    client.connect()
                    logger.info(f"{label} reconnected: {client.is_connected()}")
                except ConnectionRefusedError as e:
                    logger.warning(f"{label} reconnect failed: {e}")
                except Exception as e:
                    logger.error(f"{label} reconnect error: {e}")

    def on_loop_hook(self):
        self._check_updated_config()
        self._check_reconnection()
        self._update_bulletins()
        self._update_status()

        # poll all clients
        for label, client in self.clients.items():
            try:
                client.loop()
            except Exception as e:
                logger.error(f"Error in {label} client.loop(): {e}")

        # periodic netname beacon
        now = time.monotonic()
        if not hasattr(self, "_last_netname_beacon"):
            self._last_netname_beacon = 0
        if now - self._last_netname_beacon > 900:
            self._last_netname_beacon = now
            beacon_text = self._aprs_handler.beacon_message_template.format(
                alias=self._aprs_handler.user_defined_beacon_alias,
                call=self._aprs_handler.callsign
            )
            self._aprs_handler.beacon_as_botnet(beacon_text)

        # remote command completions
        while True:
            rcmd = self._rem.poll_ret()
            if not rcmd:
                break
            self.on_remote_command_result(rcmd)

    def on_remote_command_result(self, cmd):
        logger.debug("ret = %s", cmd)
        if isinstance(cmd, SystemStatusCommand):
            self._aprs_handler.send_aprs_status(cmd.status_str)

    def close(self):
        # close clients and DB cleanly
        for c in list(self.clients.values()):
            try:
                c.close()
            except Exception:
                pass
        try:
            self._aprs_handler.db.close()
        except Exception:
            pass

# ---------- CLI entrypoint ----------
def _run_from_cli():
    import argparse
    parser = argparse.ArgumentParser(prog="ioreth.bot")
    parser.add_argument("config", nargs="?", default="/opt/aprsbot/aprsbot.conf")
    args = parser.parse_args()

    # Fallback logging if none configured by service
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("/opt/aprsbot/logs/replybot.log"),
                logging.StreamHandler(sys.stdout),
            ],
        )

    bot = ReplyBot(args.config)
    logger.info("Bot initialized, entering main loop")

    stop_evt = threading.Event()

    def _graceful(_sig, _frm):
        logger.info("Signal %s received, shutting down...", _sig)
        stop_evt.set()

    # Respond to systemd SIGTERM and Ctrl-C
    signal.signal(signal.SIGTERM, _graceful)
    signal.signal(signal.SIGINT, _graceful)

    try:
        while not stop_evt.is_set():
            bot.on_loop_hook()
            time.sleep(0.5)
    finally:
        bot.close()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    _run_from_cli()
