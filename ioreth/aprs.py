#
# Ioreth - An APRS library and bot
# Modified for logging APRS messages with transport classification
#

import logging

logging.basicConfig()
logger = logging.getLogger(__name__)

from . import ax25

from collections import deque

RECENT_MSG_CACHE = deque(maxlen=400)

def is_duplicate(source, dest, text, msgid):
    key = (
#        str(source).strip().lower(),
        str(dest).strip().lower(),
        str(text).strip().lower()
    )
    logger.debug(f"[DEDUP-TRACE] Checking key: {key}")
    if key in RECENT_MSG_CACHE:
        return True
    RECENT_MSG_CACHE.append(key)
    return False


def classify_transport(via):
    """
    Determine whether a message came via RF or APRS-IS based on the VIA path.

    Arguments:
        via: A string (e.g., "TCPIP,qAR") or a list (e.g., ["TCPIP", "qAR"]).

    Returns:
        'APRS-IS' if the path includes intelligent internet-only digipeaters like 'TCPIP' or 'qAR',
        otherwise 'RF'.
    """
    if not via:
        return "RF"  # Assume RF if no path provided

    # Normalize to a list of lowercase path elements, strip trailing '*'
    if isinstance(via, str):
        path_elements = [v.strip().lower().rstrip('*') for v in via.split(',') if v.strip()]
    elif isinstance(via, (list, tuple)):
        path_elements = [str(v).strip().lower().rstrip('*') for v in via if v]
    else:
        return "RF"

    if not path_elements:
        return "RF"

    aprsis_tags = {"tcpip", "tcpxx", "qac", "qas", "qar", "qao", "qax"}

    if any(part in aprsis_tags or part.startswith("q") for part in path_elements):
        return "APRS-IS"

    return "RF"


class Handler:
    """Handle parsing and generation of APRS packets."""

    DEFAULT_PATH = "WIDE1-1,WIDE2-2"
    DEFAULT_DESTINATION = "PYBOT1"

    def __init__(self, callsign="XX0ABC"):
        self.callsign = callsign
        self.destination = Handler.DEFAULT_DESTINATION
        self.path = Handler.DEFAULT_PATH

    def make_frame(self, data):
        return ax25.Frame(
            ax25.Address.from_string(self.callsign),
            ax25.Address.from_string(self.destination),
            [ax25.Address.from_string(s) for s in self.path.split(",")],
            ax25.APRS_CONTROL_FLD,
            ax25.APRS_PROTOCOL_ID,
            data,
        )

    def make_aprs_msg(self, to_call, text):
        addr_msg = ":" + to_call.ljust(9, " ") + ":" + text
        return self.make_frame(addr_msg.encode("utf-8"))

    def make_aprs_status(self, status):
        return self.make_frame((">" + status).encode("utf-8"))

    def handle_frame(self, frame, from_aprsis=False):
        if frame.info == b"":
            return
    
        source = frame.source.to_string().strip()
        payload = frame.info
        via = None
    
        if payload[0] == ord(b"}"):  # third-party APRS-IS packet
            try:
                third_party_data = frame.info[1:].decode("utf-8", errors="replace")
                logger.debug(f"3rd-party raw: {third_party_data}")
        
                if ">" in third_party_data and ":" in third_party_data:
                    src_digi, data_payload = third_party_data.split(":", 1)
                    source, path = src_digi.split(">", 1)
                    path_parts = path.split(",")
        
                    via = [p.strip().lower().rstrip("*") for p in path_parts if p.strip()]
                    payload = data_payload.encode("utf-8")
                else:
                    logger.warning("Malformed third-party format – missing '>' or ':'")
                    via = ["tcpip"]
        
            except Exception as e:
                logger.warning(f"Exception handling 3rd-party frame: {e}")
                via = ["tcpip"]
        else:
            try:
                path_parts = [str(p) for p in frame.digi]
                via = [p.strip().lower().rstrip("*") for p in path_parts if p.strip()]
                if not via and from_aprsis:
                    via = ["tcpip"]
            except Exception:
                if from_aprsis:
                    via = ["tcpip"]
                else:
                    via = ["rf"]

    
        logger.debug(f"[Parsed] source={source}, via={via}, payload={payload.decode(errors='ignore')[:70]}")
    
        self.on_aprs_packet(frame, source, payload, via)


    def on_aprs_packet(self, origframe, source, payload, via=None):
        if payload == b"":
            self.on_aprs_empty(origframe, source, payload, via)
            return

        data_type = payload[0]

        if data_type == ord(b":"):
            self._handle_aprs_message(origframe, source, payload, via)
        elif data_type == ord(b">"):
            self.on_aprs_status(origframe, source, payload, via)
        elif data_type == ord(b";"):
            self.on_aprs_object(origframe, source, payload, via)
        elif data_type == ord(b")"):
            self.on_aprs_item(origframe, source, payload, via)
        elif data_type == ord(b"?"):
            self.on_aprs_query(origframe, source, payload, via)
        elif data_type == ord(b"<"):
            self.on_aprs_capabilities(origframe, source, payload, via)
        elif data_type == ord(b"!"):
            try:
                self.on_aprs_position_wtr(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Position packet error for {source}: {e}")
        elif data_type == ord(b"@"):
            try:
                self.on_aprs_position_ts_msg(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"TS position packet error for {source}: {e}")
        elif data_type == ord(b"="):
            try:
                self.on_aprs_position_msg(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Position msg packet error for {source}: {e}")
        elif data_type == ord(b"/"):
            try:
                self.on_aprs_position_ts(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Slash position packet error for {source}: {e}")
        elif data_type == ord(b"T"):
            self.on_aprs_telemetry(origframe, source, payload, via)
        elif data_type == ord(b"`"):
            self.on_aprs_mic_e(origframe, source, payload, via)
        elif data_type == ord(b"'"):
            self.on_aprs_old_mic_e(origframe, source, payload, via)
        else:
            self.on_aprs_others(origframe, source, payload, via)

    def _handle_aprs_message(self, origframe, source, payload, via):
        """
        Parses an APRS message (data type ':') and delegates processing.
        Format: :ADDRESSEE: MESSAGE {MSGID}
        """
        try:
            data_str = payload.decode("utf-8", errors="replace")

            # Validate structure
            if not data_str.startswith(":") or ":" not in data_str[1:]:
                logger.warning("Malformed APRS message payload: '%s'", data_str)
                return

            addressee_text = data_str[1:].split(":", 1)
            if len(addressee_text) != 2:
                logger.warning("Bad addressee:text pair in APRS message: %r", addressee_text)
                return

            addressee = addressee_text[0].strip()
            message_part = addressee_text[1]

            # Split optional message ID
            text_msgid = message_part.rsplit("{", 1)
            text = text_msgid[0].strip()
            msgid = text_msgid[1].strip() if len(text_msgid) == 2 else None

            logger.info("Message from %s: %s", source, text)

            # Transport debug logging
            if isinstance(via, list):
                via_str = ','.join(via)
            else:
                via_str = via or "None"

            if msgid:
                logger.debug(f"📩 Parsed message: to={addressee}, msg='{text}', msgid={msgid}, via={via_str}")
            else:
                logger.debug(f"📩 Parsed message: to={addressee}, msg='{text}', via={via_str}")

            self.on_aprs_message(
                source=source,
                addressee=addressee,
                text=text,
                origframe=origframe,
                msgid=msgid,
                via=via
            )

        except Exception as e:
            logger.exception(f"💥 Exception in _handle_aprs_message from {source}: {e}")

    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        """APRS message packet (data type :)"""
        clean_source = source.replace("*", "").strip()
        destination = addressee.upper().strip()
        cleaned_text = text.strip()
        
            # 🟢 DE-DUPLICATION HERE
        if is_duplicate(clean_source, destination, cleaned_text, msgid):
            logger.info(f"[DEDUP] Duplicate message {msgid} from {clean_source} to {destination}, skipping.")
            return
        transport = classify_transport(via) if via else "RF"

        via_str = ','.join(via) if isinstance(via, list) else (via or "None")
        logger.info(f"[AUDIT] {clean_source} → {destination} via={via_str} → transport={transport} | msg='{cleaned_text}'")

        try:
            self._log_audit(
                direction="recv",
                source=clean_source,
                destination=destination,
                # ✅ preserve MSG / CQ prefix
                message=text.strip(),
                msgid=msgid,
                transport=transport
            )
        except Exception as e:
            logger.error(f"Error logging APRS message: {e}")

    # Placeholder methods for other APRS message types,
    # which can be overridden in subclasses as needed.
    def on_aprs_empty(self, origframe, source, payload, via): pass
    def on_aprs_status(self, origframe, source, payload, via=None): pass
    def on_aprs_object(self, origframe, source, payload, via=None): pass
    def on_aprs_item(self, origframe, source, payload, via=None): pass
    def on_aprs_query(self, origframe, source, payload, via=None): pass
    def on_aprs_capabilities(self, origframe, source, payload, via=None): pass
    def on_aprs_position_wtr(self, origframe, source, payload, via=None): pass
    def on_aprs_position_ts_msg(self, origframe, source, payload, via=None): pass
    def on_aprs_position_msg(self, origframe, source, payload, via=None): pass
    def on_aprs_position_ts(self, origframe, source, payload, via=None): pass
    def on_aprs_telemetry(self, origframe, source, payload, via=None): pass
    def on_aprs_mic_e(self, origframe, source, payload, via=None): pass
    def on_aprs_old_mic_e(self, origframe, source, payload, via=None): pass
    def on_aprs_others(self, origframe, source, payload, via=None): pass
