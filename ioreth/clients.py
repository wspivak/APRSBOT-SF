import socket
import logging
from . import ax25

logger = logging.getLogger(__name__)


class BaseClient:
    def __init__(self, addr, port):
        self.addr = addr
        self.port = port
        self.sock = None
        self._connected = False
        self.on_recv_frame = None

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.addr, self.port))
            self.sock.settimeout(None)
            self._connected = True
            logger.info(f"Connected to {self.addr}:{self.port}")

            # APRS-IS specific login and filter logic (moved from original BaseClient.connect)
            # This is handled in AprsIsClient's overridden connect method now.
            # No general login/filter sending here for BaseClient.
            # The AprsIsClient's connect method will call super().connect()
            # and then handle its specific login/filter.

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self._connected = False

    def is_connected(self):
        return self.sock is not None and self._connected and self.sock.fileno() >= 0

    def loop(self):
        raise NotImplementedError

    def enqueue_frame(self, frame):
        raise NotImplementedError


class AprsIsClient(BaseClient):
    def __init__(self, addr, port, callsign, passcode, aprs_filter=""):
        super().__init__(addr, port)
        self.callsign = callsign
        self.passcode = passcode
        self.buf = b""
        self.filter = aprs_filter

    def connect(self):
        # Call the BaseClient's connect method first to establish socket connection
        super().connect()

        if self._connected: # Only proceed if base connection was successful
            try:
                # Send login
                login = f"user {self.callsign} pass {self.passcode} vers ERLIBot 1.0\n"
                self.sock.sendall(login.encode())
                logger.info("APRS-IS login sent")

                # Send filter as a separate command if it exists
                if self.filter:
                    self.sock.sendall(f"filter {self.filter}\n".encode())
                    logger.info(f"APRS-IS filter sent: {self.filter}")

            except Exception as e:
                logger.error(f"APRS-IS login/filter failed: {e}")
                self._connected = False # Mark as disconnected if login/filter fails

    def loop(self):
        try:
            data = self.sock.recv(1024)
            if not data:
                logger.warning("APRS-IS socket returned empty — connection may have closed.")
                self._connected = False
                return

            frame_str = data.decode(errors="replace").strip()
            for line in frame_str.splitlines():
                logger.debug(f"📨 Raw line from APRS-IS: {repr(line)}")
                line = line.strip()
                if not line or line.startswith("#"):  # Skip comments
                    continue

                # Skip lines that do not contain a colon, as valid APRS frames usually do
                if ":" not in line:
                    logger.debug(f"Skipping non-APRS line (no colon found): {repr(line)}")
                    continue

                try:
                    frame = ax25.Frame.from_aprs_string(line)
                    if self.on_recv_frame:
                        self.on_recv_frame(frame)
                except Exception as parse_err:
                    logger.warning(f"APRS-IS frame parse failed: {parse_err}")
                    logger.debug(f"Offending frame string: {repr(line)}")
                    logger.debug(f"Failed frame string: {line}")
        except socket.timeout:
            logger.warning("APRS-IS read timed out.")
            self._connected = False
        except Exception as e:
            logger.error(f"APRS-IS socket error: {e}")
            self._connected = False


    def enqueue_frame(self, frame):
        try:
            raw = frame.to_aprs_string()
            if isinstance(raw, str):
                raw = raw.encode()
            self.sock.sendall(raw + b"\n")
            logger.info(f"Sent to APRS-IS: {raw.decode(errors='replace')}")
        except Exception as e:
            logger.error(f"Send to APRS-IS failed: {e}")


class RfKissClient(BaseClient):
    FEND = b"\xc0"
    FESC = b"\xdb"
    TFEND = b"\xdc"
    TFESC = b"\xdd"
    DATA = b"\x00"

    def __init__(self, addr, port, callsign="RF"):
        super().__init__(addr, port)
        self.callsign = callsign
        self.inbuf = bytearray()
        self.outbuf = bytearray()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.addr, self.port))
            self.sock.settimeout(None)
            self._connected = True
            logger.info(f"RF KISS connected to {self.addr}:{self.port}")
        except Exception as e:
            logger.error(f"RF KISS connection failed: {e}")
            self._connected = False

    def loop(self):
        try:
            data = self.sock.recv(2048)
            if not data:
                self.disconnect()
                return

            self.inbuf.extend(data)

            while len(self.inbuf) > 3:
                if self.inbuf[0] != self.FEND[0]:
                    self.inbuf.pop(0)
                    continue

                lst = self.inbuf[2:].split(self.FEND, 1)
                if len(lst) < 2:
                    break

                raw_frame, self.inbuf = lst[0], lst[1]

                frame_data = (
                    raw_frame.replace(self.FESC + self.TFEND, self.FEND)
                                 .replace(self.FESC + self.TFESC, self.FESC)
                )

                try:
                    frame = ax25.Frame.from_kiss_bytes(frame_data)
                    logger.info(f"RF KISS RECV: {str(frame)}")
                    if self.on_recv_frame:
                        self.on_recv_frame(frame)
                except Exception as e:
                    logger.warning(f"RF KISS frame parse failed: {e}")

        except Exception as e:
            logger.error(f"RF KISS socket error: {e}")
            self.disconnect()

    def enqueue_frame(self, frame):
        try:
            kiss_bytes = frame.to_kiss_bytes()
            escaped = (
                kiss_bytes.replace(self.FESC, self.FESC + self.TFESC)
                                 .replace(self.FEND, self.FESC + self.TFEND)
            )
            pkt = self.FEND + self.DATA + escaped + self.FEND
            self.sock.sendall(pkt)
            logger.info(f"Sent to RF: {frame.to_aprs_string().decode(errors='replace')}")
        except Exception as e:
            logger.error(f"KISS frame send failed: {e}")

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self._connected = False
        logging.info(f"Disconnected from {self.addr}:{self.port}")