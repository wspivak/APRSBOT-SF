#
# Ioreth - An APRS library and bot
# Copyright (C) 2020  Alexandre Erwin Ittner, PP5ITT <alexandre@ittner.com.br>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""
Random utilities for handling AX25 frames
"""
import logging

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG) # Remove or comment out this line if you added it temporarily

_ADDR_DIGIPEATED_BIT = 0b10000000
_ADDR_END_OF_PATH_BIT = 1

APRS_CONTROL_FLD = 0x03
APRS_PROTOCOL_ID = 0xF0

def pack_address(callsign, ssid=0, digipeated=False, end_of_path=False):
    if ssid < 0 or ssid > 15:
        raise ValueError("Bad SSID %d" % ssid)
    if len(callsign) > 6:
        raise ValueError("Callsign '%s' is too long" % callsign)

    addr = [a << 1 for a in callsign.ljust(6).encode("ASCII")]

    lastb = 0b01100000 | (ssid << 1)
    if digipeated:
        lastb |= _ADDR_DIGIPEATED_BIT
    if end_of_path:
        lastb |= _ADDR_END_OF_PATH_BIT
    addr.append(lastb)
    return bytes(addr)

def parse_address_string(addr_str):
    digipeated = False
    ssid = 0
    if addr_str[-1] == "*":
        digipeated = True
        addr_str = addr_str[:-1]
    lst = addr_str.split("-", 1)
    if len(lst) == 2:
        try:
            ssid = int(lst[1])
        except ValueError:
            logger.warning(f"Could not parse SSID from '{lst[1]}' in address '{addr_str}'. Defaulting to SSID 0.")
            ssid = 0
    return lst[0], ssid, digipeated

def pack_address_string(addr_str, end_of_path=False):
    callsign, ssid, digipeated = parse_address_string(addr_str)
    return pack_address(callsign, ssid, digipeated, end_of_path)

def unpack_address(addr):
    if len(addr) != 7:
        raise ValueError("Bad AX25 address")

    callsign = "".join(chr(n >> 1) for n in addr[0:6]).strip()
    ssid = (addr[6] & 0b00011110) >> 1
    digipeated = bool(addr[6] & _ADDR_DIGIPEATED_BIT)
    end_of_path = bool(addr[6] & _ADDR_END_OF_PATH_BIT)
    return callsign, ssid, digipeated, end_of_path

def format_address_to_string(callsign, ssid, digipeated):
    cs_pair = callsign
    if ssid != 0:
        cs_pair += "-%d" % ssid
    if digipeated:
        cs_pair += "*"
    return cs_pair

def unpack_address_to_string(addr):
    callsign, ssid, digipeated, _ = unpack_address(addr)
    return format_address_to_string(callsign, ssid, digipeated)

class Address:
    def __init__(self, callsign, ssid=0, digipeated=False, end_of_path=False):
        self.callsign = callsign
        self.ssid = ssid
        self.digipeated = digipeated
        self.end_of_path = end_of_path

    @staticmethod
    def from_bytes(addr):
        callsign, ssid, digipeated, end_of_path = unpack_address(addr)
        return Address(callsign, ssid, digipeated, end_of_path)

    @staticmethod
    def from_string(addr_str, end_of_path=False):
        callsign, ssid, digipeated = parse_address_string(addr_str)
        return Address(callsign, ssid, digipeated, end_of_path)

    def to_bytes(self):
        return pack_address(self.callsign, self.ssid, self.digipeated, self.end_of_path)

    def to_string(self):
        return format_address_to_string(self.callsign, self.ssid, self.digipeated)

    def __bytes__(self):
        return self.to_bytes()

    def __repr__(self):
        return self.to_string()

    def __str__(self):
        return self.to_string()

def pack_path(addr_strings):
    return b"".join(
        pack_address_string(a, False) for a in addr_strings[:-1]
    ) + pack_address_string(addr_strings[-1], True)

def unpack_path(path):
    if len(path) % 7 != 0:
        raise ValueError("Invalid path length")
    return [unpack_address_to_string(path[i:i+7]) for i in range(0, len(path), 7)]

def unpack_path_to_addrs(path):
    if len(path) % 7 != 0:
        raise ValueError("Invalid path length")
    return [Address.from_bytes(path[i:i+7]) for i in range(0, len(path), 7)]

class Frame:
    def __init__(self, source, dest, path, control, pid, info):
        self.source = source
        self.dest = dest
        self.path = path
        self.control = control
        self.pid = pid
        self.info = info

    @staticmethod
    def from_kiss_bytes(fdata):
        pos = 0
        dlen = len(fdata)
        if dlen < 19:
            raise ValueError("Frame length too short: " + fdata.hex())

        dest = Address.from_bytes(fdata[0:7])
        pos += 7

        addr_list = []
        while pos < dlen - 2: # Changed condition to dlen - 2 to ensure control/pid bytes are present
            addr_list.append(Address.from_bytes(fdata[pos:pos+7]))
            pos += 7
            if addr_list[-1].end_of_path:
                break

        source = addr_list[0]
        path = addr_list[1:]

        if pos >= dlen - 2:
            raise ValueError("Invalid frame data: not enough bytes for control, PID, and info: " + fdata.hex())

        control = fdata[pos]
        pid = fdata[pos+1]
        info = fdata[pos+2:]

        return Frame(source, dest, path, control, pid, info)

    def _update_end_of_path_flags(self):
        self.source.end_of_path = False
        if len(self.path) > 0:
            self.dest.end_of_path = False
            for p in self.path:
                p.end_of_path = False
            self.path[-1].end_of_path = True
        else:
            self.dest.end_of_path = True

    def to_kiss_bytes(self):
        self._update_end_of_path_flags()
        return (
            self.dest.to_bytes()
            + self.source.to_bytes()
            + b"".join(p.to_bytes() for p in self.path)
            + bytes([self.control, self.pid])
            + self.info
        )

    @staticmethod
    def from_aprs_string(frame):
        if isinstance(frame, str):
            frame_bytes = frame.encode("utf-8", errors="replace") # Use a new variable for bytes
        elif not isinstance(frame, bytes):
            raise TypeError(f"Expected str or bytes, got {type(frame).__name__} for frame: {repr(frame)}")
        else:
            frame_bytes = frame # If it's already bytes, use it directly

        lst = frame_bytes.split(b":", 1) # Use frame_bytes here
        if len(lst) != 2:
            # MODIFIED: Include the problematic frame in the error message
            raise ValueError(f"Bad APRS frame string: Missing colon delimiter. Frame: {repr(frame.decode('utf-8', errors='replace'))}")

        headers = lst[0].decode("ascii", errors="replace")
        info = lst[1]

        lst = headers.split(">", 1)
        if len(lst) != 2:
            # MODIFIED: Include the problematic headers in the error message
            raise ValueError(f"Bad headers in APRS frame string: Missing > delimiter. Headers: {repr(headers)}")

        source_str = lst[0].strip()
        if not source_str:
            raise ValueError(f"Empty source callsign in APRS frame string. Headers: {repr(headers)}")
        source = Address.from_string(source_str)

        path_str = lst[1].strip()
        if not path_str:
            # This case might be valid for direct messages without a path,
            # but the existing code expects a destination.
            # For now, we'll keep the error if no path/destination is found.
            raise ValueError(f"Empty destination/path in APRS frame string. Headers: {repr(headers)}")

        addrs = []
        for s in path_str.split(","):
            s_stripped = s.strip()
            if s_stripped:
                addrs.append(Address.from_string(s_stripped))

        if len(addrs) == 0:
            raise ValueError(f"No valid destination address in APRS frame string. Headers: {repr(headers)}")

        dest = addrs[0]
        if addrs:
            addrs[-1].end_of_path = True
        path = addrs[1:]

        f = Frame(source, dest, path, APRS_CONTROL_FLD, APRS_PROTOCOL_ID, info)
        f._update_end_of_path_flags()
        return f

    def to_aprs_string(self):
        buf = (
            self.source.to_string().encode("ASCII")
            + b">"
            + self.dest.to_string().encode("ASCII")
        )
        if len(self.path) > 0:
            buf += b"," + b",".join(a.to_string().encode("ASCII") for a in self.path)
        buf += b":" + self.info
        return buf

    def __repr__(self):
        return self.to_aprs_string().decode("utf-8", errors="replace")