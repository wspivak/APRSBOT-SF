import socket
import time
import random
import sys
import os

#################### Silence all Output if launched from ATD ####################
# Force silence: redirect stdout and stderr to /dev/null
# This prevents ATD from sending "Output from job" emails
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')
#################### End of Silence all Output from ATD ####################

from .aprs import Handler  # adjust if not using as package

# --- Configuration ---
APRS_IS_SERVER = 'rotate.aprs2.net'
APRS_IS_PORT = 14580
BOT_ALIAS = 'ERLI'  # Default destination alias
LOGIN_CALL = 'KC2NJV-10'
PASSCODE = '16569'  # Replace with your actual passcode

def send_aprs_message(message_text, to_call=BOT_ALIAS):
    print(f"Sending APRS message: '{message_text}' from {LOGIN_CALL} to {to_call}")

    # Set up APRS frame
    aprs_handler = Handler(callsign=LOGIN_CALL)
    aprs_handler.destination = to_call
    aprs_handler.path = "TCPIP,qAR"  # APRS-IS path

    # Add message ID
    msg_id = str(random.randint(100, 999))
    message_with_id = f"{message_text}{{{msg_id}}}"

    # Build and encode the frame
    try:
        aprs_frame = aprs_handler.make_aprs_msg(to_call=to_call, text=message_with_id)
        aprs_message_frame_bytes = aprs_frame.to_aprs_string() + b'\n'
    except Exception as e:
        print(f"ERROR converting frame to APRS string: {e}")
        return

    print("Constructed APRS-IS Frame:")
    try:
        print(aprs_message_frame_bytes.decode('ascii', errors='replace'))
    except Exception:
        print("Failed to decode APRS frame for display.")

    # Connect and send over APRS-IS
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.settimeout(15)
            sock.connect((APRS_IS_SERVER, APRS_IS_PORT))
            print(f"Connected to APRS-IS server: {APRS_IS_SERVER}:{APRS_IS_PORT}")

            login_line = f'user {LOGIN_CALL} pass {PASSCODE} vers aprs-message-sender 1.0\n'
            sock.sendall(login_line.encode())
            print("Sent login.")

            time.sleep(1)

            filter_line = "filter t/m\n"
            sock.sendall(filter_line.encode())
            print("Sent APRS-IS filter request.")

            time.sleep(1)

            sock.sendall(aprs_message_frame_bytes)
            print("APRS message sent.")

            try:
                response = sock.recv(1024)
                print("Server response:")
                print(response.decode('utf-8', errors='replace'))
            except socket.timeout:
                print("No server response (timeout).")

            time.sleep(2)
            print("Finished message send cycle.")

        except ConnectionRefusedError:
            print(f"ERROR: Connection refused on port {APRS_IS_PORT}.")
        except socket.timeout:
            print("ERROR: Connection timed out.")
        except Exception as e:
            print(f"Unexpected error: {e}")

# --- CLI Entry Point ---
if __name__ == '__main__':
    if len(sys.argv) > 2:
        target = sys.argv[1].strip().upper()
        message_to_send = sys.argv[2]
        print(f"Sending message to: {target}")
        send_aprs_message(message_to_send, to_call=target)
    elif len(sys.argv) > 1:
        message_to_send = sys.argv[1]
        print(f"Sending message to default alias: {BOT_ALIAS}")
        send_aprs_message(message_to_send)
    else:
        print("Usage:")
        print("  python tatical_text_msg.py \"MSG message to ERLI\"")
        print("  OR")
        print("  python tatical_text_msg.py KC2NJV-4 \"MSG custom message\"")
