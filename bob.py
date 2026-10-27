import argparse
import secrets
import socket
import sys
from dataclasses import dataclass

import utils
from crypto.aes.modes import AES_ECB
from crypto.padding import pkcs7_pad, pkcs7_unpad


@dataclass
class Session:
    conn: socket.socket
    a_id: bytes
    key_session: bytes
    n_b: bytes

class Bob:
    def __init__(self, id_b, key_b, host="0.0.0.0", port=9000):
        self.id_b = id_b
        self.key_b = key_b
        self.host = host
        self.port = port
        self.sock = None
        self.session = None

    def receive_ticket(self):
        if self.session is not None:
            print("Session with Alice is already active.")
            return

        try:
            conn, addr = self.sock.accept()
        except OSError as e:
            print(f"Error accepting connection: {e}")
            return

        print(f"Connection from {addr}")

        try:
            data = utils.recv_frame(conn)
        except (OSError, ValueError) as e:
            print(f"Error receiving frame: {e}")
            self._close_session()
            return

        if data is None:
            print("Alice closed the connection before sending the ticket.")
            return

        try:
            decrypted_data = AES_ECB(self.key_b).decrypt(data)
            unpadded_data = pkcs7_unpad(decrypted_data, AES_ECB.block_size)
            fields = utils.decode(unpadded_data)
        except ValueError as e:
            print(f"Error decrypting or decoding ticket: {e}")
            self._close_session()
            return

        if len(fields) != 2:
            print(f"Invalid ticket: expected 2 fields, got {len(fields)}")
            self._close_session()
            return

        key_session, a_id = fields
        print(f"Received ticket from Alice ID: {a_id.decode()}")

        n_b = secrets.token_bytes(16)

        self.session = Session(conn=conn, a_id=a_id, key_session=key_session, n_b=n_b)

    def send_nonce(self):
        if self.session is None:
            print("No session with Alice is active.")
            return

        n_b = self.session.n_b
        try:
            response_plaintext = utils.encode([n_b])
            response_encrypted = AES_ECB(self.session.key_session).encrypt(pkcs7_pad(response_plaintext, AES_ECB.block_size))
            utils.send_frame(self.session.conn, response_encrypted)
            print(f"Sent nonce to Alice: {n_b.hex()}")
        except OSError as e:
            print(f"Error sending nonce to Alice: {e}")
            self.session.conn.close()
            self.session = None

    def verify_nonce(self):
        if self.session is None:
            print("No session with Alice is active.")
            return

        try:
            data = utils.recv_frame(self.session.conn)
        except (OSError, ValueError) as e:
            print(f"Error receiving nonce from Alice: {e}")
            self.session.conn.close()
            self.session = None
            return

        if data is None:
            print("Alice closed the connection before sending the nonce.")
            self.session.conn.close()
            self.session = None
            return

        try:
            decrypted_data = AES_ECB(self.session.key_session).decrypt(data)
            unpadded_data = pkcs7_unpad(decrypted_data, AES_ECB.block_size)
            fields = utils.decode(unpadded_data)
        except ValueError as e:
            print(f"Error decrypting or decoding nonce: {e}")
            self.session.conn.close()
            self.session = None
            return

        if len(fields) != 1:
            print(f"Invalid nonce response: expected 1 field, got {len(fields)}")
            self.session.conn.close()
            self.session = None
            return

        n_b_received = fields[0]
        expected_n_b = utils.decrement_nonce(self.session.n_b)
        if n_b_received != expected_n_b:
            print(f"Nonce verification failed: expected {expected_n_b.hex()}, got {n_b_received.hex()}")
            self._close_session()
        else:
            print("Nonce verification succeeded.")

    def receive_message(self):
        if self.session is None:
            print("No session with Alice is active.")
            return

        print("Waiting to receive message from Alice...")
        try:
            data = utils.recv_frame(self.session.conn)
        except (OSError, ValueError) as e:
            print(f"Error receiving message from Alice: {e}")
            self._close_session()
            return

        if data is None:
            print("Alice closed the connection before sending the message.")
            self._close_session()
            return

        try:
            decrypted_data = AES_ECB(self.session.key_session).decrypt(data)
            unpadded_data = pkcs7_unpad(decrypted_data, AES_ECB.block_size)
            fields = utils.decode(unpadded_data)
            message = fields[0].decode()
        except ValueError as e:
            print(f"Error decrypting or decoding message: {e}")
            return

        print(f"Received message from Alice: {message}")

        try:
            reply_text = f"Echo: {message}"
            reply_plaintext = utils.encode([reply_text.encode()])
            reply_padded = pkcs7_pad(reply_plaintext, AES_ECB.block_size)
            reply_encrypted = AES_ECB(self.session.key_session).encrypt(reply_padded)
            utils.send_frame(self.session.conn, reply_encrypted)
            print(f"Sent reply to Alice: {reply_text}")
        except OSError as e:
            print(f"Error sending reply to Alice: {e}")
            self._close_session()

    def set_key(self, hex):
        try:
            self.key_b = bytes.fromhex(hex)
        except ValueError:
            print(f"Invalid hex key for {self.id_b.decode()}: {hex}")
            return
        print(f"Set key for {self.id_b.decode()}: {hex}")

    def show_all(self):
        print(f"Bob ID: {self.id_b.decode()}")
        print(f"Bob Key: {self.key_b.hex()}")
        if self.session is not None:
            print(f"Session with Alice ID: {self.session.a_id.decode()}")
            if self.session.key_session is not None:
                print(f"Session Key: {self.session.key_session.hex()}")
            if self.session.n_b is not None:
                print(f"Nonce from Alice: {self.session.n_b.hex()}")

    def _close_session(self):
        if self.session is not None:
            self.session.conn.close()
            self.session = None

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"Bob listening on {self.host}:{self.port}")
        print("Available commands: receive_ticket, send_nonce, verify_nonce, set_key <hex>, show_all, receive_message, exit")

        try:
            while True:
                sys.stdout.write("bob> ")
                sys.stdout.flush()
                line = sys.stdin.readline()
                if not line:
                    break
                if not self._process_command(line.strip().split()):
                    break
        except KeyboardInterrupt:
            print("\nExiting Bob.")
        finally:
            self._cleanup()

    def _process_command(self, parts):
        if not parts:
            return True
        command = parts[0]

        if command == "receive_ticket":
            self.receive_ticket()
        elif command == "send_nonce":
            self.send_nonce()
        elif command == "verify_nonce":
            self.verify_nonce()
        elif command == "set_key":
            if len(parts) != 2:
                print("Usage: set_key <hex>")
            else:
                self.set_key(parts[1])
        elif command == "show_all":
            self.show_all()
        elif command == "receive_message":
            self.receive_message()
        elif command == "disconnect":
            self.disconnect()
        elif command == "exit":
            return False
        else:
            print(f"Unknown command: {command}")
        return True

    def disconnect(self):
        self._close_session()
        print("Disconnected from Alice.")

    def _cleanup(self):
        if self.sock is not None:
            self.sock.close()
        self._close_session()

def main():
    parser = argparse.ArgumentParser(description="Bob's side of the Needham-Schroeder protocol.")
    parser.add_argument("--id", required=True, help="Bob's ID")
    parser.add_argument("--key", required=True, help="Bob's key in hex")
    parser.add_argument("--host", default="localhost", help="Host to bind to (default: localhost)")
    parser.add_argument("--port", type=int, default=9000, help="Port to bind to (default: 9000)")
    args = parser.parse_args()
    id_b = args.id.encode()
    key_b = bytes.fromhex(args.key)
    bob = Bob(id_b, key_b)
    bob.run()

if __name__ == "__main__":
    main()