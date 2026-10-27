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
    sock_kdc: socket.socket
    b_id: bytes
    n_a: bytes
    sock_bob: socket.socket = None
    key_session: bytes = None
    ticket: bytes = None
    n_b: bytes = None

class Alice:
    def __init__(self, id_a, key_a, kdc_addr, bob_addr):
        self.id_a = id_a
        self.key_a = key_a
        self.kdc_addr = kdc_addr
        self.bob_addr = bob_addr
        self.session = None

    def request_ticket(self, id):
        s = self.session
        if s is not None:
            if s.sock_kdc is not None:
                print("Ticket yet to be received.")
                return
            if s.sock_bob is not None:
                print("Session with Bob is still active.")
                return

        n_a = secrets.token_bytes(16)

        try:
            sock_kdc = socket.create_connection(self.kdc_addr)
        except OSError as e:
            print(f"Error connecting to KDC: {e}")
            return

        try:
            request = utils.encode([self.id_a, id, n_a])
            utils.send_frame(sock_kdc, request)
        except OSError as e:
            print(f"Error sending request to KDC: {e}")
            sock_kdc.close()
            return

        self.session = Session(sock_kdc=sock_kdc, b_id=id, n_a=n_a)
        print(f"Sent ticket request to KDC for {id.decode()} with nonce {n_a.hex()}")

    def receive_ticket(self):
        s = self.session
        if s is None or s.sock_kdc is None:
            print("No ticket request has been sent.")
            return

        try:
            response = utils.recv_frame(s.sock_kdc)
        except (OSError, ValueError) as e:
            print(f"Error receiving response from KDC: {e}")
            s.sock_kdc.close()
            self.session = None
            return

        if response is None:
            print("KDC closed the connection.")
            s.sock_kdc.close()
            self.session = None
            return

        try:
            decrypted_response = AES_ECB(self.key_a).decrypt(response)
            unpadded_response = pkcs7_unpad(decrypted_response, AES_ECB.block_size)
            fields = utils.decode(unpadded_response)
        except ValueError as e:
            print(f"Error decrypting or decoding response: {e}")
            s.sock_kdc.close()
            self.session = None
            return

        if len(fields) != 4:
            print(f"Invalid response: expected 4 fields, got {len(fields)}")
            s.sock_kdc.close()
            self.session = None
            return

        key_session, b_id, n_a_received, ticket = fields
        if n_a_received != s.n_a:
            print("Nonce mismatch in response.")
            s.sock_kdc.close()
            self.session = None
            return

        s.key_session = key_session
        s.ticket = ticket
        s.sock_kdc.close()
        s.sock_kdc = None
        print(f"Received ticket for {b_id.decode()} with session key {key_session.hex()}")

    def forward_ticket(self):
        s = self.session
        if s is None or s.ticket is None:
            print("No ticket has been received yet.")
            return

        if s.sock_bob is not None:
            print("Session with Bob is already active.")
            return

        try:
            sock_bob = socket.create_connection(self.bob_addr)
        except OSError as e:
            print(f"Error connecting to Bob: {e}")
            return

        try:
            utils.send_frame(sock_bob, s.ticket)
        except OSError as e:
            print(f"Error sending ticket to Bob: {e}")
            sock_bob.close()
            return

        s.sock_bob = sock_bob
        print(f"Forwarded ticket to Bob for session with {s.b_id.decode()}")

    def receive_nonce(self):
        s = self.session
        if s is None or s.sock_bob is None:
            print("No session with Bob is active.")
            return

        try:
            response = utils.recv_frame(s.sock_bob)
        except (OSError, ValueError) as e:
            print(f"Error receiving nonce from Bob: {e}")
            s.sock_bob.close()
            self.session = None
            return

        if response is None:
            print("Bob closed the connection.")
            s.sock_bob.close()
            self.session = None
            return

        try:
            decrypted_response = AES_ECB(s.key_session).decrypt(response)
            unpadded_response = pkcs7_unpad(decrypted_response, AES_ECB.block_size)
            fields = utils.decode(unpadded_response)
        except ValueError as e:
            print(f"Error decrypting or decoding response from Bob: {e}")
            s.sock_bob.close()
            self.session = None
            return

        if len(fields) != 1:
            print(f"Invalid response from Bob: expected 1 field, got {len(fields)}")
            s.sock_bob.close()
            self.session = None
            return

        n_b_received = fields[0]
        s.n_b = n_b_received
        print(f"Received nonce from Bob: {n_b_received.hex()}")

    def complete_handshake(self):
        s = self.session
        if s is None or s.sock_bob is None or s.n_b is None:
            print("Handshake with Bob is not ready to be completed.")
            return

        try:
            response = utils.encode([utils.decrement_nonce(s.n_b)])
            response = pkcs7_pad(response, AES_ECB.block_size)
            encrypted_response = AES_ECB(s.key_session).encrypt(response)
            utils.send_frame(s.sock_bob, encrypted_response)
        except OSError as e:
            print(f"Error sending nonce response to Bob: {e}")
            s.sock_bob.close()
            self.session = None
            return

        print(f"Completed handshake with Bob by sending nonce {utils.decrement_nonce(s.n_b).hex()}")

    def send_message(self, message):
        s = self.session
        if s is None or s.sock_bob is None or s.key_session is None:
            print("No active session with Bob to send a message.")
            return

        try:
            message_bytes = message.encode()
            plaintext = utils.encode([message_bytes])
            padded_message = pkcs7_pad(plaintext, AES_ECB.block_size)
            encrypted_message = AES_ECB(s.key_session).encrypt(padded_message)
            utils.send_frame(s.sock_bob, encrypted_message)
        except OSError as e:
            print(f"Error sending message to Bob: {e}")
            return

        print(f"Sent encrypted message to Bob: {message}")

    def receive_echo(self):
        s = self.session
        if s is None or s.sock_bob is None or s.key_session is None:
            print("No active session with Bob to receive a message.")
            return

        try:
            response = utils.recv_frame(s.sock_bob)
        except (OSError, ValueError) as e:
            print(f"Error receiving message from Bob: {e}")
            return

        if response is None:
            print("Bob closed the connection.")
            return

        try:
            decrypted_response = AES_ECB(s.key_session).decrypt(response)
            unpadded_response = pkcs7_unpad(decrypted_response, AES_ECB.block_size)
            fields = utils.decode(unpadded_response)
            message = fields[0].decode()
        except ValueError as e:
            print(f"Error decrypting or decoding message from Bob: {e}")
            return

        print(f"Received encrypted echo from Bob: {message}")

    def set_key(self, hex):
        try:
            self.key_a = bytes.fromhex(hex)
        except ValueError:
            print("Invalid hex key")
            return
        print(f"Set Alice's master key to {hex}")

    def show_all(self):
        print(f"Alice ID: {self.id_a.decode()}")
        print(f"Alice Key: {self.key_a.hex()}")
        if self.session is not None:
            print(f"Session with Bob ID: {self.session.b_id.decode()}")
            if self.session.key_session is not None:
                print(f"Session Key: {self.session.key_session.hex()}")
            if self.session.ticket is not None:
                print(f"Ticket: {self.session.ticket.hex()}")
            if self.session.n_b is not None:
                print(f"Nonce from Bob: {self.session.n_b.hex()}")

    def run(self):
        print("Alice is running.")
        print("Available commands: request_ticket <id>, receive_ticket, forward_ticket, receive_nonce, complete_handshake, set_key <id> <hex>, show_all, send_message, receive_echo, disconnect, exit")
        try:
            while True:
                sys.stdout.write("alice> ")
                sys.stdout.flush()
                line = sys.stdin.readline()
                if not line:
                    break
                if not self._process_command(line.strip().split()):
                    break
        finally:
            self._cleanup()

    def _process_command(self, parts):
        if not parts:
            return True
        cmd = parts[0]
        if cmd == "request_ticket" and len(parts) == 2:
            self.request_ticket(parts[1].encode())
        elif cmd == "receive_ticket":
            self.receive_ticket()
        elif cmd == "forward_ticket":
            self.forward_ticket()
        elif cmd == "receive_nonce":
            self.receive_nonce()
        elif cmd == "complete_handshake":
            self.complete_handshake()
        elif cmd == "set_key" and len(parts) == 2:
            self.set_key(parts[1])
        elif cmd == "show_all":
            self.show_all()
        elif cmd == "send_message" and len(parts) >= 2:
            message = " ".join(parts[1:])
            self.send_message(message)        
        elif cmd == "receive_echo":
            self.receive_echo()
        elif cmd == "disconnect":
            self.disconnect()
        elif cmd == "exit":
            print("Exiting Alice.")
            self._cleanup()
            return False
        else:
            print("Unknown command or incorrect arguments. Type 'help' for commands.")
        return True

    def disconnect(self):
        self._cleanup()
        print("Disconnected.")

    def _cleanup(self):
        if self.session is not None:
            if self.session.sock_kdc is not None:
                self.session.sock_kdc.close()
            if self.session.sock_bob is not None:
                self.session.sock_bob.close()
            self.session = None

def main():
    parser = argparse.ArgumentParser(description="Alice in Needham-Schroeder Protocol")
    parser.add_argument("--id", required=True, help="Alice's ID")
    parser.add_argument("--key", required=True, help="Alice's key in hex")
    parser.add_argument("--kdc-host", default="localhost", help="KDC host (default: localhost)")
    parser.add_argument("--kdc-port", type=int, default=8000, help="KDC port (default: 8000)")
    parser.add_argument("--bob-host", default="localhost", help="Bob host (default: localhost)")
    parser.add_argument("--bob-port", type=int, default=9000, help="Bob port (default: 9000)")

    args = parser.parse_args()

    id_a = args.id.encode()
    try:
        key_a = bytes.fromhex(args.key)
    except ValueError:
        print("Invalid hex key for Alice.")
        sys.exit(1)

    kdc_addr = (args.kdc_host, args.kdc_port)
    bob_addr = (args.bob_host, args.bob_port)

    alice = Alice(id_a=id_a, key_a=key_a, kdc_addr=kdc_addr, bob_addr=bob_addr)
    alice.run()

if __name__ == "__main__":
    main()