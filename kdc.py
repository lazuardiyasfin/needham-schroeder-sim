import secrets
import socket
import sys

import utils
from crypto.aes.modes import AES_ECB
from crypto.padding import pkcs7_pad
    

class KDC:
    def __init__(self, host="0.0.0.0", port=8000):
        self.keys = {}
        self.host = host
        self.port = port
        self.sock = None

    def authenticate(self):
        conn, addr = self.sock.accept()
        print(f"Connection from {addr}")
        with conn:
            data = utils.recv_frame(conn)
            if data is None:
                print("Client disconnected before sending request")
                return

            try:
                fields = utils.decode(data)
            except ValueError as e:
                print(f"Error decoding request: {e}")
                return
            if len(fields) != 3:
                print(f"Invalid request: expected 3 fields, got {len(fields)}")
                return

            id_a, id_b, n_a = fields
            print(f"Received request from {id_a.decode()} for {id_b.decode()} with nonce {n_a.hex()}")

            try:
                ticket = self.issue_ticket(id_a, id_b, n_a)
            except ValueError as e:
                print(f"Error issuing ticket: {e}")
                return

            utils.send_frame(conn, ticket)
            print(f"Sent ticket to {id_a.decode()} for {id_b.decode()}")

    def issue_ticket(self, id_a, id_b, n_a):
        if id_a.decode() not in self.keys or id_b.decode() not in self.keys:
            raise ValueError(f"Unknown user: {id_a.decode()} or {id_b.decode()}")

        key_a = self.keys[id_a.decode()]
        key_b = self.keys[id_b.decode()]

        session_key = secrets.token_bytes(16)

        ticket_plaintext = utils.encode([session_key, id_a])
        ticket_encrypted = AES_ECB(key_b).encrypt(pkcs7_pad(ticket_plaintext, AES_ECB.block_size))

        response_plaintext = utils.encode([session_key, id_b, n_a, ticket_encrypted])
        response_encrypted = AES_ECB(key_a).encrypt(pkcs7_pad(response_plaintext, AES_ECB.block_size))

        return response_encrypted

    def set_key(self, id, hex):
        try:
            self.keys[id] = bytes.fromhex(hex)
        except ValueError:
            print(f"Invalid hex key for {id}: {hex}")
            return
        print(f"Set key for {id}: {hex}")

    def show_keys(self):
        for id, key in self.keys.items():
            print(f"{id}: {key.hex()}")

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"KDC listening on {self.host}:{self.port}")
        print("Available commands: auth, set_key <id> <hex>, show_keys, exit")

        try:
            while True:
                sys.stdout.write("kdc> ")
                sys.stdout.flush()
                line = sys.stdin.readline()
                if not line:
                    break
                if not self._process_command(line.strip().split()):
                    break
        finally:
            self.sock.close()
            print("KDC shutting down")

    def _process_command(self, parts):
        if not parts:
            return True
        cmd = parts[0]

        if cmd == "auth":
            self.authenticate()
        elif cmd == "set_key":
            if len(parts) != 3:
                print("Usage: set_key <id> <hex>")
                return True
            self.set_key(parts[1], parts[2])
        elif cmd == "show_keys":
            self.show_keys()
        elif cmd == "exit":
            return False
        else:
            print(f"Unknown command: {cmd}")
        return True

if __name__ == "__main__":
    kdc = KDC()
    kdc.run()