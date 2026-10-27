import struct


def encode(fields):
    out = b""
    for f in fields:
        if len(f) > 255:
            raise ValueError(f"Field too long: {len(f)}. Should be less than 255 bytes.")
        out += bytes([len(f)]) + f
    return out

def decode(data):
    fields = []
    i = 0
    while i < len(data):
        n = data[i]
        i += 1
        if i + n > len(data):
            raise ValueError(f"Truncated field at offset {i-1}")
        fields.append(data[i:i+n])
        i += n
    return fields

def send_frame(conn, frame):
    conn.sendall(struct.pack(">I", len(frame)) + frame)

def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_frame(conn):
    length_data = _recv_exact(conn, 4)
    if length_data is None:
        raise ValueError("Connection closed while reading frame length")
    length = struct.unpack(">I", length_data)[0]
    frame = _recv_exact(conn, length)
    if frame is None:
        raise ValueError("Connection closed while reading frame data")
    return frame

def decrement_nonce(nonce):
    nonce_int = int.from_bytes(nonce, byteorder='big')
    decremented_nonce_int = (nonce_int - 1) % (1 << (len(nonce) * 8))
    return decremented_nonce_int.to_bytes(len(nonce), byteorder='big')

def increment_nonce(nonce):
    nonce_int = int.from_bytes(nonce, byteorder='big')
    incremented_nonce_int = (nonce_int + 1) % (1 << (len(nonce) * 8))
    return incremented_nonce_int.to_bytes(len(nonce), byteorder='big')