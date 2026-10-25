from .core import AES


class AES_ECB:
    def __init__(self, key):
        self.aes = AES(key)

    def encrypt(self, plaintext):
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        if len(plaintext) % 16 != 0:
            raise ValueError("Plaintext must be a multiple of 16 bytes")

        ciphertext = bytearray()

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            encrypted_block = self.aes.encrypt_block(block)
            ciphertext.extend(encrypted_block)

        return bytes(ciphertext)