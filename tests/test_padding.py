import unittest

from crypto.aes.modes import AES_ECB
from crypto.padding import pkcs7_pad, pkcs7_unpad


class TestPKCS7Padding(unittest.TestCase):
    def test_pkcs7_pad(self):
        data = b"This is a test"
        block_size = 16
        expected_padded_data = b"This is a test\x02\x02"
        padded_data = pkcs7_pad(data, block_size)
        self.assertEqual(padded_data, expected_padded_data)

    def test_pkcs7_unpad(self):
        padded_data = b"This is not a test\x04\x04\x04\x04"
        block_size = 16
        expected_unpadded_data = b"This is not a test"
        unpadded_data = pkcs7_unpad(padded_data, block_size)
        self.assertEqual(unpadded_data, expected_unpadded_data)

    def test_invalid_padding_length(self):
        padded_data = b"This is not a test\x05\x05\x05\x05"
        block_size = 16
        with self.assertRaises(ValueError):
            pkcs7_unpad(padded_data, block_size)

    def test_invalid_padding_bytes(self):
        padded_data = b"This is a test\x04\x04\x04\x05"
        block_size = 16
        with self.assertRaises(ValueError):
            pkcs7_unpad(padded_data, block_size)

    def test_encrypt_decrypt_with_padding(self):
        key = bytes.fromhex(
            "2B7E1516 28AED2A6 ABF71588 09CF4F3C"
        )
        plaintext = b"Test"

        cipher = AES_ECB(key)

        padded_plaintext = pkcs7_pad(plaintext, AES_ECB.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)

        decrypted_padded_plaintext = cipher.decrypt(ciphertext)
        decrypted_plaintext = pkcs7_unpad(decrypted_padded_plaintext, AES_ECB.block_size)
        self.assertEqual(decrypted_plaintext, plaintext)