import unittest

import sys
sys.path.append("/media/Seagate_B/projects/py_project/AES")

from utils.aes import AES


class TestKeySizes(unittest.TestCase):
    """
    Тесты шифрования и расшифровки с использованием 192- и 256-битных ключей.
    """
    def test_192(self):
        aes = AES(b'P' * 24)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_256(self):
        aes = AES(b'P' * 32)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_expected_values192(self):
        message = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        aes = AES(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17')
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(ciphertext, b'\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91')
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_expected_values256(self):
        message = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        aes = AES(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(ciphertext, b'\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89')
        self.assertEqual(aes.decrypt_block(ciphertext), message)


if __name__ == '__main__':
    unittest.main()