import unittest

import sys
sys.path.append("/media/Seagate_B/projects/py_project/AES")

from utils.aes import AES


class TestBlock(unittest.TestCase):
    """
    Тест AES-128 операций с блоками.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)


    def test_success(self):
        """ Должен шифровать и расшифровывать сообщения блоков. """
        message = b'\x01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)


    def test_bad_key(self):
        """ Проверка размерности ключа AES. """
        with self.assertRaises(AssertionError):
            AES(b'short key')

        with self.assertRaises(AssertionError):
            AES(b'long key' * 10)

    def test_expected_value(self):
        """ Проверка адекватности шифрования. """
        message = b'\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34'
        key     = b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C'
        ciphertext = AES(bytes(key)).encrypt_block(bytes(message))
        self.assertEqual(ciphertext, b'\x39\x25\x84\x1D\x02\xDC\x09\xFB\xDC\x11\x85\x97\x19\x6A\x0B\x32')


if __name__ == '__main__':
    unittest.main()