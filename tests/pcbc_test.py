import unittest

import sys
sys.path.append("/media/Seagate_B/projects/py_project/AES")

from utils.mods import PCBC


class TestPCBC(unittest.TestCase):
    """
    Тест AES-128 в режиме PCBC.
    """
    def setUp(self):
        self.aes_pcbc = PCBC(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Должен шифровать и расшифровывать одноблочные сообщения. """
        ciphertext = self.aes_pcbc.encrypt(self.message, self.iv)
        self.assertEqual(self.aes_pcbc.decrypt(ciphertext, self.iv), self.message)

        # Since len(message) < block size, padding won't create a new block.
        self.assertEqual(len(ciphertext), 16)

    def test_wrong_iv(self):
        """ Должен проверять длину IV """
        with self.assertRaises(AssertionError):
            self.aes_pcbc.encrypt(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes_pcbc.encrypt(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes_pcbc.decrypt(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes_pcbc.decrypt(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Различные IVs должны генерировать разные шифры. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes_pcbc.encrypt(self.message, self.iv)
        ciphertext2 = self.aes_pcbc.encrypt(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes_pcbc.decrypt(ciphertext1, self.iv)
        plaintext2 = self.aes_pcbc.decrypt(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ Когда len(message) == block size, padding добавляет блок. """
        block_message = b'M' * 16
        ciphertext = self.aes_pcbc.encrypt(block_message, self.iv)
        self.assertEqual(len(ciphertext), 32)
        self.assertEqual(self.aes_pcbc.decrypt(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ Должен допускать сообщения длиннее одного блока. """
        long_message = b'M' * 100
        ciphertext = self.aes_pcbc.encrypt(long_message, self.iv)
        self.assertEqual(self.aes_pcbc.decrypt(ciphertext, self.iv), long_message)


if __name__ == '__main__':
    unittest.main()