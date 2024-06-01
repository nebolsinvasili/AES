import unittest

import sys
sys.path.append("/media/Seagate_B/projects/py_project/AES")

from utils.mods import CTR


class TestCTR(unittest.TestCase):
    """
    Тест AES-128 в режиме CTR.
    """
    def setUp(self):
        self.aes_ctr = CTR(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Должен шифровать и расшифровывать одноблочные сообщения. """
        ciphertext = self.aes_ctr.encrypt(self.message, self.iv)
        self.assertEqual(self.aes_ctr.decrypt(ciphertext, self.iv), self.message)

        # Stream mode ciphers don't increase message size.
        self.assertEqual(len(ciphertext), len(self.message))

    def test_wrong_iv(self):
        """ Должен проверять длину IV """
        with self.assertRaises(AssertionError):
            self.aes_ctr.encrypt(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes_ctr.encrypt(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes_ctr.decrypt(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes_ctr.decrypt(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Различные IVs должны генерировать разные шифры. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes_ctr.encrypt(self.message, self.iv)
        ciphertext2 = self.aes_ctr.encrypt(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes_ctr.decrypt(ciphertext1, self.iv)
        plaintext2 = self.aes_ctr.decrypt(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ Когда len(message) == block size, padding добавляет блок. """
        block_message = b'M' * 16
        ciphertext = self.aes_ctr.encrypt(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes_ctr.decrypt(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ Должен допускать сообщения длиннее одного блока. """
        long_message = b'M' * 100
        ciphertext = self.aes_ctr.encrypt(long_message, self.iv)
        self.assertEqual(self.aes_ctr.decrypt(ciphertext, self.iv), long_message)


if __name__ == '__main__':
    unittest.main()