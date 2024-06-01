import sys
import unittest

sys.path.append("/media/Seagate_B/projects/py_project/AES")
from utils.mods import AES_Plus

class AES_Plus_Test(unittest.TestCase):
    """
    Тест функций `encrypt` и `decrypt`, а также базовых
    функций безопасности, такие как рандомизация и целостность.
    """
    def setUp(self):
        self.key = b'master key_12345'
        self.message = b'secret message'
        self.aes_plus = AES_Plus(master_key=self.key, metod="CBC")
        # Lower workload then default to speed up tests.
        self.encrypt = lambda ciphertext: self.aes_plus.encrypt(ciphertext, 10000)
        self.decrypt = lambda ciphertext: self.aes_plus.decrypt(ciphertext, 10000)

    def test_success(self):
        """ Должен уметь шифровать и расшифровывать простые сообщения. """
        ciphertext = self.encrypt(self.message)
        self.assertEqual(self.decrypt(ciphertext), self.message)

    def test_long_message(self):
        """ Должна быть возможность шифровать и расшифровывать более длинные сообщения. """
        ciphertext = self.encrypt(self.message * 100)
        self.assertEqual(self.decrypt(ciphertext), self.message * 100)

    def test_sanity(self):
        """ Гарантирует, что зашифрованный текст не содержит секретной информации. """
        ciphertext = self.encrypt(self.message)
        self.assertNotIn(self.key, ciphertext)
        self.assertNotIn(self.message, ciphertext)

    def test_randomization(self):
        """ Тест рандомизации salt. """
        ciphertext1 = self.encrypt(self.message)
        ciphertext2 = self.encrypt(self.message)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_integrity(self):
        """ Tests integrity verifications. """
        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.message)
            ciphertext += b'a'
            self.decrypt(ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.message)
            ciphertext = ciphertext[:-1]
            self.decrypt(ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.message)
            ciphertext = ciphertext[:-1] + b'a'
            self.decrypt(ciphertext)


if __name__ == '__main__':
    unittest.main()