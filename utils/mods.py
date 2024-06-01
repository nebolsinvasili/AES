import os

from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

from .aes import AES
from .utils import xor_bytes, inc_bytes


class CBC(AES):
    def __init__(self, master_key) -> None:
        super().__init__(master_key)
          
    def split_blocks(self, message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]

    def encrypt(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = AES.pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in self.split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in self.split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return AES.unpad(b''.join(blocks))

class CFB(AES):
    def __init__(self, master_key) -> None:
          super().__init__(master_key)
          
    def split_blocks(self, message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]
    
    def encrypt(self, plaintext, iv):
        """
        Encrypts `plaintext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in self.split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt(self, ciphertext, iv):
        """
        Decrypts `ciphertext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in self.split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

class CTR(AES):
    def __init__(self, master_key) -> None:
          super().__init__(master_key)
    
    def split_blocks(self, message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]

    def encrypt(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in self.split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in self.split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

class OFB(AES):
    def __init__(self, master_key) -> None:
          super().__init__(master_key)
          
    def split_blocks(self, message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]

    def encrypt(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for plaintext_block in self.split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in self.split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

class PCBC(AES):
    def __init__(self, master_key) -> None:
          super().__init__(master_key)
          
    def split_blocks(self, message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]

    def encrypt(self, plaintext, iv):
            """
            Encrypts `plaintext` using PCBC mode and PKCS#7 padding, with the given
            initialization vector (iv).
            """
            assert len(iv) == 16

            plaintext = AES.pad(plaintext)

            blocks = []
            prev_ciphertext = iv
            prev_plaintext = bytes(16)
            for plaintext_block in self.split_blocks(plaintext):
                # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
                ciphertext_block = self.encrypt_block(xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
                blocks.append(ciphertext_block)
                prev_ciphertext = ciphertext_block
                prev_plaintext = plaintext_block

            return b''.join(blocks)

    def decrypt(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in self.split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return AES.unpad(b''.join(blocks))

class AES_Plus:

    metods = {"CBC": CBC,
              "CFB": CFB,
              "CTR": CTR,
              "OFB": OFB,
              "PCBC": PCBC}
    AES_KEY_SIZE = 16
    HMAC_KEY_SIZE = 16
    IV_SIZE = 16

    SALT_SIZE = 16
    HMAC_SIZE = 32

    def __init__(self, master_key, metod: str) -> None:
        self.master_key = master_key.encode('utf-8') if isinstance(master_key, str) else master_key
        self.metod = metod
    
    def get_key_iv(password, salt, workload=100000):
        """
        Stretches the password and extracts an AES self.master_key, an HMAC self.master_key and an AES
        initialization vector.
        """
        stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_Plus.AES_KEY_SIZE + AES_Plus.IV_SIZE + AES_Plus.HMAC_KEY_SIZE)
        aes_key, stretched = stretched[:AES_Plus.AES_KEY_SIZE], stretched[AES_Plus.AES_KEY_SIZE:]
        hmac_key, stretched = stretched[:AES_Plus.HMAC_KEY_SIZE], stretched[AES_Plus.HMAC_KEY_SIZE:]
        iv = stretched[:AES_Plus.IV_SIZE]
        return aes_key, hmac_key, iv


    def encrypt(self, plaintext, workload=100000):
        """
        Encrypts `plaintext` with `self.master_key` using AES-128, an HMAC to verify integrity,
        and PBKDF2 to stretch the given self.master_key.

        The exact algorithm is specified in the module docstring.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        salt = os.urandom(AES_Plus.SALT_SIZE)
        master_key, hmac_key, iv = AES_Plus.get_key_iv(self.master_key, salt, workload)
        ciphertext = AES_Plus.metods.get(self.metod, 
                                         "Такого метода несуществует")(master_key).encrypt(plaintext=plaintext, 
                                                                                           iv=iv)
        hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
        assert len(hmac) == AES_Plus.HMAC_SIZE

        return hmac + salt + ciphertext
    

    def decrypt(self, ciphertext, workload=100000):
        """
        Decrypts `ciphertext` with `self.master_key` using AES-128, an HMAC to verify integrity,
        and PBKDF2 to stretch the given self.master_key.

        The exact algorithm is specified in the module docstring.
        """

        assert len(ciphertext) % 16 == 0, "Ciphertext must be made of full 16-byte blocks."

        assert len(ciphertext) >= 32, """
        Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
        encrypt or decrypt single blocks use `AES(self.master_key).decrypt_block(ciphertext)`.
        """

        hmac, ciphertext = ciphertext[:AES_Plus.HMAC_SIZE], ciphertext[AES_Plus.HMAC_SIZE:]
        salt, ciphertext = ciphertext[:AES_Plus.SALT_SIZE], ciphertext[AES_Plus.SALT_SIZE:]
        master_key, hmac_key, iv = AES_Plus.get_key_iv(self.master_key, salt, workload)

        expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
        assert compare_digest(hmac, expected_hmac), 'Ciphertext corrupted or tampered.'

        return AES_Plus.metods.get(self.metod, 
                                   "Такого метода несуществует")(master_key).decrypt(ciphertext, iv)
    

if __name__ == "__main__":
    pass
