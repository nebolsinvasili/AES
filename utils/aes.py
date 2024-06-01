from .utils import (xor_bytes,
                   bytes2matrix, matrix2bytes,
                   add_round_key,
                   sub_bytes, inv_sub_bytes,
                   shift_rows, inv_shift_rows,
                   mix_columns, inv_mix_columns)
from .utils import s_box, r_con


class AES:
    """_summary_
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key) -> None:
        """Инициализация AES

        Args:
            master_key (srt): _description_
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]

        self._key_matrices = self._expand_key(master_key)
    

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Пропустите через S-box на четвертой итерации при использовании AES-256.
                word = [s_box[b] for b in word]

            # XOR с эквивалентным словом из предыдущей итерации.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Группировка в байтовые матрицы размером 4x4.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


    def encrypt_block(self, data):
        """Шифрование одиного блока данных длиной 16 байт.

        Args:
            data (_type_): _description_

        Returns:
            _type_: _description_
        """
        assert len(data) == 16
        
        plain_state = bytes2matrix(data)  # Преобразование блока данных в матрицу состояния

        add_round_key(plain_state, self._key_matrices[0])  # Добавление к матрице состояния раундового ключа

        for i in range(1, self.n_rounds):  # Выполнение серии преобразований для каждого раунда шифрования (кроме последнего)
            sub_bytes(plain_state)  # Применение S-BOX к каждому байту матрицы состояния
            shift_rows(plain_state)  # Циклический сдвиг строк матрицы состояния
            mix_columns(plain_state)  # Смешивание столбцов матрицы состояния
            add_round_key(plain_state, self._key_matrices[i])  # Добавление раундового ключа

        # Последний раунд (Не выполняется смешивание столбцов матрицы состояния)
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)  # Преобразование зашифрованной матрицы состояния обратно в байты


    def decrypt_block(self, ciphertext):
        """Дешифровка одиного блока данных длиной 16 байт.

        Args:
            data (_type_): _description_

        Returns:
            _type_: _description_
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    @staticmethod
    def pad(plaintext):
        """
        Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
        Note that if the plaintext size is a multiple of 16,
        a whole block will be added.
        """
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    @staticmethod
    def unpad(plaintext):
        """
        Removes a PKCS#7 padding, returning the unpadded text and ensuring the
        padding was correct.
        """
        padding_len = plaintext[-1]
        assert padding_len > 0
        message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
        assert all(p == padding_len for p in padding)
        return message
    

if __name__ == "__main__":
    pass