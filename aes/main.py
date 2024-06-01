import os
import sys

from typing import Union
from pathlib import Path

sys.path.append("/media/Seagate_B/projects/py_project/AES")
from utils.mods import CTR, AES_Plus

def encrypt_file(file_path: Union[str, Path], 
                 encrypted_path: Union[str, Path], 
                 key):
    # Чтение файла
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = AES_Plus(master_key=key, 
                              metod="CBC").encrypt(data, 10000)

    # Запись зашифрованных данных
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)


def decrypt_file(encrypted_path: Union[str, Path], 
                 decrypted_path: Union[str, Path], 
                 key):
    # Чтение зашифрованного файла
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = AES_Plus(master_key=key, 
                              metod="CBC").decrypt(encrypted_data, 10000)
            
    # Запись дешифрованных данных
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)


key = os.urandom(16)
iv = os.urandom(16)

message = b'Attack at dawn'
print(message)

aes = CTR(key)

encrypted_aes = aes.encrypt(message, iv)
print(encrypted_aes)
decrypt_aes = aes.decrypt(encrypted_aes, iv)
print(decrypt_aes)


aes_plus_e = AES_Plus(master_key=key, metod="CBC")
encrypted_aes_plus = aes_plus_e.encrypt(message, 10000)
print(encrypted_aes_plus)

aes_plus_d = AES_Plus(master_key=key, metod="CBC")
decrypt_aes_plus = aes_plus_d.decrypt(encrypted_aes_plus, 10000)
print(decrypt_aes_plus)

if __name__ == "__main__":

    key = os.urandom(16)

    for path in [Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/text/example_txt_data.txt'),
                 Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/image/jpeg/example_image_data.jpeg'),
                 Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/image/png/example_image_data.png'),
                 Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/music/music.mp3'),
                 Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/video/without_music/video.mp4'),
                 Path('/media/Seagate_B/projects/py_project/AES/aes/work_aes/video/with_music/video.mp4'),
                 ]:
        print(path)

        # Шифрование файла
        encrypt_file(file_path=path, 
                     encrypted_path=Path(path.parent, f'{path.stem}_encrypted.enc'), 
                     key=key)
        # Дешифрование файла
        decrypt_file(encrypted_path=Path(path.parent, f'{path.stem}_encrypted.enc'),
                     decrypted_path=Path(path.parent, f'{path.stem}_decrypted{path.suffix}'), 
                     key=key)
        