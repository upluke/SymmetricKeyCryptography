from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binascii
import os


class TaskOne:
    def __init__(self, value):
        self.value = value

    def cbc(self):
        with open("mustang.bmp", "rb") as file:
            binary_data = file.read()
        key = binascii.unhexlify("1F61ECB5ED5D6BAF8D7A7068B28DCC8E")
        IV = os.urandom(16)

        encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
        # pad
        padded_data = pad(binary_data, AES.block_size)
        ciphertext = encryptor.encrypt(padded_data)
        # print("123", binascii.hexlify(ciphertext).upper())
        with open("encrypted_mustang.bmp", "wb") as file:
            file.write(ciphertext)

        self.cbc_decryption("encrypted_mustang.bmp", key, IV)

    def cbc_decryption(self, file_pah, key, IV):
        with open(file_pah, "rb") as file:
            encrypted_data = file.read()

        decryptor = AES.new(key, AES.MODE_CBC, IV=IV)
        decrypted_data = decryptor.decrypt(encrypted_data)
        # unpad
        decrypted_data = unpad(decrypted_data, AES.block_size)

        with open("mustang.bmp", "rb") as file:
            original_data = file.read()

        if decrypted_data == original_data:
            print("successful")
        else:
            print("nah")

    def print_value(self):
        print(self.value)


if __name__ == "__main__":
    obj = TaskOne("Hello")
    obj.print_value()
    obj.cbc()
