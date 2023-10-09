from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binascii
import os
from Crypto import __version__


class TaskOne:
    def __init__(self, value):
        self.value = value

    # read in input data/img
    def break_message(self, msg, len_of_block):
        # create a list of blocks, then encrypt them with the key
        list_of_blocks = []
        for i in range(0, len(msg), len_of_block):
            block = msg[i : i + len_of_block]

            if len(block) == len_of_block:
                list_of_blocks.append(block)
            else:  # check last block may need to have padding
                padding_size = len_of_block - len(block)
                for i in range(padding_size):
                    block = block + " "
                list_of_blocks.append(block)

        return list_of_blocks

    # generate both the key and IV
    def gen_key(self, length):
        return bytearray(
            os.urandom(length)
        )  # bytearray elements are integers in the range 0-255

    def cbc_encrypt_message(self, block_list, key, iv, len_of_block):
        list_of_ciphers = []
        for i in range(len(block_list)):
            cipher1 = encrypt1(block_list[i], iv)
            cipher2 = encrypt2(cipher1, key)
            list_of_ciphers.append(cipher2)
            iv = cipher2
        return list_of_ciphers

    def cbc_decrypt():
        return

    def main(self):
        msg = "my message for testing: aljdsflsadjflsadjfdasjflasdjfladfl"
        len_of_block = 16
        block_list = self.break_message(msg, len_of_block)
        print(block_list)

        key = self.gen_key(len_of_block)
        iv = self.gen_key(len_of_block)
        print(key)
        print(iv)

        # return a cipher
        cipher_list = self.cbc_encrypt_message(block_list, key, iv, len_of_block)

    # -------------------------------------------- demo
    def cbc_demo(self):
        print("Crypto library version:", __version__)
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

        self.cbc_demo_decryption("encrypted_mustang.bmp", key, IV)

    def cbc_demo_decryption(self, file_pah, key, IV):
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
    # obj.print_value()
    obj.cbc_demo()
    # obj.main()
