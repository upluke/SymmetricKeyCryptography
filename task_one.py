from Crypto.Cipher import AES
import os
from Crypto import __version__


class TaskOne:
    def __init__(self, value):
        self.value = value

    def break_binary_data(self, binary_data, len_of_block):
        list_of_blocks = []
        for i in range(0, len(binary_data), len_of_block):
            block = binary_data[i : i + len_of_block]

            if len(block) == len_of_block:
                list_of_blocks.append(block)
            else:
                padding_size = len_of_block - len(block)
                # padding should be bytes, not a string
                padding = bytes([0] * padding_size)
                block += padding
                list_of_blocks.append(block)

        return list_of_blocks

    # generate both the key and IV
    def gen_key(self, length):
        return bytearray(
            os.urandom(length)
        )  # bytearray elements are integers in the range 0-255

    def ecb_encrypt_message(self, block_list, key):
        list_of_ciphers = []
        for i in range(len(block_list)):
            ECB_cipher = AES.new(key, AES.MODE_ECB)
            list_of_ciphers.append(ECB_cipher.encrypt(block_list[i]))

        return list_of_ciphers

    # reference:
    # def encrypt_one(self, plain_block, key):
    #     return bytearray(
    #         [ord(plain_block[1]) ^ key[i] for i in range(len(plain_block))]
    #     )

    # def encrypt_two(self, plain_block, key):
    #     return bytearray([plain_block ^ key[i] for i in range()])

    # def cbc_encrypt_message(self, block_list, key, iv, len_of_block):
    #     list_of_ciphers = []
    #     for i in range(len(block_list)):
    #         cipher1 = self.encrypt_one(block_list[i], iv)
    #         cipher2 = self.encrypt_two(cipher1, key)
    #         list_of_ciphers.append(cipher2)
    #         iv = cipher2
    #     return list_of_ciphers

    def cbc_encrypt_message(self, block_list, key, iv):
        list_of_ciphers = []

        for i in range(len(block_list)):
            block = block_list[i]
            block = bytes(x ^ y for x, y in zip(block, iv))
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_block = cipher.encrypt(block)
            list_of_ciphers.append(encrypted_block)
            iv = encrypted_block
        return list_of_ciphers

    def main(self):
        # msg = "my message for testing: aljdsflsadjflsadjfdasjflasdjfladfl"

        with open("mustang.bmp", "rb") as file:
            binary_data = file.read()
        len_of_block = 16
        # print(binary_data)
        header_size = 54  # BMP header size
        header = binary_data[:header_size]
        image_data = binary_data[header_size:]

        block_list = self.break_binary_data(image_data, len_of_block)
        # block_list = self.break_message(msg, len_of_block)
        # print(block_list)

        key = self.gen_key(len_of_block)
        iv = self.gen_key(len_of_block)

        # ECB
        ecb_cipher_list = self.ecb_encrypt_message(block_list, key)
        ecb_encrypted_image_data = b"".join(ecb_cipher_list)
        ecb_encrypted_bmp_data = header + ecb_encrypted_image_data
        with open("ecb_encrypted_mustang.bmp", "wb") as file:
            file.write(ecb_encrypted_bmp_data)

        # CBC:
        cbc_cipher_list = self.cbc_encrypt_message(block_list, key, iv)
        cbc_encrypted_image_data = b"".join(cbc_cipher_list)
        cbc_encrypted_bmp_data = header + cbc_encrypted_image_data
        with open("cbc_encrypted_mustang.bmp", "wb") as file:
            file.write(cbc_encrypted_bmp_data)


# -------------------------------------------- demo
# def cbc_demo(self):
#     print("Crypto library version:", __version__)
#     with open("mustang.bmp", "rb") as file:
#         binary_data = file.read()
#     key = binascii.unhexlify("1F61ECB5ED5D6BAF8D7A7068B28DCC8E")
#     IV = os.urandom(16)

#     encryptor = AES.new(key, AES.MODE_CBC, IV=IV)

#     # pad
#     padded_data = pad(binary_data, AES.block_size)
#     ciphertext = encryptor.encrypt(padded_data)

#     # print("123", binascii.hexlify(ciphertext).upper())
#     with open("encrypted_mustang.bmp", "wb") as file:
#         file.write(ciphertext)

#     self.cbc_demo_decryption("encrypted_mustang.bmp", key, IV)

# def cbc_demo_decryption(self, file_pah, key, IV):
#     with open(file_pah, "rb") as file:
#         encrypted_data = file.read()

#     decryptor = AES.new(key, AES.MODE_CBC, IV=IV)
#     decrypted_data = decryptor.decrypt(encrypted_data)
#     # unpad
#     decrypted_data = unpad(decrypted_data, AES.block_size)

#     with open("mustang.bmp", "rb") as file:
#         original_data = file.read()

#     if decrypted_data == original_data:
#         print("successful")
#     else:
#         print("nah")


def print_value(self):
    print(self.value)


if __name__ == "__main__":
    obj = TaskOne("Hello")

    # obj.print_value()
    # obj.cbc_demo()
    obj.main()
