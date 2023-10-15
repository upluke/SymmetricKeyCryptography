from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import urllib.parse
import os


class TaskTwo:
    def __init__(self):
        self.key = self.gen_key(16)
        self.iv = self.gen_key(16)

    def gen_key(self, length):
        return bytearray(os.urandom(length))

    def cbc_encrypt_message(self, block_list, key, iv):
        list_of_ciphers = []

        for i in range(len(block_list)):
            block = bytes(x ^ y for x, y in zip(block_list[i], iv))

            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_block = cipher.encrypt(block)
            list_of_ciphers.append(encrypted_block)
            iv = encrypted_block
        return list_of_ciphers

    def submit(self, s):
        user_s = "userid=456;userdata=" + s + ";session-id=31337"

        url_encoded_s = urllib.parse.quote(user_s, safe="")
        bin_modified_s = url_encoded_s.encode("utf-8")
        padded_data = pad(bin_modified_s, AES.block_size, style="pkcs7")

        ciphertext = b"".join(
            self.cbc_encrypt_message([padded_data], self.key, self.iv)
        )
        return ciphertext

    # def verify(self, ciphertext):
    #     print(ciphertext)
    #     cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
    #     decrypted_text = cipher.decrypt(ciphertext)
    #     unpadded_text = unpad(decrypted_text, AES.block_size)
    #     return b";admin=true;" in unpadded_text
    def verify(self, ciphertext):
        # Decrypt the ciphertext using AES-CBC
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        decrypted_message = cipher.decrypt(ciphertext)
        injection = ";admin=true;"

        position = len(decrypted_message) - len(injection)

        modified_message = decrypted_message[:position] + bytes(
            x ^ y for x, y in zip(decrypted_message[position:], injection.encode())
        )

        return b";admin=true;" in modified_message

    def main(self):
        s = "You’re the man now, dog"
        ciphertext = self.submit(s)
        # print(ciphertext)

        print(self.verify(ciphertext))


if __name__ == "__main__":
    obj = TaskTwo()
    obj.main()
