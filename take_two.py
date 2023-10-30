from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import urllib.parse
import os


class TaskTwo:
    def __init__(self):
        self.key = b"\xca\xfd\xe1N\xac\xe4\x08]\xca^\x9c\xcd\xbb\xba\xfd\xac"
        self.iv = b"A!b\x98l\xfc4\xbfR\xa0\x15\xf8`\xfc\x86\x82"

    def gen_key(self, length):
        return bytearray(os.urandom(length))

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

    def cbc_encrypt_message(self, block_list, key, iv):
        list_of_ciphers = []
        for bl in block_list:
            block = bytes(x ^ y for x, y in zip(bl, iv))

            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_block = cipher.encrypt(block)
            list_of_ciphers.append(encrypted_block)
            iv = encrypted_block

        return list_of_ciphers

    def submit(self, s):
        len_of_block = 16
        user_s = "userid=456;userdata=" + s + ";session-id=31337"
        url_encoded_s = urllib.parse.quote(user_s, safe="")
        bin_modified_s = url_encoded_s.encode("utf-8")
        # print(url_encoded_s)
        block_list = self.break_binary_data(bin_modified_s, len_of_block)
        ciphertext = b"".join(self.cbc_encrypt_message(block_list, self.key, self.iv))
        return ciphertext

    def verify(self, ciphertext):
        # Decrypt the ciphertext using AES-CBC
        # print("ciphertext: ", ciphertext)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        decrypted_message = cipher.decrypt(ciphertext)
        print("decry: ", decrypted_message)
        return b";admin=true;" in decrypted_message

    def main(self):
        s = "You’re the man now, dog"
        ciphertext = self.submit(s)
        print("ciphertext: ", ciphertext.hex())

        or_cipher = [  # e7 8e 98 59 96 f7 bb 6c 65 a9 5e 1e        // first 24 chars in ciphertext.hex()
            0xE7,
            0x8E,
            0x98,
            0x59,
            0x96,
            0xF7,
            0xBB,
            0x6C,
            0x65,
            0xA9,
            0x5E,
            0x1E,
        ]
        inject_str = [
            0x3B,
            0x61,
            0x64,
            0x6D,
            0x69,
            0x6E,
            0x3D,
            0x74,
            0x72,
            0x75,
            0x65,
            0x3B,
        ]  # text -> hex

        og_url_str = [
            0x73,
            0x65,
            0x72,
            0x64,
            0x61,
            0x74,
            0x61,
            0x25,
            0x33,
            0x44,
            0x59,
            0x6F,
        ]

        for i in range(len(inject_str)):
            inject_str[i] ^= or_cipher[i]

        for i in range(len(inject_str)):
            inject_str[i] ^= og_url_str[i]

        for x in inject_str:
            print(
                hex(x)
            )  # 0xaf 0x8a 0x8e 0x50 0x9e 0xed 0xe7 0x3d 0x24 0x98 0x62 0x4a       # manully inject them into below
        modified = bytes.fromhex("af8a8e509eede73d2498624a" + ciphertext.hex()[24:])

        print(self.verify(modified))


if __name__ == "__main__":
    obj = TaskTwo()
    obj.main()
