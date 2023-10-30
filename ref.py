from Crypto.Cipher import AES
import urllib.parse
import os

block_size = 16


def pad_string(s):
    padding_length = block_size - len(s) % block_size
    return s + bytes([padding_length] * padding_length)


def unpad_string(s):
    return s[: -s[-1]]


def encrypt(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(text)


def decrypt(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(text)


def input_to_blocks(text):
    text_blocks = []
    for i in range(0, len(text), block_size):
        text_blocks.append(text[i : i + block_size])
    return text_blocks


def XOR(str1, str2):
    if len(str1) != len(str2):
        print("Strings are of different length: exiting")
        return
    mod_str = b""
    for i in range(len(str1)):
        temp_xor = str1[i] ^ str2[i]
        mod_str += temp_xor.to_bytes(1, byteorder="big")
    return mod_str


def submit(key, iv):
    cipher_text = []
    encode_str = "userid=456;userdata=You’re the man now, dog;session-id=31337"
    encode_str = urllib.parse.quote(encode_str, safe="").encode("utf-8")
    encode_str = pad_string(encode_str)
    blocks = input_to_blocks(encode_str)
    prev = iv
    for block in blocks:
        t = encrypt(XOR(block, prev), key, iv)
        cipher_text.append(t)
        prev = t

    # Now, let's modify the ciphertext to insert "admin=true" within the last block
    admin_block = bytes("admin=true".ljust(16), "utf-8")
    cipher_text[-1] = XOR(cipher_text[-1], admin_block)

    return cipher_text


def verify(key, iv, encoded_str):
    total_str = b""
    prev = iv
    for block in encoded_str:
        t = decrypt(block, key, iv)
        total_str += XOR(t, prev)
        prev = block

    total_str = unpad_string(total_str)

    if b"admin=true" in total_str:
        return True
    else:
        return False


if __name__ == "__main__":
    print("--------------------------------------------------------------------------")
    print("EXECUTING TASK 2")
    print(
        "--------------------------------------------------------------------------\n"
    )
    print(
        "\n--------------------------------------------------------------------------"
    )
    print("START GENERATE THE KEY, IV")

    key = os.urandom(block_size)
    print("Key: " + str(key))

    iv = os.urandom(block_size)
    print("IV: " + str(iv))

    print("\nEND GENERATE THE KEY, IV")
    print("--------------------------------------------------------------------------")
    print("START SUBMIT\n")

    cipher_text = submit(key, iv)
    print("CIPHER TEXT BELOW")
    print(cipher_text)

    print("\nEND SUBMIT")
    print("--------------------------------------------------------------------------")
    print("START VERIFY\n")

    tf = verify(key, iv, cipher_text)
    if tf:
        print("TRUE")
    else:
        print("FALSE")

    print("\nEND VERIFY")
    print(
        "--------------------------------------------------------------------------\n"
    )
