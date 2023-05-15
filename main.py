import binascii

from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad


def encrypt(padded_data, key, iv):

    # Create a DES cipher object in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Encrypt the padded data
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def xor(a, b, c):
    # Perform XOR between three single-byte values
    result = bytes([a[0] ^ b[0] ^ c[0]])
    return result


def oracle(ciphertext, key, iv):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        deciphered_text = cipher.decrypt(ciphertext)
        unpad(deciphered_text, DES.block_size)
        return True
    except ValueError:
        print("Decryption error: Invalid padding!")
        return False
    except Exception as e:
        print("Decryption error:", str(e))
        return False


def main():
    # Define the plaintext data
    plaintext = b'Hello World'
    block_size = 16
    reset_block = b'\x00' * 8

    # Define the key and IV
    key = b'poaisfun'
    iv = b'\x00' * 8

    # Pad the plaintext data
    padded_data = pad(plaintext, block_size)

    ciphertext = encrypt(padded_data, key, iv)

    c = reset_block + ciphertext[8:16]

    i = 0
    for i in range(256):
        c_modified = c[:7] + i.to_bytes(1, 'big') + c[8:]
        print(c_modified.hex())
        if oracle(c_modified, key, iv):
            print("True value of the eighth byte:", i)
            break

    print(xor(b'\x01', i.to_bytes(1, 'big'), b'\x7b'))


if __name__ == '__main__':
    main()
