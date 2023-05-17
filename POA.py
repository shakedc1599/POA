import sys
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad


def encrypt(padded_data, key, iv):
    # Create a DES cipher object in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Encrypt the padded data
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def oracle(ciphertext, key, iv):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        deciphered_text = cipher.decrypt(ciphertext)
        unpadded_decrypted_text = unpad(deciphered_text, 8)
        return True
    except ValueError:
        # print("Decryption error: Invalid padding!")
        return False
    except Exception as e:
        print("Decryption error:", str(e))
        return False


def xor(a, b, c):
    return (a ^ b ^ c).to_bytes(1, 'big')


def creat_next_xj(p_tag, c_i_minus_history, decipher_block_history, j):
    xj = []
    for x in range(j):
        xj.append(xor(p_tag[0], c_i_minus_history[x], (decipher_block_history[x])[0]))
    return xj


def reversed_list(old_list):
    return old_list[::-1]


def POA():
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes.fromhex(sys.argv[2])
    iv = bytes.fromhex(sys.argv[3])
    block_size = 8

    # padded_data = pad(ciphertext, block_size)
    # ciphertext = encrypt(padded_data, key, iv)
    blocks = [ciphertext[x: x + block_size] for x in range(0, len(ciphertext), block_size)]
    blocks = reversed_list(blocks)
    plaintext_after_decrypt = []

    for i in range(len(blocks)):
        second_block = blocks[i]
        if i + 1 == len(blocks):
            first_block = iv
        else:
            first_block = blocks[i + 1]

        xj_saved = []
        ci_minus1_history = []
        decipher_block = []

        for j in range(9):
            if j == 8:
                plaintext_after_decrypt.append(decipher_block)
                break

            if not xj_saved:
                c = b'\x00' * (8 - j)
            else:
                c = b'\x00' * (8 - j)
                g = b''

                for k in range(len(xj_saved)):
                    g = g + xj_saved[k]
                c = c + g

            p_tag = (j + 1).to_bytes(1, 'big')
            ci_minus1_current = first_block[7 - j]

            for x in range(256):
                cipher_modified = c + second_block
                new_iv = cipher_modified[:8]
                flag = oracle(cipher_modified[8:], key, new_iv)
                if flag:
                    xj = c[7 - j]
                    p_tag2 = (j + 2).to_bytes(1, 'big')
                    plaintext_last_byte = xor(p_tag[0], ci_minus1_current, xj)
                    decipher_block.append(plaintext_last_byte)
                    ci_minus1_history.append(ci_minus1_current)
                    xj_saved = creat_next_xj(p_tag2, ci_minus1_history, decipher_block, j + 1)
                    xj_saved = reversed_list(xj_saved)
                    break
                else:
                    c = bytearray(c)
                    c[7 - j] = x
                    c = bytes(c)

    new_list = []
    for blocks in plaintext_after_decrypt:
        b = reversed_list(blocks)
        b = b''.join(b)
        new_list.append(b)

    new_list = reversed_list(new_list)
    plaintext = b''.join(new_list)
    plaintext = unpad(plaintext, block_size)
    plaintext = plaintext.decode()

    print(f"Your word was: {plaintext}")


POA()
