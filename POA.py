import sys
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import unpad


def oracle(ciphertext, key, iv):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        deciphered_text = cipher.decrypt(ciphertext)
        unpad(deciphered_text, 8)
        return True
    except ValueError:
        # print("Decryption error: Invalid padding!")
        return False
    except Exception as e:
        return False


def xor(a, b, c):
    return (a ^ b ^ c).to_bytes(1, 'big')


def creat_next_xj(p_tag, previous_ci, previous_block, j):
    """
    Creates the next Xj value.
    """

    xj = []
    for x in range(j):
        xj.append(xor(p_tag[0], previous_ci[x], (previous_block[x])[0]))
    return xj


def POA():
    # Get the variables from the user and convert them from Hex.
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes.fromhex(sys.argv[2])
    iv = bytes.fromhex(sys.argv[3])

    # Define the block size.
    block_size = 8

    # Split the ciphertext into blocks.
    blocks = [ciphertext[x: x + block_size] for x in range(0, len(ciphertext), block_size)]

    # Reverse the blocks.
    blocks.reverse()

    # Create a list to store the decrypted blocks.
    ciphertext_after_decryption = []

    for i, second_block in enumerate(blocks):
        # If this is the last block, use the initialization vector as the first block.
        if i + 1 == len(blocks):
            first_block = iv
        else:
            first_block = blocks[i + 1]

        temp_xj = []

        # Create a list to store the previous Ci values.
        previous_ci_minus1 = []
        decipher_block = []

        for j in range(9):
            # If this is the last iteration, add the decipher block and break.
            if j == 8:
                ciphertext_after_decryption.append(decipher_block)
                break

            # If there are no previous Xj values, create a list of all zeros.
            if not temp_xj:
                c = b'\x00' * (8 - j)
            else:
                c = b'\x00' * (8 - j) + b''.join(temp_xj)

            # Create the p'.
            p_tag = (j + 1).to_bytes(1, 'big')
            current_ci_minus1 = first_block[7 - j]

            # Iterate over all possible values for the current byte.
            for x in range(256):
                cipher_modified = c + second_block

                # Create the new IV.
                new_iv = cipher_modified[:8]

                # If the decryption was successful.
                if oracle(cipher_modified[8:], key, new_iv):
                    xj = c[7 - j]
                    p_tag2 = (j + 2).to_bytes(1, 'big')
                    plaintext_last_byte = xor(p_tag[0], current_ci_minus1, xj)
                    decipher_block.append(plaintext_last_byte)
                    previous_ci_minus1.append(current_ci_minus1)
                    temp_xj = creat_next_xj(p_tag2, previous_ci_minus1, decipher_block, j + 1)
                    temp_xj.reverse()
                    break

                # Otherwise, set the current byte to the next possible value.
                else:
                    c = bytearray(c)
                    c[7 - j] = x
                    c = bytes(c)

    plaintext_blocks = []

    # Go through each block, return the values in it to the original order, and then combine them.
    for blocks in ciphertext_after_decryption:
        new_block = list(reversed(blocks))
        new_block = b''.join(new_block)
        plaintext_blocks.append(new_block)

    # Return the blocks to the correct order, unite them, and remove the padding.
    plaintext_blocks.reverse()
    plaintext = b''.join(plaintext_blocks)
    plaintext = unpad(plaintext, block_size)

    # Decode and print the plaintext.
    plaintext = plaintext.decode()
    print(plaintext)


POA()
