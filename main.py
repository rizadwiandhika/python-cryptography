import typing
from constants import (
    PC_1,
    PC_2,
    LEFT_ROTATION,
    IP,
    EXPANSION_TABLE,
    S_BOXES,
    S_BOX_PERMUTATION,
    FP,
)

# Helper functions
def string_to_bitlist(inp: str) -> typing.List[int]:
    data = inp.encode("ascii")
    l = len(data) * 8
    result = [0] * l
    pos = 0
    for ch in data:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1

    return result


def bitlist_to_string(bitlist: typing.List[int]) -> str:
    result = b""
    for i in range(0, len(bitlist), 8):
        byte = bitlist[i : i + 8]
        result += bytes([int("".join(map(str, byte)), 2)])
    return result.decode("ascii")


def parse_plain_text_into_bit_blocks(message: str) -> typing.List[typing.List[int]]:
    if len(message) % 8 != 0:
        raise RuntimeError("Message length must be multiple of 8!")

    messages_str_blocks: typing.List[str] = []
    for i in range(0, len(message), 8):
        messages_str_blocks.append(message[i : i + 8])

    messages_bit_blocks: typing.List[typing.List[int]] = []
    for block in messages_str_blocks:
        messages_bit_blocks.append(string_to_bitlist(block))

    return messages_bit_blocks


def parse_cipher_text_to_bit_blocks(cipher: str) -> typing.List[typing.List[int]]:
    if len(cipher) % 16 != 0:
        raise RuntimeError("Message length must be multiple of 16!")

    cipher_bit_blocks: typing.List[typing.List[int]] = []

    # 16 characters of hex string will be 64 bits
    for i in range(0, len(cipher), 16):
        block_str = bin(int(cipher[i : i + 16], 16))[2:].zfill(64)
        cipher_bit_blocks.append([int(x) for x in block_str])

    return cipher_bit_blocks


def des_s_function(block: typing.List[int], table: typing.List[typing.List[int]]):
    if len(block) != 6:
        raise RuntimeError("des_s_function error: block length must be 6 bits!")

    bits_row: str = "".join(map(str, [block[0], block[5]]))
    bits_column: str = "".join(map(str, block[1:5]))

    row = int(bits_row, 2)
    column = int(bits_column, 2)

    v = table[row][column]
    b = bin(v)[2:].zfill(4)

    return list(map(int, b))


def des_round_f(right: typing.List[int], key: typing.List[int]) -> typing.List[int]:
    if len(right) != 32:
        raise RuntimeError("des_round_f error: right length must be 32 bits!")

    expanded_right = [0] * 48
    for i, _val in enumerate(expanded_right):
        expanded_right[i] = right[EXPANSION_TABLE[i]]

    xor_result = [0] * 48
    for i in range(48):
        xor_result[i] = expanded_right[i] ^ key[i]

    s_blocks: typing.List[int] = []

    for i in range(8):
        bi = xor_result[i * 6 : i * 6 + 6]
        si = des_s_function(bi, S_BOXES[i])

        s_blocks += si

    result = [0] * 32
    for i, _val in enumerate(result):
        result[i] = s_blocks[S_BOX_PERMUTATION[i]]

    return result


# 1. Sub keys generation (used for every round)
def generate_sub_keys(str_key_64: str) -> typing.List[typing.List[int]]:
    if len(str_key_64) != 8:
        raise RuntimeError("Key length must be 64 bits or 8 characters!")

    key_64 = string_to_bitlist(str_key_64)
    key_56 = [0] * 56

    # iterate over key_56 with index
    for i, _val in enumerate(key_56):
        key_56[i] = key_64[PC_1[i]]

    left_keys = [[]] * 17
    right_keys = [[]] * 17

    left_keys[0] = key_56[:28]
    right_keys[0] = key_56[28:]

    for i in range(16):
        left_keys[i + 1] = (
            left_keys[i][LEFT_ROTATION[i] :] + left_keys[i][: LEFT_ROTATION[i]]
        )
        right_keys[i + 1] = (
            right_keys[i][LEFT_ROTATION[i] :] + right_keys[i][: LEFT_ROTATION[i]]
        )

    keys = [[]] * 16
    for i in range(16):
        combined_key = left_keys[i + 1] + right_keys[i + 1]
        r = [0] * 48

        for j, _val in enumerate(r):
            r[j] = combined_key[PC_2[j]]

        keys[i] = r

    return keys


# 2. Initial Permutation
def initial_permutation(message_64_bits: typing.List[int]) -> typing.List[int]:
    if len(message_64_bits) != 64:
        raise RuntimeError("Input length must be 64 bits!")

    result = [0] * 64
    for i, _val in enumerate(result):
        result[i] = message_64_bits[IP[i]]

    return result


# 3. DES round
def des_round(
    message_64_bits: typing.List[int], key: typing.List[int]
) -> typing.List[int]:
    if len(message_64_bits) != 64:
        raise RuntimeError(
            f"des_round error: message_64_bits length must be 64 bits! found:{len(message_64_bits)}"
        )

    left = message_64_bits[:32]
    right = message_64_bits[32:]

    new_left = right
    new_right = [0] * 32

    round_result = des_round_f(right, key)
    for i in range(32):
        new_right[i] = left[i] ^ round_result[i]

    return new_left + new_right


# 4. Final permutation
def final_permutation(message_64_bits: typing.List[int]) -> str:
    if len(message_64_bits) != 64:
        raise RuntimeError(
            "final_permutation error: message_64_bits length must be 64 bits!"
        )

    result = [0] * 64
    for i, _val in enumerate(result):
        result[i] = message_64_bits[FP[i]]

    return "".join(map(str, result))


# Encrypt
def des_encrypt(plain_text: str, key: str) -> str:
    cipher_text = ""

    # Convert plain text into blocks of bits that each block size is 64 bits
    bit_blocks = parse_plain_text_into_bit_blocks(plain_text)

    # Generate sub keys (16 sub keys for each 16 rounds later)
    sub_keys = generate_sub_keys(key)

    for block in bit_blocks:
        # Initial permutation
        block = initial_permutation(block)

        # Apply 16 rounds for each block
        for i in range(16):
            block = des_round(block, sub_keys[i])

        left = block[:32]
        right = block[32:]

        # Switch left and right
        block = right + left

        # Final permutation
        cipher_block_bits = final_permutation(block)

        # Convert cipher block bits into hex string
        cipher_text += "%08X" % int(cipher_block_bits, 2)

    return cipher_text


# Decrypt
def des_decrypt(cipher_text: str, key: str) -> str:
    message = ""

    # Convert cipher text into blocks of bits that each block size is 64 bits
    cipher_text_bit_blocks = parse_cipher_text_to_bit_blocks(cipher_text)

    # Generate sub keys (16 sub keys for each 16 rounds later)
    sub_keys = generate_sub_keys(key)

    for block in cipher_text_bit_blocks:
        # Initial permutation
        block = initial_permutation(block)

        # Apply 16 rounds for each block
        for i in range(16):
            # In decryption, we use the sub keys in reverse order
            block = des_round(block, sub_keys[15 - i])

        left = block[:32]
        right = block[32:]

        # Switch left and right
        block = right + left

        # Final permutation
        plain_block_bits = final_permutation(block)

        # Convert plain block bits into string ascii characters
        message += bitlist_to_string([int(x) for x in plain_block_bits])

    return message


def main():
    # DES Implementation (ECB mode)

    key = "password"  # 64 bits
    original_plain_text = "abcdefghijklmnop"  # multiply of 64 bits

    print(f"Original plain text: {original_plain_text}\n")

    cipher_text = des_encrypt(original_plain_text, key)  # each should be 64 bits length
    print(f"DES encrypted: {cipher_text}")

    plain_text = des_decrypt(cipher_text, key)
    print(f"DES decrypted: {plain_text}")


if __name__ == "__main__":
    main()
