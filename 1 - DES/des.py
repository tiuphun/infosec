# Implementation of DES encription algorithm
# Nguyen Tieu Phuong - 20210692

##############################################################################
# Implement the sub-key generation algorithm 
# 1. Implement the f-function 
# 2. Combine step from step 1, 2 to implement the encryption algorithm of DES 
# 3. Apply DES and encrypt your name 
# 4. Submit your code for 1, 2, 3 and result for 4 
# Note: details of S-boxes, P-box, PC, ... can be found here:
# https://en.wikipedia.org/wiki/DES_supplementary_material

# Initial permutation table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final permutation table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion table
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation table
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# S-boxes
S_BOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Permutation choice 1 table
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permutation choice 2 table
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Left shift schedule
LS = [
    1, 1, 2, 2, 
    2, 2, 2, 2,
    1, 2, 2, 2, 
    2, 2, 2, 1
]

# Input processing functions
def get_user_input():
    while True:
        plaintext = input("Enter your name (8 characters only): ")
        if len(plaintext) == 8:
            break
        else:
            print("Please enter exactly 8 characters.")
    return plaintext

def text_to_binary(text):
    binary_result = ""
    for char in text:
        unicode_value = ord(char)
        binary_value = format(unicode_value, '08b')
        binary_result += binary_value
    return binary_result

# Helper functions for DES
def permute(bits, table):
    permuted_text = [bits[i - 1] for i in table]
    permuted_text = ''.join(permuted_text)
    return permuted_text

def left_circular_shift(bit_string, shift_amount):
    shift_amount = shift_amount % len(bit_string)
    shifted_bits = bit_string[shift_amount:] + bit_string[:shift_amount]
    return shifted_bits


def xor(bits1, bits2):
    return [int(b1) ^ int(b2) for b1, b2 in zip(bits1, bits2)]

def substitute(bits, s_box):
    row = int(str(bits[0]) + str(bits[5]), 2)
    col = int(''.join(map(str, bits[1:5])), 2)
    return [int(b) for b in format(s_box[row][col], '04b')]

sub_key = []
def key_generate(key_bits):
    key = permute(key_bits, PC1)

    left_half = key[:28]
    right_half = key[28:]
    
    for i in range(16):
        left_half = left_circular_shift(left_half, LS[i])
        right_half = left_circular_shift(right_half, LS[i])
        newkey = left_half + right_half
        newkey = permute(newkey, PC2)
        sub_key.append(newkey)

# DES function
def des_encrypt(inputbits, subkeys):
    permuted_text = permute(inputbits, IP)
    
    left_half = permuted_text[:32]
    right_half = permuted_text[32:]
    
    for i in range(16):
        expanded_right = permute(right_half, E)
        xor_result = bin(int(expanded_right, 2) ^ int(subkeys[i], 2))[2:].zfill(48)
        
        s_box_output = ""
        for j in range(8):
            s_box_input = xor_result[j * 6: (j + 1) * 6]
            row = int(s_box_input[0] + s_box_input[5], 2)
            col = int(s_box_input[1:5], 2)
            s_box_value = S_BOXES[j][row][col]
            s_box_output += format(s_box_value, '04b')
        
        permuted_output = permute(s_box_output, P)
        new_right = bin(int(left_half, 2) ^ int(permuted_output, 2))[2:].zfill(32)
        
        left_half = right_half
        right_half = new_right

    combined = right_half + left_half

    encrypted_text = permute(combined, FP)

    return encrypted_text

def main():
    # Get user input
    plaintext = get_user_input()
    print("Enter your key: ")
    keytext = input()

    # Convert to binary
    inputbits = text_to_binary(plaintext)
    keybits = text_to_binary(keytext)

    # Generate subkeys
    key_generate(keybits)

    # Encrypt
    encrypted_text = des_encrypt(inputbits, sub_key)
    print("Encrypted Text: ", encrypted_text)

if __name__ == "__main__":
    main()
