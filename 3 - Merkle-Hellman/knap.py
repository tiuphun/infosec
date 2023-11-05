# Nguyen Tieu Phuong (20210692)
# 1. Encrypt your first name into a binary string, each letter is encoded by 5 bits. 
# For example: 
# A is encoded to 00000
# B is encoded to 00001 
# C is encoded to 00010 
# ...
# Denote the encoded string as X 

# 2. Build  Knapsack-based cryptography (generate the key pair) satisfying the following properties: 
# a is an arbitrary super-increasing vector, len(a) = len(X)
# m is an arbitrary integer satisfying the condition described in the algorithm 
# w is a number greater than the last two digits of your student ID and satisfies the condition for w 
# a) Encrypt X using the public key generated in step 2. Denote the encrypted text by T.
# b) Decrypt T using the private key generated in Step 2

# Present the solutions for the questions step-by-step 
# -------------------------------------------------------------------------------
import random

def name_to_binary(name):
    # Create a dictionary mapping each letter to its 5-bit binary representation
    letter_to_binary = {chr(i+65): format(i, '05b') for i in range(26)}
    # Convert the name to uppercase
    name = name.upper()
    # Convert each letter in the name to its binary representation
    binary_name = ''.join(letter_to_binary[letter] for letter in name)
    return binary_name

def generate_a(length):
    # Initialize the first element to a random number
    vector = [random.randint(1, 10)]
    # Generate the rest of the elements
    for _ in range(length - 1):
        vector.append(random.randint(sum(vector) + 1, 2 * sum(vector)))
    return vector

def generate_m(vector):
    # m must >= all elements a[i] in a
    return sum(vector) + 1

def generate_w(m):
    w = max(93, m + 1) # my student id is 92, so we start from 93
    while w % m != 1:
        w += 1
    return w

def encrypt(X, a):
    T = sum(int(X[i]) * a[i] for i in range(len(X)))
    return T

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return -1

def decrypt(T, w, m, a):
    # Calculate w(-1)
    w_inv = mod_inverse(w, m)
    # Calculate T'
    T_prime = (T * w_inv) % m
    # Use greedy algorithm to find elements in vector a
    binary_string = ''
    for ai in reversed(a):
        if T_prime >= ai:
            binary_string = '1' + binary_string
            T_prime -= ai
        else:
            binary_string = '0' + binary_string
    
    return binary_string

# Test the function
name = input("Enter your first name: ")
X = name_to_binary(name)
print("Encoded string:", X)

a = generate_a(len(X))
print("Super-increasing vector:", a)

m = generate_m(a)
w = generate_w(m)
print("w:", w)

ciphertext = encrypt(X, a)
print("Ciphertext: ", ciphertext)

plaintext = decrypt(ciphertext, w, m, a)
print("Plaintext: ", plaintext)

