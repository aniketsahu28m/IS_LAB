import numpy as np

def preprocess_message(message, block_size):
    message = ''.join(filter(str.isalpha, message)).upper()
    while len(message) % block_size != 0:
        message += 'X'
    return message

def text_to_numbers(text):
    return [ord(c) - ord('A') for c in text]

def numbers_to_text(numbers):
    return ''.join(chr(int(n) + ord('A')) for n in numbers)

def hill_encrypt_general(message, key):
    block_size = key.shape[0]
    message = preprocess_message(message, block_size)
    numbers = text_to_numbers(message)

    ciphertext = ''
    for i in range(0, len(numbers), block_size):
        block = np.array(numbers[i:i+block_size])
        encrypted_block = np.dot(key, block) % 26
        ciphertext += numbers_to_text(encrypted_block)
    return ciphertext


message = "We live in an insecure world"
K=np.array([[3,3],[2,7]])

print("Hill Cipher encryption:", hill_encrypt_general(message, K))

