import numpy as np

print("enter a number:")


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


message = "The hey is hidden under the mattress"
K=np.array([[3,3],[2,5]])
print( K)
ciphertext = hill_encrypt_general(message, K)

print("Message:", message)
print("Hill Cipher encryption:", hill_encrypt_general(message, K))


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

keypair = RSA.generate(2048)
private_key = keypair
public_key = keypair.publickey()

data = "The key is hidden under the mattress".encode('utf-8')

rsa_cipher_enc = PKCS1_OAEP.new(public_key)
ct = rsa_cipher_enc.encrypt(data)

rsa_cipher_dec = PKCS1_OAEP.new(private_key)
pt = rsa_cipher_dec.decrypt(ct)

print("Original Data: ", data.decode("utf-8"))
print("Cipher Text: ", hexlify(ct).decode("utf-8"))
print("Decrypted Text: ", pt.decode("utf-8"))

print("Successful") if pt.decode("utf-8") == data.decode("utf-8") else print("Unsuccessful")

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(pt, key):
    print("Plaintext: ", pt)
    pt = pt.encode('utf-8')

    key = key[:24].encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)

    padded_pt = pad(pt, AES.block_size)
    print("Padded Plaintext (hex):", padded_pt.hex())

    ct = cipher.encrypt(padded_pt)
    print("Ciphertext (hex):", ct.hex())
    return ct

def decrypt(ct, key):
    key = key[:24].encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)

    pt_padded = cipher.decrypt(ct)
    pt = unpad(pt_padded, AES.block_size)
    pt = pt.decode('utf-8')

    print("Decrypted from CT: ", pt)
    return pt

key = "0123456789ABCDEFGHIJKLNOP012345"
message = "Information Security Lab Evaluation One"

ct = encrypt(message, key)
dt = decrypt(ct, key)

print("Successful Encryption and Decryption: ", message == dt)

import time
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(pt, key):
    key_bytes = key[:32].encode('utf-8')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    pt_bytes = pt.encode('utf-8')
    padded_pt = pad(pt_bytes, AES.block_size)
    ct = cipher.encrypt(padded_pt)
    return ct

def aes_decrypt(ct, key):
    key_bytes = key[:32].encode('utf-8')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    pt_padded = cipher.decrypt(ct)
    pt = unpad(pt_padded, AES.block_size).decode('utf-8')
    return pt

def des_encrypt(pt, key):
    key_bytes = key[:8].encode('utf-8')  # DES key 8 bytes
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    pt_bytes = pt.encode('utf-8')
    padded_pt = pad(pt_bytes, DES.block_size)
    ct = cipher.encrypt(padded_pt)
    return ct

def des_decrypt(ct, key):
    key_bytes = key[:8].encode('utf-8')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    pt_padded = cipher.decrypt(ct)
    pt = unpad(pt_padded, DES.block_size).decode('utf-8')
    return pt

def measure_time(func, *args):
    start = time.perf_counter()
    result = func(*args)
    end = time.perf_counter()
    return end - start, result

def main():
    message = "Performance Testing of Encryption Algorithms"
    aes_key = "0123456789ABCDEFGHIJKLMNOP012345"
    des_key = "A1B2C3D4"

    aes_enc_time, aes_ct = measure_time(aes_encrypt, message, aes_key)
    aes_dec_time, aes_pt = measure_time(aes_decrypt, aes_ct, aes_key)

    des_enc_time, des_ct = measure_time(des_encrypt, message, des_key)
    des_dec_time, des_pt = measure_time(des_decrypt, des_ct, des_key)

    assert aes_pt == message, "AES decryption failed"
    assert des_pt == message, "DES decryption failed"

    print(f"AES-128 Encryption Time: {aes_enc_time*1000:.4f} ms")
    print(f"AES-128 Decryption Time: {aes_dec_time*1000:.4f} ms")
    print(f"DES Encryption Time: {des_enc_time*1000:.4f} ms")
    print(f"DES Decryption Time: {des_dec_time*1000:.4f} ms")

    labels = ['AES-128', 'DES']
    enc_times = [aes_enc_time*1000, des_enc_time*1000]
    dec_times = [aes_dec_time*1000, des_dec_time*1000]

    x = range(len(labels))

    plt.figure(figsize=(8,5))
    plt.bar(x, enc_times, width=0.4, label='Encryption Time (ms)', align='center')
    plt.bar(x, dec_times, width=0.4, label='Decryption Time (ms)', align='edge')
    plt.xticks(x, labels)
    plt.ylabel('Time (milliseconds)')
    plt.title('AES-128 vs DES Encryption and Decryption Time')
    plt.legend()
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
    #Output:
    #AES-256 Encryption Time: 1.1083 ms
    #AES-256 Decryption Time: 0.0401 ms
    #DES Encryption Time: 0.0556 ms
    #DES Decryption Time: 0.0265 ms

