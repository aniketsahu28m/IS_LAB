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


def measure_time(func, *args):
    start = time.perf_counter()
    result = func(*args)
    end = time.perf_counter()
    return end - start, result

def main():
    message = "Performance Testing of Encryption Algorithms"
    aes_key = "0123456789ABCDEFGHIJKLMNOP012345"


    aes_enc_time, aes_ct = measure_time(aes_encrypt, message, aes_key)
    aes_dec_time, aes_pt = measure_time(aes_decrypt, aes_ct, aes_key)



    assert aes_pt == message, "AES decryption failed"


    print(f"AES-128 Encryption Time: {aes_enc_time*1000:.4f} ms")
    print(f"AES-128 Decryption Time: {aes_dec_time*1000:.4f} ms")


    labels = ['AES-128']
    enc_times = [aes_enc_time*1000 ]


    x = range(len(labels))

    plt.figure(figsize=(8,5))
    plt.bar(x, enc_times, width=0.4, label='Encryption Time (ms)', align='center')

    plt.xticks(x, labels)
    plt.ylabel('Time (milliseconds)')
    plt.title('AES-128')
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