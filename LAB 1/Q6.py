def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

def modInverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def affine_decrypt(ciphertext, a_inv, b):
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            C = ord(char) - ord('A')
            P = (a_inv * (C - b)) % 26
            plaintext += chr(P + ord('A'))
        else:
            plaintext += char
    return plaintext

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_plaintext_pair = "ab"
known_ciphertext_pair = "GL"

b_key = (ord(known_ciphertext_pair[0]) - ord('A'))
print(f"Deduced b key: {b_key}")

a_key = ((ord(known_ciphertext_pair[1]) - ord('A')) - b_key) % 26
print(f"Deduced a key: {a_key}")

a_inv_key = modInverse(a_key, 26)
if a_inv_key is None:
    print(f"Error: 'a' key {a_key} has no modular inverse modulo 26. Cannot decrypt.")
else:
    print(f"Modular inverse of a ({a_key}) is: {a_inv_key}")

    decrypted_message = affine_decrypt(ciphertext, a_inv_key, b_key)
    print(f"\nOriginal Ciphertext: {ciphertext}")
    print(f"Decrypted Plaintext: {decrypted_message}")