def decrypt_shift_cipher(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            decrypted_char_code = (ord(char) - ord('A') - shift) % 26
            plaintext += chr(decrypted_char_code + ord('A'))
        else:
            plaintext += char
    return plaintext

determined_shift = 4
print(f"Determined Shift: {determined_shift}")

ciphertext_to_decrypt = "XVIEWYWI"
decrypted_message = decrypt_shift_cipher(ciphertext_to_decrypt, determined_shift)

print(f"Ciphertext: {ciphertext_to_decrypt}")
print(f"Plaintext: {decrypted_message}")