
plaintext = "the house is being sold tonight"
print("Plaintext:", plaintext)

key_num = 7
print("Initial key value:", key_num)

plaintext_no_spaces = plaintext.replace(" ", "")
initial_key_char = chr(key_num + 65)

autokey = initial_key_char + plaintext_no_spaces

encrypted_text = ""
decrypted_text = ""

key_idx = 0
for i in range(len(plaintext)):
    p_char = plaintext[i]

    if p_char.isalpha():
        k_char = autokey[key_idx]

        p_val = ord(p_char) - ord('a')
        k_val = ord(k_char) - ord('a')

        encrypted_val = (p_val + k_val) % 26
        encrypted_char = chr(encrypted_val + ord('a'))
        encrypted_text += encrypted_char

        key_idx += 1
    else:

        encrypted_text += p_char

print("Encrypted cipher:", encrypted_text)


decrypted_text_with_spaces = ""
key_idx = 0
for i in range(len(encrypted_text)):
    e_char = encrypted_text[i]

    if e_char.isalpha():
        k_char = autokey[key_idx]

        e_val = ord(e_char) - ord('a')
        k_val = ord(k_char) - ord('a')

        decrypted_val = (e_val - k_val + 26) % 26
        decrypted_char = chr(decrypted_val + ord('a'))
        decrypted_text_with_spaces += decrypted_char

        key_idx += 1
    else:
        decrypted_text_with_spaces += e_char

print("Decrypted cipher:", decrypted_text_with_spaces)

key="dollars"
str="the house is being sold tonight"
print("Key: %s" %key)
print("Plaintext: %s" %str)
str=str.replace(" ","")
res=""
decr=""

if len(str) != len(key):
    for i in range(len(str) - len(key)):
        key+=(key[i % len(key)])

for i in range(len(str)):
    char = str[i]
    if char.isupper():
        res+= chr((ord(char) + ord(key[i]) - 2 * ord('A')) % 26 + ord('A'))
    elif char.islower():
        res+= chr((ord(char) + ord(key[i]) - 2 * ord('a')) % 26 + ord('a'))
    else:
        res+= char

print("Cipher: %s" %res)
print("\nDecrypting the cipher: ")


for i in range(len(res)):
    char = res[i]
    if char.isupper():
        decr+= chr((ord(char) - ord(key[i]) + 26) % 26 + ord('A'))
    elif char.islower():
        decr+= chr((ord(char) - ord(key[i]) + 26) % 26 + ord('a'))
    else:
        decr+= char


print("Decrypted cipher: %s" %decr)