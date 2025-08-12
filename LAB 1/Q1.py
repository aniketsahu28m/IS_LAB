def encrypt(text,s):
    result = ""

    for i in range(len(text)):
        char = text[i]

        if (char.isupper()):
            result += chr((ord(char) + s-65) % 26 + 65)

        else:
            result += chr((ord(char) + s - 97) % 26 + 97)

    return result

text = "iamlearninginformationsecurity"
s = 20
print ("Text  : " + text)
print ("Shift : " + str(s))
print ("Cipher: " + encrypt(text,s))

cipher=encrypt(text,s)

def decrypt(cipher,s):
    result1 = ""
    for i in range(len(cipher)):
        char = cipher[i]
        if (char.isupper()):
            result1 += chr((ord(char) - s - 65) % 26 + 65)

        else:
            result1 += chr((ord(char) - s - 97) % 26 + 97)

    return result1
print ("Decrypt: " + decrypt(cipher,s))
print("\n")

text2 = "iamlearninginformationsecurity"
s1 = 15

def multiencrypt(text2,s1):
    result2 = ""
    for char in text2:
        if char.isalpha():
            num = ord(char.lower())-ord('a')
            encrypted = (num*s1)%26
            result2 += chr(encrypted+ord('a'))
        else:
            result2 += char
    return result2

print ("Text  : " + text2)
print ("Shift : " + str(s1))
print ("Cipher: " + multiencrypt(text2,s1))
cipher=multiencrypt(text2,s1)

def multidecrypt(cipher,s1):
    result2 = ""
    inverse_s1=pow(s1,-1,26)
    for char in cipher:
        if char.isalpha():
            num = ord(char.lower())-ord('a')
            decrypted = (num*inverse_s1)%26
            result2 += chr(decrypted+ord('a'))
        else:
            result2 += char
    return result2
print ("Decrypt: " + multidecrypt(cipher,s1))

print("\n")

text = "iamlearninginformationsecurity"
s2=15
s3=20

def affine_encrypt(text,s2,s3):
    result = ""

    for i in range(len(text)):
        char = text[i]

        if (char.isupper()):
            result += chr((((ord(char)-ord('A')) *s2)+s3) % 26 + 65)

        else:
            result += chr((((ord(char)-ord('a'))*s2)+s3) % 26 + 97)

    return result

print ("Text  : " + text)
print ("Shift : " + str(s2)+","+str(s3))
print ("Cipher: " + affine_encrypt(text,s2,s3))

cipher=affine_encrypt(text,s2,s3)

def affine_decrypt(cipher,s2,s3):
    result = ""
    inverse_key= pow(s2,-1,26)
    for i in range(len(cipher)):
        char = cipher[i]
        if (char.isupper()):
            result += chr((((ord(char)-ord('A')) -s3)*inverse_key) % 26 + 65)
        else:
            result += chr((((ord(char) - ord('a')) -s3) *inverse_key) % 26 + 97)

    return result
print ("Decrypt: " + affine_decrypt(cipher,s2,s3))







