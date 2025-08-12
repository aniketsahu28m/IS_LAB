from Crypto.Cipher import DES
import base64


key = b'A1B2C3D4'
message = b'Confidential Data'

cipher = DES.new(key, DES.MODE_OFB)
msg = cipher.iv + cipher.encrypt(message)

encrypted_message = des_encrypt(message, key)
print(f"Encrypted Message: {encrypted_message}")

decrypted_message = des_decrypt(encrypted_message, key)
print(f"Decrypted Message: {decrypted_message}")