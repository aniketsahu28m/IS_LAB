import socket
import threading
import hashlib
from random import randint

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def elgamal_keygen():
    while True:
        p = randint(1000, 5000)
        if is_prime(p):
            break
    g = randint(2, p - 2)
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return p, g, y, x

def elgamal_encrypt(m, p, g, y):
    k = randint(1, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return a, b

def elgamal_decrypt(a, b, x, p):
    s = pow(a, x, p)
    s_inv = pow(s, -1, p)
    m = (b * s_inv) % p
    return m

def elgamal_sign(message_hash, p, g, x):
    while True:
        k = randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((message_hash - x * r) * k_inv) % (p - 1)
    return r, s

def elgamal_verify(message_hash, r, s, p, g, y):
    v1 = pow(y, r, p) * pow(r, s, p) % p
    v2 = pow(g, message_hash, p)
    return v1 == v2

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def sha1_digest(data):
    return int(hashlib.sha1(data.encode()).hexdigest(), 16)

def handle_client(conn, addr, server_keys):
    p, g, y, x = server_keys
    sellers = []
    while True:
        menu = '1. Add Seller\n2. Summary and Sign\n3. Exit\nChoice: '
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode()
        if choice == '1':
            conn.sendall('Seller Name: '.encode())
            name = conn.recv(4096).decode()
            conn.sendall('Number of Transactions: '.encode())
            n = int(conn.recv(4096).decode())
            txs, txs_enc = [], []
            for _ in range(n):
                conn.sendall('Transaction Amount: '.encode())
                amt = int(conn.recv(4096).decode())
                a, b = elgamal_encrypt(amt, p, g, y)
                txs.append(amt)
                txs_enc.append((a, b))
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == '2':
            summary = ''
            results = []
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_enc_a, total_enc_b = 1, 1
                for enc in txs_enc:
                    total_enc_a = (total_enc_a * enc[0]) % p
                    total_enc_b = (total_enc_b * enc[1]) % p
                total_dec = sum(txs)
                decs = [elgamal_decrypt(a, b, x, p) for a, b in txs_enc]
                total_dec_calc = elgamal_decrypt(total_enc_a, total_enc_b, x, p)
                summary += f'{name},{",".join(map(str, txs))},{",".join(f"{a}|{b}" for a,b in txs_enc)},{",".join(map(str, decs))},{total_enc_a}|{total_enc_b},{total_dec_calc}\n'
                results.append((name, txs, txs_enc, decs, (total_enc_a, total_enc_b), total_dec_calc))
            hash_val = sha1_digest(summary)
            r, s = elgamal_sign(hash_val, p, g, x)
            verify = elgamal_verify(hash_val, r, s, p, g, y)
            resp = f'\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for i, seller in enumerate(results):
                resp += f'{seller[0]} | {seller[1]} | {seller[2]} | {seller[3]} | {seller[4]} | {seller[5]} | ({r},{s}) | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    p, g, y, x = elgamal_keygen()
    server_keys = (p, g, y, x)
    s = socket.socket()
    s.bind(('localhost', 5001))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, server_keys)).start()

main()
