import socket
import threading
import random
import hashlib

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t
    if x1 < 0:
        x1 += m0
    return x1

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def rsa_keygen():
    while True:
        p = random.randint(100, 300)
        q = random.randint(100, 300)
        if is_prime(p) and is_prime(q) and p != q:
            break
    n = p * q
    phi = (p-1)*(q-1)
    while True:
        e = random.randint(3, phi-1)
        if gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return n, e, d

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def rsa_sign(msg_hash, d, n):
    return pow(msg_hash, d, n)

def rsa_verify(msg_hash, sig, e, n):
    val = pow(sig, e, n)
    return val == msg_hash

def md5_digest(data):
    return int(hashlib.md5(data.encode()).hexdigest(), 16)

def handle_client(conn, addr, rsa_keys):
    n, e, d = rsa_keys
    sellers = []
    while True:
        menu = '1. Add Seller\n2. Summary and Sign\n3. Exit\nChoice: '
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode()
        if choice == '1':
            conn.sendall('Seller Name: '.encode())
            name = conn.recv(4096).decode()
            conn.sendall('Number of Transactions: '.encode())
            n_tx = int(conn.recv(4096).decode())
            txs, txs_enc = [], []
            for _ in range(n_tx):
                conn.sendall('Transaction Amount: '.encode())
                amt = int(conn.recv(4096).decode())
                c = rsa_encrypt(amt, e, n)
                txs.append(amt)
                txs_enc.append(c)
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == '2':
            summary = ''
            results = []
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_enc = 1
                for c in txs_enc:
                    total_enc = (total_enc * c) % n
                decs = [rsa_decrypt(c, d, n) for c in txs_enc]
                total_dec_calc = rsa_decrypt(total_enc, d, n)
                summary += f'{name},{",".join(map(str, txs))},{",".join(map(str, txs_enc))},{",".join(map(str, decs))},{total_enc},{total_dec_calc}\n'
                results.append((name, txs, txs_enc, decs, total_enc, total_dec_calc))
            hash_val = md5_digest(summary)
            sig = rsa_sign(hash_val, d, n)
            verify = rsa_verify(hash_val, sig, e, n)
            resp = f'\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for i, seller in enumerate(results):
                resp += f'{seller[0]} | {seller[1]} | {seller[2]} | {seller[3]} | {seller[4]} | {seller[5]} | {sig} | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    n, e, d = rsa_keygen()
    rsa_keys = (n, e, d)
    s = socket.socket()
    s.bind(('localhost', 5011))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, rsa_keys)).start()

main()
