import socket
import threading
import random
import hashlib
from math import gcd

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def modinv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def getprime(start, end):
    while True:
        p = random.randint(start, end)
        for i in range(2, int(p**0.5) + 1):
            if p % i == 0:
                break
        else:
            return p

def paillier_keygen():
    p = getprime(70, 100)
    q = getprime(105, 130)
    n = p * q
    g = n + 1
    lam = lcm(p - 1, q - 1)
    mu = modinv((pow(g, lam, n * n) - 1) // n, n)
    pub = (n, g)
    priv = (lam, mu)
    return pub, priv

def paillier_encrypt(m, pub):
    n, g = pub
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def paillier_decrypt(c, pub, priv):
    n, g = pub
    lam, mu = priv
    u = pow(c, lam, n * n)
    l = (u - 1) // n
    m = (l * mu) % n
    return m

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def elgamal_keygen():
    while True:
        p = getprime(180, 320)
        g = random.randint(2, p - 2)
        x = random.randint(1, p - 2)
        y = pow(g, x, p)
        if pow(g, x, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
            break
    return p, g, y, x

def modinv_eg(a, m):
    m0, x0, x1 = m, 0, 1
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

def elgamal_sign(msg_hash, p, g, x):
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv_eg(k, p - 1)
    s = ((msg_hash - x * r) * k_inv) % (p - 1)
    return r, s

def elgamal_verify(msg_hash, r, s, p, g, y):
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, msg_hash, p)
    return v1 == v2

def sha256_int(data):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)

def handle_client(conn, addr, paillier_pub, paillier_priv, eg_keys):
    sellers = []
    p, g, y, x = eg_keys
    while True:
        menu = "1. Add Seller\n2. Summary and Sign\n3. Exit\nChoice: "
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode()
        if choice == "1":
            conn.sendall("Seller Name: ".encode())
            name = conn.recv(4096).decode()
            conn.sendall("Number of Transactions: ".encode())
            n_tx = int(conn.recv(4096).decode())
            txs, txs_enc = [], []
            for _ in range(n_tx):
                conn.sendall("Transaction Amount: ".encode())
                amt = int(conn.recv(4096).decode())
                c = paillier_encrypt(amt, paillier_pub)
                txs.append(amt)
                txs_enc.append(c)
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == "2":
            summary = ''
            results = []
            n, g_p = paillier_pub
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_enc = 1
                n_sq = n * n
                for c in txs_enc:
                    total_enc = (total_enc * c) % n_sq
                decs = [paillier_decrypt(c, paillier_pub, paillier_priv) for c in txs_enc]
                total_dec_calc = paillier_decrypt(total_enc, paillier_pub, paillier_priv)
                summary += f'{name},{",".join(map(str, txs))},{",".join(map(str, txs_enc))},{",".join(map(str, decs))},{total_enc},{total_dec_calc}\n'
                results.append((name, txs, txs_enc, decs, total_enc, total_dec_calc))
            hash_val = sha256_int(summary)
            r, s = elgamal_sign(hash_val, p, g, x)
            verify = elgamal_verify(hash_val, r, s, p, g, y)
            resp = '\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for seller in results:
                resp += f'{seller[0]} | {seller[1]} | {seller[2]} | {seller[3]} | {seller[4]} | {seller[5]} | ({r},{s}) | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == "3":
            break
    conn.close()

def main():
    paillier_pub, paillier_priv = paillier_keygen()
    eg_keys = elgamal_keygen()
    s = socket.socket()
    s.bind(('localhost', 5201))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, paillier_pub, paillier_priv, eg_keys)).start()

main()
