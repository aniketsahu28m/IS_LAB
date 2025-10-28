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

def gcd_extended(a, b):
    if a == 0:
        return b, 0, 1
    gcd_, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_, x, y

def rsa_keygen():
    while True:
        p = getprime(100, 200)
        q = getprime(200, 400)
        if p != q:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randint(3, phi - 1)
        if gcd(e, phi) == 1:
            break
    gcd_, d, _ = gcd_extended(e, phi)
    d = d % phi
    if d < 0:
        d += phi
    return n, e, d

def rsa_sign(msg_hash, d, n):
    return pow(msg_hash, d, n)

def rsa_verify(msg_hash, sig, e, n):
    val = pow(sig, e, n)
    return val == msg_hash

def md5_digest(data):
    return int(hashlib.md5(data.encode()).hexdigest(), 16)

def handle_client(conn, addr, paillier_pub, paillier_priv, rsa_keys):
    n_rsa, e_rsa, d_rsa = rsa_keys
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
                c = paillier_encrypt(amt, paillier_pub)
                txs.append(amt)
                txs_enc.append(c)
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == '2':
            summary = ''
            results = []
            n, g = paillier_pub
            n_sq = n * n
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_enc = 1
                for c in txs_enc:
                    total_enc = (total_enc * c) % n_sq
                decs = [paillier_decrypt(c, paillier_pub, paillier_priv) for c in txs_enc]
                total_dec_calc = paillier_decrypt(total_enc, paillier_pub, paillier_priv)
                summary += f'{name},{",".join(map(str, txs))},{",".join(map(str, txs_enc))},{",".join(map(str, decs))},{total_enc},{total_dec_calc}\n'
                results.append((name, txs, txs_enc, decs, total_enc, total_dec_calc))
            hash_val = md5_digest(summary)
            sig = rsa_sign(hash_val, d_rsa, n_rsa)
            verify = rsa_verify(hash_val, sig, e_rsa, n_rsa)
            resp = '\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for seller in results:
                resp += f'{seller[0]} | {seller[1]} | {seller[2]} | {seller[3]} | {seller[4]} | {seller[5]} | {sig} | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    paillier_pub, paillier_priv = paillier_keygen()
    rsa_keys = rsa_keygen()
    s = socket.socket()
    s.bind(('localhost', 5091))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, paillier_pub, paillier_priv, rsa_keys)).start()

main()
