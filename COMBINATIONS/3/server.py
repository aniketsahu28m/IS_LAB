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
        for i in range(2, int(p ** 0.5) + 1):
            if p % i == 0:
                break
        else:
            return p

def paillier_keygen():
    p = getprime(100, 200)
    q = getprime(200, 300)
    n = p * q
    g = n + 1
    lam = lcm(p-1, q-1)
    mu = modinv((pow(g, lam, n*n) - 1) // n, n)
    public = (n, g)
    private = (lam, mu)
    return public, private

def paillier_encrypt(m, pub):
    n, g = pub
    r = random.randint(1, n-1)
    while gcd(r, n) != 1:
        r = random.randint(1, n-1)
    c = (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)
    return c

def paillier_decrypt(c, pub, priv):
    n, g = pub
    lam, mu = priv
    u = pow(c, lam, n*n)
    l = (u - 1) // n
    m = (l * mu) % n
    return m

def schnorr_keygen(p, q):
    g = pow(2, (p-1)//q, p)
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    return (p, q, g, y, x)

def schnorr_sign(msg_hash, params):
    p, q, g, y, x = params
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    e = msg_hash % q
    s = (k - x * e) % q
    return (r, s)

def schnorr_verify(msg_hash, sig, params):
    p, q, g, y, x = params
    r, s = sig
    e = msg_hash % q
    rv = (pow(g, s, p) * pow(y, e, p)) % p
    return rv == r

def sha256_digest(data):
    h = hashlib.sha256(data.encode()).hexdigest()
    return int(h, 16)

def handle_client(conn, addr, paillier_pub, paillier_priv, schnorr_params):
    sellers = []
    p, q, g, y, x = schnorr_params
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
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_enc = 1
                for c in txs_enc:
                    total_enc = (total_enc * c) % (n*n)
                decs = [paillier_decrypt(c, paillier_pub, paillier_priv) for c in txs_enc]
                total_dec_calc = paillier_decrypt(total_enc, paillier_pub, paillier_priv)
                summary += f'{name},{",".join(map(str, txs))},{",".join(map(str, txs_enc))},{",".join(map(str, decs))},{total_enc},{total_dec_calc}\n'
                results.append((name, txs, txs_enc, decs, total_enc, total_dec_calc))
            hash_val = sha256_digest(summary)
            sig = schnorr_sign(hash_val, schnorr_params)
            verify = schnorr_verify(hash_val, sig, schnorr_params)
            resp = f'\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for i, seller in enumerate(results):
                resp += f'{seller[0]} | {seller[1]} | {seller[2]} | {seller[3]} | {seller[4]} | {seller[5]} | {sig} | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    paillier_pub, paillier_priv = paillier_keygen()
    schnorr_p = getprime(800, 1000)
    schnorr_q = getprime(40, 60)
    schnorr_params = schnorr_keygen(schnorr_p, schnorr_q)
    s = socket.socket()
    s.bind(('localhost', 5021))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, paillier_pub, paillier_priv, schnorr_params)).start()

main()
