import socket
import threading
import random
import hashlib
from math import gcd

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def modinv(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def get_prime(start, end):
    while True:
        p = random.randint(start, end)
        for i in range(2, int(p**0.5) + 1):
            if p % i == 0:
                break
        else:
            return p

def paillier_keygen():
    p = get_prime(70, 100)
    q = get_prime(105, 130)
    n = p * q
    g = n + 1
    lam = lcm(p-1, q-1)
    mu = modinv((pow(g, lam, n*n) - 1)//n, n)
    pub = (n, g)
    priv = (lam, mu)
    return pub, priv

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

def rsa_keygen():
    while True:
        p = get_prime(100, 200)
        q = get_prime(200, 300)
        if p != q:
            break
    n = p * q
    phi = (p-1)*(q-1)
    while True:
        e = random.randint(3, phi-1)
        if gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return n, e, d

def rsa_sign(hash_val, d, n):
    return pow(hash_val, d, n)

def rsa_verify(hash_val, sig, e, n):
    return pow(sig, e, n) == hash_val

def sha256_hash(data):
    h = hashlib.sha256()
    h.update(data.encode())
    return int(h.hexdigest(), 16)

def handle_client(conn, addr, paillier_pub, paillier_priv, rsa_keys):
    sellers = []
    n, e, d = rsa_keys
    while True:
        menu = '1. Add Seller\n2. Show Summary and Sign\n3. Exit\nChoose: '
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode().strip()
        if choice == '1':
            conn.sendall('Seller Name: '.encode())
            name = conn.recv(4096).decode().strip()
            conn.sendall('Number of Transactions: '.encode())
            tx_count = int(conn.recv(4096).decode().strip())
            txs = []
            txs_enc = []
            for _ in range(tx_count):
                conn.sendall('Transaction Amount: '.encode())
                amt = int(conn.recv(4096).decode().strip())
                txs.append(amt)
                c = paillier_encrypt(amt, paillier_pub)
                txs_enc.append(c)
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == '2':
            summary = ''
            results = []
            n_p, g = paillier_pub
            n_sq = n_p * n_p
            for s in sellers:
                total_enc = 1
                for c in s['txs_enc']:
                    total_enc = (total_enc * c) % n_sq
                decs = [paillier_decrypt(c, paillier_pub, paillier_priv) for c in s['txs_enc']]
                total_dec = paillier_decrypt(total_enc, paillier_pub, paillier_priv)
                summary += f"{s['name']},{','.join(map(str,s['txs']))},{','.join(map(str,s['txs_enc']))},{','.join(map(str,decs))},{total_enc},{total_dec}\n"
                results.append((s['name'], s['txs'], s['txs_enc'], decs, total_enc, total_dec))
            hash_val = sha256_hash(summary)
            signature = rsa_sign(hash_val, d, n)
            verify = rsa_verify(hash_val, signature, e, n)
            out = "\n===== Transaction Summary =====\n"
            out += "Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n"
            for res in results:
                out += f"{res[0]} | {res[1]} | {res[2]} | {res[3]} | {res[4]} | {res[5]} | {signature} | {verify}\n"
            conn.sendall(out.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    paillier_pub, paillier_priv = paillier_keygen()
    rsa_keys = rsa_keygen()
    server_socket = socket.socket()
    server_socket.bind(('localhost', 5231))
    server_socket.listen(5)
    while True:
        client_conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_conn, addr, paillier_pub, paillier_priv, rsa_keys)).start()

main()
