import socket
import threading
import random
import hashlib

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def get_prime(start, end):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = x0
        x0 = x1 - q*x0
        x1 = t
    if x1 < 0:
        x1 += m0
    return x1

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def elgamal_keygen():
    while True:
        p = get_prime(300, 500)
        g = random.randint(2, p - 2)
        x = random.randint(2, p - 2)
        y = pow(g, x, p)
        if pow(g, x, p) != 1 and pow(g, (p - 1)//2, p) != 1:
            break
    return p, g, y, x

def elgamal_encrypt(m, p, g, y):
    k = random.randint(1, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return a, b

def elgamal_decrypt(a, b, x, p):
    s = pow(a, x, p)
    s_inv = modinv(s, p)
    m = (b * s_inv) % p
    return m

def schnorr_keygen(p, q):
    g = pow(2, (p-1)//q, p)
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    return p, q, g, y, x

def schnorr_sign(msg_hash, params):
    p, q, g, y, x = params
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    e = msg_hash % q
    s = (k - x * e) % q
    return r, s

def schnorr_verify(msg_hash, sig, params):
    p, q, g, y, x = params
    r, s = sig
    e = msg_hash % q
    v = (pow(g, s, p) * pow(y, e, p)) % p
    return v == r

def sha256_int(data):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)

def handle_client(conn, addr, elgamal_keys, schnorr_params):
    p, g, y, x = elgamal_keys
    sellers = []
    while True:
        menu = "1. Add Seller\n2. Summary and Sign\n3. Exit\nChoice: "
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode().strip()
        if choice == "1":
            conn.sendall("Seller Name: ".encode())
            name = conn.recv(4096).decode().strip()
            conn.sendall("Number of Transactions: ".encode())
            n_tx = int(conn.recv(4096).decode().strip())
            txs, txs_enc = [], []
            for _ in range(n_tx):
                conn.sendall("Transaction Amount: ".encode())
                amt = int(conn.recv(4096).decode().strip())
                a, b = elgamal_encrypt(amt, p, g, y)
                txs.append(amt)
                txs_enc.append((a, b))
            sellers.append({'name': name, 'txs': txs, 'txs_enc': txs_enc})
        elif choice == "2":
            summary = ""
            results = []
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_a = 1
                total_b = 1
                for a, b in txs_enc:
                    total_a = (total_a * a) % p
                    total_b = (total_b * b) % p
                decs = [elgamal_decrypt(a, b, x, p) for a, b in txs_enc]
                total_dec = elgamal_decrypt(total_a, total_b, x, p)
                summary += f"{name},{','.join(map(str, txs))},{','.join(f'{a}|{b}' for a,b in txs_enc)},{','.join(map(str, decs))},{total_a}|{total_b},{total_dec}\n"
                results.append((name, txs, txs_enc, decs, (total_a, total_b), total_dec))
            hash_val = sha256_int(summary)
            r, s = schnorr_sign(hash_val, schnorr_params)
            verify = schnorr_verify(hash_val, (r, s), schnorr_params)
            resp = "\n===== Transaction Summary =====\n"
            resp += "Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n"
            for rsl in results:
                resp += f"{rsl[0]} | {rsl[1]} | {rsl[2]} | {rsl[3]} | {rsl[4]} | {rsl[5]} | ({r},{s}) | {verify}\n"
            conn.sendall(resp.encode())
        elif choice == "3":
            break
    conn.close()

def main():
    elgamal_keys = elgamal_keygen()
    p = get_prime(800, 1000)
    q = get_prime(40, 60)
    schnorr_params = schnorr_keygen(p, q)
    s = socket.socket()
    s.bind(("localhost", 5131))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, elgamal_keys, schnorr_params)).start()

main()
