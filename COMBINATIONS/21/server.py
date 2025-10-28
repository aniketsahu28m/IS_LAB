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
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def get_prime(start,end):
    while True:
        p = random.randint(start,end)
        if is_prime(p):
            return p

def rsa_keygen():
    while True:
        p = get_prime(100,200)
        q = get_prime(200,400)
        if p != q:
            break
    n = p*q
    phi = (p-1)*(q-1)
    while True:
        e = random.randint(3, phi-1)
        if gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return n, e, d

def rsa_encrypt(m,e,n):
    return pow(m,e,n)

def rsa_decrypt(c,d,n):
    return pow(c,d,n)

def elgamal_keygen():
    while True:
        p = get_prime(300,500)
        g = random.randint(2,p-2)
        x = random.randint(2,p-2)
        y = pow(g,x,p)
        if pow(g,x,p) != 1 and pow(g,(p-1)//2,p) != 1:
            break
    return p,g,y,x

def modinv_eg(a,m):
    m0, x0, x1 = m,0,1
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
        k = random.randint(1, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g,k,p)
    k_inv = modinv_eg(k,p-1)
    s = ((msg_hash - x*r)*k_inv) % (p-1)
    return r,s

def elgamal_verify(msg_hash,r,s,p,g,y):
    v1 = (pow(y,r,p)*pow(r,s,p)) % p
    v2 = pow(g,msg_hash,p)
    return v1 == v2

def md5_int(data):
    return int(hashlib.md5(data.encode()).hexdigest(),16)

def handle_client(conn, addr, rsa_keys, eg_keys):
    n, e, d = rsa_keys
    p, g, y, x = eg_keys
    sellers = []
    while True:
        menu = '1. Add Seller\n2. Summary and Sign\n3. Exit\nChoice: '
        conn.sendall(menu.encode())
        choice = conn.recv(4096).decode().strip()
        if choice == '1':
            conn.sendall('Seller Name: '.encode())
            name = conn.recv(4096).decode().strip()
            conn.sendall('Number of Transactions: '.encode())
            n_tx = int(conn.recv(4096).decode().strip())
            txs, txs_enc = [], []
            for _ in range(n_tx):
                conn.sendall('Transaction Amount: '.encode())
                amt = int(conn.recv(4096).decode().strip())
                c = rsa_encrypt(amt,e,n)
                txs.append(amt)
                txs_enc.append(c)
            sellers.append({'name':name,'txs':txs,'txs_enc':txs_enc})
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
                decs = [rsa_decrypt(c,d,n) for c in txs_enc]
                total_dec = rsa_decrypt(total_enc,d,n)
                summary += f'{name},{",".join(map(str,txs))},{",".join(map(str,txs_enc))},{",".join(map(str,decs))},{total_enc},{total_dec}\n'
                results.append((name,txs,txs_enc,decs,total_enc,total_dec))
            hash_val = md5_int(summary)
            r,s = elgamal_sign(hash_val,p,g,x)
            verify = elgamal_verify(hash_val,r,s,p,g,y)
            resp = '\n===== Transaction Summary =====\n'
            resp += 'Seller Name | Individual Amounts | Encrypted Amounts | Decrypted Amounts | Total Encrypted | Total Decrypted | Signature | Verification\n'
            for rsl in results:
                resp += f'{rsl[0]} | {rsl[1]} | {rsl[2]} | {rsl[3]} | {rsl[4]} | {rsl[5]} | ({r},{s}) | {verify}\n'
            conn.sendall(resp.encode())
        elif choice == '3':
            break
    conn.close()

def main():
    rsa_keys = rsa_keygen()
    eg_keys = elgamal_keygen()
    s = socket.socket()
    s.bind(('localhost', 5191))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, rsa_keys, eg_keys)).start()

main()
