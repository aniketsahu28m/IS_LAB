import socket
import threading
import random
import hashlib

def gcd(a, b):
    while b:
        a,b = b, a % b
    return a

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

def is_prime(n):
    if n<2:
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

def elgamal_keygen():
    while True:
        p = get_prime(300,500)
        g = random.randint(2,p-2)
        x = random.randint(2,p-2)
        y = pow(g,x,p)
        if pow(g,x,p) != 1 and pow(g,(p-1)//2,p) != 1:
            break
    return p,g,y,x

def elgamal_encrypt(m,p,g,y):
    k = random.randint(1,p-2)
    a = pow(g,k,p)
    b = (m * pow(y,k,p)) % p
    return a,b

def elgamal_decrypt(a,b,x,p):
    s = pow(a,x,p)
    s_inv = modinv(s,p)
    m = (b * s_inv) % p
    return m

def elgamal_sign(msg_hash,p,g,x):
    while True:
        k = random.randint(1,p-2)
        if gcd(k,p-1) == 1:
            break
    r = pow(g,k,p)
    k_inv = modinv(k,p-1)
    s = ((msg_hash - x*r) * k_inv) % (p-1)
    return r,s

def elgamal_verify(msg_hash,r,s,p,g,y):
    v1 = (pow(y,r,p)*pow(r,s,p)) % p
    v2 = pow(g,msg_hash,p)
    return v1 == v2

def md5_int(data):
    return int(hashlib.md5(data.encode()).hexdigest(),16)

def handle_client(conn, addr, elgamal_keys):
    p,g,y,x = elgamal_keys
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
                a,b = elgamal_encrypt(amt,p,g,y)
                txs.append(amt)
                txs_enc.append((a,b))
            sellers.append({'name':name,'txs':txs,'txs_enc':txs_enc})
        elif choice == '2':
            summary = ''
            results = []
            for seller in sellers:
                name = seller['name']
                txs = seller['txs']
                txs_enc = seller['txs_enc']
                total_a,total_b = 1,1
                for a,b in txs_enc:
                    total_a = (total_a * a) % p
                    total_b = (total_b * b) % p
                decs = [elgamal_decrypt(a,b,x,p) for a,b in txs_enc]
                total_dec = elgamal_decrypt(total_a,total_b,x,p)
                summary += f'{name},{",".join(map(str,txs))},{",".join(f"{a}|{b}" for a,b in txs_enc)},{",".join(map(str,decs))},{total_a}|{total_b},{total_dec}\n'
                results.append((name,txs,txs_enc,decs,(total_a,total_b),total_dec))
