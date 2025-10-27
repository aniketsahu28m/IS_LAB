"""
Client-Server Program for Seller and Payment Gateway
Demonstrates Paillier homomorphic encryption and RSA digital signatures
"""

import socket
import json
import threading
import hashlib
import time
from typing import List, Dict, Tuple
import random

# Paillier Encryption Implementation
class PaillierKey:
    """Paillier encryption key pair"""
    def __init__(self, n, g, lambd, mu):
        self.n = n
        self.g = g
        self.lambd = lambd
        self.mu = mu
        self.n_sq = n * n

def gcd(a, b):
    """Greatest common divisor"""
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    """Least common multiple"""
    return abs(a * b) // gcd(a, b)

def mod_inverse(a, m):
    """Modular multiplicative inverse"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m

def generate_prime(bits=512):
    """Generate a prime number (simplified for demonstration)"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_paillier_keypair(bits=512):
    """Generate Paillier key pair"""
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    n = p * q
    g = n + 1
    lambd = lcm(p - 1, q - 1)
    mu = mod_inverse(lambd, n)
    
    return PaillierKey(n, g, lambd, mu)

def paillier_encrypt(m, public_key):
    """Encrypt message using Paillier encryption"""
    n = public_key.n
    g = public_key.g
    n_sq = public_key.n_sq
    
    r = random.randrange(1, n)
    while gcd(r, n) != 1:
        r = random.randrange(1, n)
    
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def paillier_decrypt(c, private_key):
    """Decrypt ciphertext using Paillier decryption"""
    n = private_key.n
    lambd = private_key.lambd
    mu = private_key.mu
    n_sq = private_key.n_sq
    
    u = pow(c, lambd, n_sq)
    l = (u - 1) // n
    m = (l * mu) % n
    return m

def paillier_add(c1, c2, public_key):
    """Homomorphic addition of encrypted values"""
    return (c1 * c2) % public_key.n_sq

# RSA Digital Signature Implementation
class RSAKey:
    """RSA key pair for digital signatures"""
    def __init__(self, n, e, d=None):
        self.n = n
        self.e = e
        self.d = d

def generate_rsa_keypair(bits=512):
    """Generate RSA key pair"""
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
    
    d = mod_inverse(e, phi)
    
    return RSAKey(n, e, d), RSAKey(n, e)

def rsa_sign(message, private_key):
    """Sign message using RSA"""
    # Hash the message using SHA-256
    hash_obj = hashlib.sha256(message.encode())
    hash_int = int.from_bytes(hash_obj.digest(), byteorder='big')
    
    # Reduce hash to fit within modulus
    hash_int = hash_int % private_key.n
    
    # Sign the hash
    signature = pow(hash_int, private_key.d, private_key.n)
    return signature

def rsa_verify(message, signature, public_key):
    """Verify RSA signature"""
    # Hash the message
    hash_obj = hashlib.sha256(message.encode())
    hash_int = int.from_bytes(hash_obj.digest(), byteorder='big')
    hash_int = hash_int % public_key.n
    
    # Verify signature
    decrypted_hash = pow(signature, public_key.e, public_key.n)
    return hash_int == decrypted_hash

# Transaction and Seller Classes
class Transaction:
    """Represents a single transaction"""
    def __init__(self, amount: float):
        self.amount = amount
        self.encrypted_amount = None
    
    def encrypt(self, public_key):
        """Encrypt transaction amount"""
        self.encrypted_amount = paillier_encrypt(int(self.amount * 100), public_key)
    
    def to_dict(self):
        return {
            'amount': self.amount,
            'encrypted_amount': self.encrypted_amount
        }

class Seller:
    """Represents a seller with transactions"""
    def __init__(self, name: str):
        self.name = name
        self.transactions: List[Transaction] = []
        self.total_encrypted = None
        self.total_decrypted = None
        self.signature = None
        self.verified = None
    
    def add_transaction(self, amount: float):
        """Add a transaction"""
        self.transactions.append(Transaction(amount))
    
    def encrypt_transactions(self, public_key):
        """Encrypt all transactions"""
        for txn in self.transactions:
            txn.encrypt(public_key)
    
    def compute_total_encrypted(self, public_key):
        """Compute total using homomorphic addition"""
        if not self.transactions:
            return
        
        self.total_encrypted = self.transactions[0].encrypted_amount
        for txn in self.transactions[1:]:
            self.total_encrypted = paillier_add(
                self.total_encrypted, 
                txn.encrypted_amount, 
                public_key
            )
    
    def decrypt_total(self, private_key):
        """Decrypt the total amount"""
        if self.total_encrypted:
            self.total_decrypted = paillier_decrypt(self.total_encrypted, private_key) / 100
    
    def get_summary(self) -> str:
        """Get transaction summary as string"""
        summary = f"Seller: {self.name}\n"
        summary += "Transactions:\n"
        for i, txn in enumerate(self.transactions, 1):
            summary += f"  Transaction {i}: ${txn.amount:.2f}\n"
            summary += f"    Encrypted: {txn.encrypted_amount}\n"
        summary += f"Total Encrypted: {self.total_encrypted}\n"
        summary += f"Total Decrypted: ${self.total_decrypted:.2f}\n"
        return summary
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'transactions': [txn.to_dict() for txn in self.transactions],
            'total_encrypted': self.total_encrypted,
            'total_decrypted': self.total_decrypted,
            'signature': self.signature,
            'verified': self.verified
        }

# Payment Gateway Server
class PaymentGatewayServer:
    """Server that processes transactions from sellers"""
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.paillier_key = generate_paillier_keypair(bits=256)
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keypair(bits=512)
        self.sellers: List[Seller] = []
    
    def start(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"Payment Gateway Server started on {self.host}:{self.port}")
        print(f"Paillier Public Key (n): {self.paillier_key.n}")
        print(f"RSA Public Key (n, e): ({self.rsa_public_key.n}, {self.rsa_public_key.e})\n")
        
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address}")
            thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            thread.start()
    
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # Send public keys to client
            keys_data = {
                'paillier_n': self.paillier_key.n,
                'paillier_g': self.paillier_key.g,
                'rsa_n': self.rsa_public_key.n,
                'rsa_e': self.rsa_public_key.e
            }
            client_socket.send(json.dumps(keys_data).encode())
            
            # Receive seller data
            data = client_socket.recv(65536).decode()
            seller_data = json.loads(data)
            
            # Create seller and process transactions
            seller = Seller(seller_data['name'])
            for amount in seller_data['transactions']:
                seller.add_transaction(amount)
            
            # Encrypt transactions
            seller.encrypt_transactions(self.paillier_key)
            
            # Compute total using homomorphic addition
            seller.compute_total_encrypted(self.paillier_key)
            
            # Decrypt total
            seller.decrypt_total(self.paillier_key)
            
            # Generate signature for the summary
            summary_str = seller.get_summary()
            seller.signature = rsa_sign(summary_str, self.rsa_private_key)
            
            # Verify signature
            seller.verified = rsa_verify(summary_str, seller.signature, self.rsa_public_key)
            
            self.sellers.append(seller)
            
            # Send response back to client
            response = {
                'status': 'success',
                'seller': seller.to_dict()
            }
            client_socket.send(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def print_all_summaries(self):
        """Print summaries for all sellers"""
        print("\n" + "="*80)
        print("COMPLETE TRANSACTION SUMMARY FOR ALL SELLERS")
        print("="*80)
        
        for seller in self.sellers:
            print(f"\n{'─'*80}")
            print(f"SELLER: {seller.name}")
            print(f"{'─'*80}")
            
            print("\nIndividual Transactions:")
            for i, txn in enumerate(seller.transactions, 1):
                print(f"  Transaction {i}:")
                print(f"    Amount: ${txn.amount:.2f}")
                print(f"    Encrypted Amount: {txn.encrypted_amount}")
            
            print(f"\nTotal Encrypted Transaction Amount: {seller.total_encrypted}")
            print(f"Total Decrypted Transaction Amount: ${seller.total_decrypted:.2f}")
            
            print(f"\nDigital Signature: {seller.signature}")
            print(f"Signature Verification Result: {'✓ VERIFIED' if seller.verified else '✗ FAILED'}")
        
        print("\n" + "="*80)
        print("END OF SUMMARY")
        print("="*80 + "\n")

# Seller Client
class SellerClient:
    """Client representing a seller"""
    def __init__(self, name: str, transactions: List[float]):
        self.name = name
        self.transactions = transactions
    
    def connect_and_send(self, host='localhost', port=5555):
        """Connect to payment gateway and send transactions"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            
            # Receive public keys
            keys_data = json.loads(client_socket.recv(4096).decode())
            print(f"\n{self.name} received public keys from Payment Gateway")
            
            # Send transaction data
            data = {
                'name': self.name,
                'transactions': self.transactions
            }
            client_socket.send(json.dumps(data).encode())
            print(f"{self.name} sent {len(self.transactions)} transactions")
            
            # Receive response
            response = json.loads(client_socket.recv(65536).decode())
            print(f"{self.name} received confirmation: {response['status']}")
            
            client_socket.close()
            return response
            
        except Exception as e:
            print(f"Error in {self.name}: {e}")
            return None

# Main Execution
def main():
    """Main function to run the demonstration"""
    print("Starting Payment Gateway System")
    print("="*80 + "\n")
    
    # Start server in a separate thread
    server = PaymentGatewayServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Create sellers with transactions
    sellers_data = [
        ("Alice's Electronics", [150.50, 275.25, 89.99]),
        ("Bob's Bookstore", [45.00, 67.50, 120.75, 33.25]),
        ("Carol's Crafts", [200.00, 150.00])
    ]
    
    # Send transactions from each seller
    print("\nSellers sending transactions to Payment Gateway:")
    print("-" * 80)
    
    for name, transactions in sellers_data:
        seller_client = SellerClient(name, transactions)
        seller_client.connect_and_send()
        time.sleep(0.5)
    
    # Wait for all processing to complete
    time.sleep(2)
    
    # Display complete summary
    server.print_all_summaries()

if __name__ == "__main__":
    main()
