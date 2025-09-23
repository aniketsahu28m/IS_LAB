# IS_LAB
LAB1 Q1- ADDITIVE, MULTIPLICATIVE, AFFINE
LAB1 Q2- VIGENERE, AUTOKEY
LAB1 Q3- PLAYFAIR
LAB1 Q4- HILL
LAB1 Q5-
LAB1 Q6- BRUTE FORCE ATTACK
LAB1 ADQ1- BRUTE FORCE ADDITIVE
LAB1 ADQ2-

LAB2 Q1- DES
LAB2 Q2- AES-128
LAB2 Q3- COMPARE DES AND AES-128
LAB2 Q4- TRIPLE DES
LAB2 Q5- AES-192
LAB2 ADQ1- AES(128,192,256) VS DES 
LAB2 ADQ2- DES
LAB2 ADQ3- AES-256
LAB2 ADQ4- DES IN CBC WITH IV
LAB2 ADQ5- AES IN CTR 

LAB3 Q1- RSA
LAB3 Q2- ECC
LAB3 Q3- ELGAMAL
LAB3 Q4- RSA(2048BIT) ECC(SECP256 CURVE) EXCHANGE KEYS FILE TRANSFER AND COMPARE
LAB3 Q5- DIFFIE HELLMAN
LAB3 ADQ1- ELGAMAL
LAB3 ADQ2- ECC
LAB3 ADQ3- RSA
LAB3 ADQ4- ELGAMAL ECC COMPARE ENCRYPT DECRPYT
LAB3 ADQ5- RSA ELGAMAL PERFORMANCE SECURITY

LAB4
Q1
SecureCorp is a large enterprise with multiple subsidiaries and business units located
across different geographical regions. As part of their digital transformation initiative,
the IT team at SecureCorp has been tasked with building a secure and scalable
communication system to enable seamless collaboration and information sharing
between their various subsystems.

The enterprise system consists of the following key subsystems:
1. Finance System (System A): Responsible for all financial record-keeping, accounting,
and reporting.
2. HR System (System B): Manages employee data, payroll, and personnel related
processes.
3. Supply Chain Management (System C): Coordinates the flow of goods, services, and
information across the organization's supply chain
These subsystems need to communicate securely and exchange critical documents, such
financial reports, employee contracts, and procurement orders, to ensure the enterprise's
overall efficiency.
The IT team at SecureCorp has identified the following requirements for the secure
communication and document signing solution:
1. Secure Communication: The subsystems must be able to establish secure
communication channels using a combination of RSA encryption and Diffie-Hellman
27
key exchange.
2. Key Management: SecureCorp requires a robust key management system to generate,
distribute, and revoke keys as needed to maintain the security of the enterprise system.
3. Scalability: The solution must be designed to accommodate the addition of new
subsystems in the future as SecureCorp continues to grow and expand its operations.
Implement a Python program which incorporates the requirements.

LAB4 Q2
HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
management system using the Rabin cryptosystem. The system allows authorized
healthcare professionals to securely access and manage patient records across multiple
hospitals and clinics within the organization. Implement a Python-based centralized key
management service that can:
• Key Generation: Generate public and private key pairs for each hospital and clinic
using the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
• Key Distribution: Provide a secure API for hospitals and clinics to request and receive
their public and private key pairs.
• Key Revocation: Implement a process to revoke and update the keys of a hospital or
clinic when necessary (e.g., when a facility is closed or compromised).
• Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
intervals (e.g., every 12 months) to maintain the security of the patient data management
system.
• Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring
that they are not accessible to unauthorized parties.
• Auditing and Logging: Maintain detailed logs of all key management operations, such
as key generation, distribution, revocation, and renewal, to enable auditing and
compliance reporting.
• Regulatory Compliance: Ensure that the key management service and its operations are
compliant with relevant data privacy regulations (e.g., HIPAA).
• Perform a trade-off analysis to compare the workings of Rabin and RSA

LAB4 ADQ1
DigiRights Inc. is a leading provider of digital content, including e-books, movies, and
music. The company has implemented a secure digital rights management (DRM)
system using the ElGamal cryptosystem to protect its valuable digital assets.
Implement a Python-based centralized key management and access control service that
can:
• Key Generation: Generate a master public-private key pair using the ElGamal
cryptosystem. The key size should be configurable (e.g., 2048 bits).
• Content Encryption: Provide an API for content creators to upload their digital content
and have it encrypted using the master public key.
• Key Distribution: Manage the distribution of the master private key to authorized
customers, allowing them to decrypt the content.
• Access Control: Implement flexible access control mechanisms, such as:
 Granting limited-time access to customers for specific content
 Revoking access to customers for specific content
 Allowing content creators to manage access to their own content
• Key Revocation: Implement a process to revoke the master private key in case of a
security breach or other emergency.
• Key Renewal: Automatically renew the master public-private key pair at regular
intervals (e.g., every 24 months) to maintain the security of the DRM system.
• Secure Storage: Securely store the master private key, ensuring that it is not accessible
to unauthorized parties.
• Auditing and Logging: Maintain detailed logs of all key management and access
control operations to enable auditing and troubleshooting.

ADQ2
Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their
sensitive communications. However, the security team at XYZ Logistics has discovered
that one of their employees, Eve, has obtained a partial copy of the RSA private key and
is attempting to recover the full private key to decrypt the company's communications.
Eve's attack involves exploiting a vulnerability in the RSA key generation process,
where the prime factors (p and q) used to generate the modulus (n) are not sufficiently
large or random.
Develop a Python script that can demonstrate the attack on the vulnerable RSA
cryptosystem and discuss the steps to mitigate the attack.

LAB5 Q1
Implement the hash function in Python. Your function should start with an initial hash
value of 5381 and for each character in the input string, multiply the current hash value
by 33, add the ASCII value of the character, and use bitwise operations to ensure
thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range
by applying an appropriate mask

LAB5 Q2
Using socket programming in Python, demonstrate the application of hash functions
for ensuring data integrity during transmission over a network. Write server and client
scripts where the server computes the hash of received data and sends it back to the
client, which then verifies the integrity of the data by comparing the received hash with
the locally computed hash. Show how the hash verification detects data corruption
or tampering during transmission.

LAB5 Q3
Design a Python-based experiment to analyze the performance of MD5, SHA-1, and
SHA-256 hashing techniques in terms of computation time and collision resistance.
Generate a dataset of random strings ranging from 50 to 100 strings, compute the hash
values using each hashing technique, and measure the time taken for hash computation.
Implement collision detection algorithms to identify any collisions within the hashed

LAB5 Q4
Write server and client scripts where the client sends a message in multiple parts to
the server, the server reassembles the message, computes the hash of the reassembled
message, and sends this hash back to the client. The client then verifies the integrity of
the message by comparing the received hash with the locally computed hash of the
original message.

LAB6
Lab Exercises
1. Try using the Elgammal, Schnor asymmetric encryption standard and verify the above
steps.
2. Try using the Diffie-Hellman asymmetric encryption standard and verify the above
steps.
3. Try the same in a client server-based scenario and record your observation and
analysis.
Additional Exercise
1. Explore the link https://www.nmichaels.org/rsa.py for better understanding.
Demonstrate CIA traid using RSA encryption and digital signature along with SHA
hashing.


