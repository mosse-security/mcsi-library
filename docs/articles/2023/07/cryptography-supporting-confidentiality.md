:orphan:
(cryptography-supporting-confidentiality)=

# Cryptography Supporting Confidentiality

Cryptography plays a critical role in supporting confidentiality in information security. It ensures that sensitive data remains hidden and protected from unauthorized access or disclosure. Here are the key cryptographic techniques that support confidentiality:

**1.	Symmetric Encryption:** Symmetric encryption is a cryptographic technique where the same secret key is used for both encrypting and decrypting data. This key is shared between the sender and receiver, ensuring secure communication between them. When data is encrypted using symmetric encryption, it becomes unreadable to anyone without the corresponding secret key. Common symmetric encryption algorithms include Advanced Encryption Standard (AES) and Data Encryption Standard (DES).

**2.	Asymmetric Encryption:** Asymmetric encryption, also known as public-key encryption, involves a pair of mathematically related keys: a public key and a private key. The public key is used for encryption, while the private key is used for decryption. With this setup, anyone can encrypt data using the recipient's public key, but only the recipient possessing the corresponding private key can decrypt and read the data. Asymmetric encryption is commonly used for secure key exchange and digital signatures. Examples of asymmetric encryption algorithms include RSA and Elliptic Curve Cryptography (ECC).

**3.	Hybrid Encryption:** Hybrid encryption is a combination of symmetric and asymmetric encryption. In hybrid encryption, data is encrypted using a randomly generated symmetric key (session key). The session key is then encrypted using the recipient's public key and sent along with the encrypted data. The recipient can use their private key to decrypt the session key and then use the session key to decrypt the data. This approach combines the efficiency of symmetric encryption with the security of asymmetric encryption.

**4.	Hash Functions (One-Way Encryption):** Hash functions are one-way cryptographic functions that convert data into fixed-size hash values or digests. Unlike encryption, hash functions are irreversible, meaning it is computationally infeasible to retrieve the original data from its hash value. Hash functions are commonly used to securely store passwords or verify data integrity. Examples of hash functions include SHA-256 and SHA-3.

## Application of Encryption Techniques

Encryption is a versatile cryptographic technique that supports confidentiality for both data-at-rest and data-in-transit. Let's explore how encryption is applied in each scenario:

### Data-at-Rest (File Encryption)

Data-at-rest refers to data that is stored on a storage medium, such as hard drives, solid-state drives, or databases. File encryption is used to protect data when it is not actively being used and is stored on these storage devices. File encryption ensures that even if unauthorized individuals gain physical access to the storage medium, they will not be able to read or understand the encrypted data without the appropriate decryption key.

#### How it works:

**•	Data Encryption:** File encryption software or encryption libraries encrypt the data before it is stored on the storage medium. This process converts the plaintext data into ciphertext using cryptographic algorithms and a secret encryption key.

**•	Decryption:** When authorized users or applications need to access the data, they use the corresponding decryption key to convert the ciphertext back into plaintext, making it readable and usable.

### Data-in-Transit (Transport Encryption)

Data-in-transit refers to data that is actively being transmitted or communicated between two parties over a network. Transport encryption, often referred to as secure transport or secure socket layer (SSL) encryption, is used to protect data during transmission to prevent unauthorized interception or eavesdropping by attackers.

#### How it works:

**•	Secure Sockets Layer (SSL) or Transport Layer Security (TLS):** SSL/TLS protocols establish secure and encrypted connections between the sender and receiver. They use asymmetric encryption during the initial handshake to negotiate symmetric encryption keys that will be used for the actual data transmission.

**•	Data Encryption:** The data transmitted between the sender and receiver is encrypted using the negotiated symmetric encryption keys, ensuring that even if intercepted, the data remains unreadable and secure.

**•	Decryption:** Upon receipt, the recipient uses the same symmetric encryption keys to decrypt the data, making it accessible and usable.

## Conclusion

In both scenarios, encryption helps to maintain the confidentiality of sensitive data. Whether the data is stored on a device (data-at-rest) or being transmitted over a network (data-in-transit), encryption provides a robust layer of protection against unauthorized access and eavesdropping. Properly implemented encryption helps ensure data remains confidential, even in the face of security breaches or unauthorized access attempts.