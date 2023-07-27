:orphan:
(key-stretching-and-salting)=

# Salting and Key Stretching

Salting and key stretching are two important concepts in password security that aim to enhance the protection of user passwords stored in databases. They are commonly used practices to mitigate the risk of password-related attacks, such as dictionary attacks and rainbow table attacks.

## Salting

Salting is the process of adding random data (a "salt") to each user's password before hashing it. The salt is typically a random string of characters that is unique for each user. When a user creates or updates their password, the system generates a random salt and combines it with the password before hashing. The salt is then stored alongside the hashed password in the database.

The purpose of salting is to prevent attackers from using precomputed tables like rainbow tables for password cracking. Rainbow tables are large databases of precomputed hashes for common passwords, and they allow attackers to quickly look up the plaintext value of a hashed password. By using a unique salt for each user, even if two users have the same password, their hashed values will be different due to the unique salt, making it much more difficult and time-consuming for attackers to crack the passwords.

### Salting Example (using SHA-256)

Suppose a user wants to create a password "mySecretPassword." The system generates a random salt, say "abCdeFg," and then concatenates it with the password:

Password: mySecretPassword Salt: abCdeFg

Combined Password + Salt: mySecretPasswordabCdeFg

Next, the system computes the hash using SHA-256:

Hashed Value: SHA-256("mySecretPasswordabCdeFg")

The resulting hashed value, along with the salt, is then stored in the database:

Stored in Database: Hashed Value + Salt

## Key Stretching

Key stretching, also known as password stretching, is a technique used to slow down the hashing process intentionally. It involves applying a cryptographic function repeatedly (thousands or millions of times) on the password and salt to make the hashing process much slower and computationally expensive.

The purpose of key stretching is to increase the time it takes for an attacker to try different password combinations in a brute-force attack. By significantly slowing down the hashing process for legitimate users as well, key stretching ensures that even with modern computing power, it would take an infeasible amount of time to try a large number of password combinations. This helps protect against brute-force attacks and adds an extra layer of security to the password storage mechanism.

### Key Stretching Example (using PBKDF2)

PBKDF2 (Password-Based Key Derivation Function 2) is a key stretching algorithm that applies a cryptographic hash function repeatedly to increase the computational effort required.
Suppose we have the same password "mySecretPassword" and salt "abCdeFg" as before. We also define the number of iterations to be 10,000 for the key stretching process.

The system applies PBKDF2 with SHA-256 as the underlying hash function and performs 10,000 iterations:

Derived Key: PBKDF2-HMAC-SHA-256("mySecretPasswordabCdeFg", 10000)
The derived key is then stored in the database, along with the original salt and the number of iterations used during the key stretching process:
Stored in Database: Derived Key + Salt + Iterations

When a user attempts to log in, the system takes their entered password, retrieves the corresponding salt from the database, and then performs the same hashing process using the same number of iterations. If the resulting hash matches the stored hash, the password is considered valid.

## Final Words

By using both salting and key stretching, even if an attacker gains access to the hashed passwords in the database, cracking the passwords becomes much more challenging and time-consuming, thus significantly improving the overall security of the system.

In summary, salting and key stretching are essential practices for secure password storage. Salting adds randomness and uniqueness to each password before hashing, while key stretching makes the hashing process deliberately slow, making it much more challenging for attackers to crack passwords using brute-force or precomputed tables. When combined, these techniques significantly improve the overall security of user passwords in databases.
