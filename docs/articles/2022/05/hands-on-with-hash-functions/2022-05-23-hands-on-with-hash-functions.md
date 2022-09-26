:orphan:
(hands-on-with-hash-functions)=

# Hands-on with Hash Functions

In this blog we are going to cover hash functions, most popular algorithms used in modern appliances and make a quick excercise to solidify our technical skills by comparing SHA256 hashes of two identical and slightly modified _.txt_ files. Let's start with a broad look on digital signatures.

## Introduction

To generate a digital signature, first, we generate a unique message digest from the plaintext message using a particular mathematical function called a hash function. Hash functions are built in such a way that messages and message digests have a one-to-one mapping; that is, no two messages will yield the same hash result.

If the technique is not correctly implemented, or if the message digest is not long enough for the maximum message length, the one-to-one mapping may fail, resulting in a collision, in which two messages have the same message digest.

## Message digest functions

- The digest function returns hexadecimal values. The digest produced has a comparable size and is considered the constrained form of the supplied input text.

- Algorithms are all based on bit manipulation, which is done numerous times to make algorithm reversal difficult and to take the time necessary to undertake brute-force analysis infeasibly long.

- Message digest functions extract the information in a file to a single huge integer (usually 128-256 bits in length).

- Message digests are one-way hash functions because they yield values that are difficult to reverse, resistant to attack, and unique.

Hashing categories are based on the mathematical technique used to calculate the hash value. Let's have a look at several hashing algorithms.

## Hashing algorithms

In cryptography, algorithms are frequently given generic names or names based on the last names of the algorithm's creators.

### MD2, MD4, MD5 family

Ronald Rivest created the message digest (MD) category of algorithms to be utilized in digital signatures. All Message Digest algorithms have demonstrated collision resistance.

**MD2**

- It generates a fixed 128-bit digest.
- It is designed to run on 8-bit CPUs.
- The most secure of Rivest's message digest algorithms, but it is
- The most time-consuming Rivest message digest algorithms to compute.
- It is not widely used.

**MD4**

- It generates a fixed 128-bit digest.
- It was created as a quick replacement for MD2.
- It was later shown to contain a potential flaw.
- MD4 has known collision vulnerabilities. As a result, it is not regarded as secure.

**MD5**

- It generates a fixed 128-bit digest.
- It is designed to run on 32-bit CPUs.
- It was developed with increased security measures as a substitute for MD4.
- MD5 checksums are routinely used in SSL, X.509 certificates, and Authenticode technology from Microsoft.
- MD5 has also collision vulnerabilities. For this reason, it is regarded as insecure.
- Instead of MD5, an alternative hashing method (such as SHA-2) should be used.

### Secure Hash Algorithm(SHA) family

The SHA (Secure Hash Algorithm) family refers to a group of six hash functions: SHA-0, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.

The acronym SHA refers to a group of algorithms chosen by the National Institute of Standards and Technology (NIST) and the NSA to offer standardized cryptographic hash functions for general public usage.

**SHA-0 and SHA-1**

- For every input less than 2^64 bits, it generates a fixed 160-bit message digest.
- In most IPSec deployments, SHA-1 is employed.

The following SHA-256, SHA-384, and SHA-512 algorithms have officially substituted for the original SHA.

**SHA-256**

- For every input less than 2^64 bits, SHA-256 generates a 256-bit message digest.

**SHA-384**

- For every input smaller than 2^128 bits, SHA-384 generates a 384-bit message digest.

**SHA-512**

For every input smaller than 2^128 bits, SHA-512 generates a 512-bit message digest.

## Hands on with file integrity checking on Windows Powershell.

_Estimated time: 5 minutes_

In this quick exercise, we will compute the hash value of a text file with the SHA256 algorithm. Then we will replicate the file and make a slight change. Lastly, compare the hash results.

`Get-FileHash` command will compute the hash value of a given file using the hash algorithm we specify.

**Step-1)** Create a text file on your computer.

``` {thumbnail} images/hashing14.png
```

**Step-2)** Open Powershell, change the directory to where your file is located or specify the full path of your file in the following command by replacing the filename with yours.

` Get-FileHash .\hash.txt`

``` {thumbnail} images/hashing13.png
```

**Step-3)** Duplicate the file and make a slight change in the content.
Run this code, replacing the file name with yours:

` Get-FileHash .\hash - Copy.txt`

``` {thumbnail} images/hashing16.png
```
``` {thumbnail} images/hashing17.png
```

**Step-4)** Compare the two SHA256 results

`(Get-FileHash .\hash.txt -A SHA256).hash -eq (Get-FileHash '.\hash - Copy.txt' -A SHA256).hash`

``` {thumbnail} images/hashing18.png
```

**Step-5)** Now let’s go back to your duplicated file and remove the modification. Now the two files have the same content.

``` {thumbnail} images/hashing19.png
```

**Step-6)** Let’s check their hashes with SHA256 again.
Run the last command again.

``` {thumbnail} images/hashing20.png
```

Congratulations! You have successfully made a file integrity check on Windows Powershell using SHA256 algorithm.
