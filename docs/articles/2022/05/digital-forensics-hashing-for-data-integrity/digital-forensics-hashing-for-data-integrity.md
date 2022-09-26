:orphan:
(digital-forensics-hashing-for-data-integrity)=

# Digital Forensics: Hashing for Data Integrity

Hashing is a digital fingerprinting technique used to ensure the integrity of data. When data is hashed, a mathematical algorithm is used to generate a unique code that corresponds to the data. This code, called a hash, can be used to verify that the data has not been modified. If even one bit of the data is changed, the hash will be different. In this article, we explain the importance of hashing in digital forensics.

## Introduction

Here is a conversation between two friends to introduce the concept of hashing and its importance in digital forensics.

Jane is a digital forensic investigator helping John whose computer had been hijacked by malware. Jane had taken a _[memory dump](uncover-crucial-information-within-memory-dumps)_ from John’s computer. She is almost done processing it. Here is a snippet from their conversation.

_Jane_: I have identified the executable that has enabled the attacker gain remote access on your computer. It has been executed from the Command Prompt yesterday. I will send you a document about the list of things you can do to prevent such an event from happening in the future.

_John_: Thank you so much, Jane! I would like to clarify one thing - this may seem like a silly question. Are you sure that the malicious executable was already present on my computer? And then it showed up on the memory dump? Is there a chance that the executable could have made its way into the memory dump from your computer?

_Jane_: It is not possible for the malicious executable to have made its way into the memory dump. The dump that I took from your computer has not been modified in any way since I acquired it.

_John_: How can you be so sure that the dump has been modified in any way?

_Jane_: Well, I took a hash of the memory dump immediately after acquiring it and took a hash again once I finished the investigation. The hash values matched, which means that the memory dump has not been tampered with in any way.

_John_: Hash? Can you tell me more about it?

_Jane_: Okay, time for hashing 101.

This blog post briefly describes what hashing is and how it is useful in digital forensics.

## What is hashing?

Say you have a file. You want to find out the hash value of the file. For this, you will use some special algorithms calling hashing algorithms, which take your file as input, run it through some special functions and generate a unique value containing alphanumeric characters. This unique value is called as _hash_. The entire process is referred to as hashing.

Algorithms like MD5 and SHA can be used for hashing. Does this mean you have to run these algorithms manually? No, there are various tools that can do this for you.

If you modify even a single character in the file and re-generate the hash, it would be different from the hash value obtained initially.

## Why is hashing important for digital forensics?

During a forensic investigation, it is of utmost importance to ensure that the integrity of the acquired evidence remains the same throughout the investigation. The state of evidence must remain the same from the moment it was acquired till the moment the investigation is complete. The best way to ensure that is by using hashing.

When a piece of evidence is acquired (forensic image or memory dump or packet capture), immediately generate its hash value using a chosen algorithm. Once the evidence has been processed, generate its hash again using the same algorithm. If both the hash values match, then it means that the evidence has not been altered in any way – its integrity has been preserved.

The evidence can be used to wrap up the investigation. If the integrity of the evidence has not been maintained, then the evidence becomes ‘inadmissible’ or invalid.

## How to generate the hash value for a file?

On Windows computers, the hash value for a file can be generated using tools _CertUtil_ command-line utility or _Get-FileHash_ PowerShell cmdlet.

On Linux-based computers, the hash value can be generated using tools like _md5sum_ or _sha512sum_ or _sha256sum_.

## Project Idea

Here is a small project idea for you:

_Part 1_

- Acquire the memory dump from a computer or VM
- As soon as the dump has been acquired, generate the hash value for the dump and store it in a text file. You can use any hash algorithm of your choice
- Process the memory dump. Print the list of active processes, print the list of network connections, etc.
- Acquire the hash value of the memory dump again
- Ensure that the hashes taken before and after the memory dump has been processed are the same

_Part 2_

- Create a text file and include some content in it
- Generate the hash value for the text file
- Modify a single character in the file and re-generate its hash
- Observe how the hash values are different

As a next step, some points to research about can be:

- How many characters are present in the hash when MD5 algorithm is used?
- How many characters are present in the hash when SHA256 or SHA512 algorithm is used?
- Identify some other utilities that can be used to generate the hash value.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MDFIR - Certified DFIR Specialist](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
