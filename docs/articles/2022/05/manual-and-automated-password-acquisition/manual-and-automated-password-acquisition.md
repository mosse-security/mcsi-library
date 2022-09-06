:orphan:
(manual-and-automated-password-acquisition)=

# Manual and automated password acquisition

Password attack/cracking is one crucial step in the art of system hacking. When performing penetration tests, passwords can be obtained in a variety of ways. These can range from manually obtaining them from the target to using advanced automated attacks such as packet sniffing and brute force.

## Non-Electronic Attacks:

There are many different types of password attacks, but non-electronic attacks are perhaps the most difficult to defend against. This is because they don't rely on breaking any electronic security, but instead exploit human weaknesses.

_Different types of Non-Electronic Attacks are:_

### Social engineering

Social engineering is the art of manipulating people so that they give up confidential information. The techniques used are generally psychological, and the goal is to trick the victim into revealing information that they would not normally disclose. Social engineering can take many different forms, but all share the common goal of obtaining sensitive information from the victim.

One common approach is known as phishing, where the attacker sends an email that appears to be from a legitimate source, such as a bank or company. The email will typically contain a link that the victim is encouraged to click on, which will then take them to a fake website that looks almost identical to the real thing. The victim is then asked to enter their login credentials, which the attacker can then use to gain access to the victim's account.

### Shoulder Surfing

Shoulder surfing is a technique of stealing passwords by peaking through the victim's shoulders and watching them enter the username and password. However, this attacker requires the attacker to be in close proximity to the victim. Some of the common places where Shoulder surfing is carried out are near ATMs.

## Offline Attacks

Offline attacks are the type of password attacks in which the attacker tries to recover passwords in plaintext. Offline attacks are time-consuming but have a high success rate. Attackers use different types of offline attacks such as rainbow table attacks to crack passwords.

### Rainbow Table attack

A rainbow table attack is a type of cryptanalytic attack that relies on the use of a rainbow table. Rainbow tables are tables of pre-computed hashes that can be used to reverse the hashing process and recover the original password. Rainbow tables are usually used to attack hashes that are generated using weak algorithms, such as MD5 or SHA- These algorithms are easy to reverse, so rainbow tables can be used to quickly recover the original password. Rainbow table attacks are very efficient, but they can be prevented by using strong hashing algorithms, such as SHA-256 or SHA-51 These algorithms are much more difficult to reverse, so rainbow tables are not as effective against them.

## Active password attacks

### Dictionary attacks

A dictionary attack is a type of brute force attack that relies on a list of words, known as a dictionary, in order to guess passwords. Dictionary attacks are one of the most common types of attacks used by hackers, as they can be highly effective in guessing passwords, especially if the passwords are not complex or are based on common words. To carry out a dictionary attack, a hacker will typically use a computer program to try all the words in a dictionary one by one until the correct password is found. This type of attack can be made more effective by using a custom dictionary that includes words related to the target system or organization, such as names of employees, and common misspellings.

### Brute-Force Attack

A brute-force attack is a type of attack in which an attacker attempts to guess the password or keys used to encrypt a piece of information. This type of attack is usually carried out by automated software that can generate large numbers of username and password combinations very quickly. Brute-force attacks can be very time-consuming and often require the use of powerful computers to try every possible combination of characters in a password or key.

## Passive Password Attacks

### Packet sniffing

Packet sniffing is a technique used by malicious actors to intercept and collect data passing through a network. By using a specialized device or software, an attacker can eavesdrop on communications and collect sensitive information, such as login credentials, financial data, and more.

### Person in the middle attack

A person-in-the-middle attack is a type of cyber-attack in which the attacker intercepts communication between two parties (the user and the application) in order to obtain information or data. This type of attack can be difficult to detect and the primary objective is to steal sensitive information like login credentials, personal information, and financial details.

Check out this blog to know more about [PITM](be-aware-of-person-in-the-middle-attacks-and-take-steps-to-prevent-them)

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
