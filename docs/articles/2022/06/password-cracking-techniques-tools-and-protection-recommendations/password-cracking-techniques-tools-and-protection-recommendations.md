:orphan:
(password-cracking-techniques-tools-and-protection-recommendations)=
# Password Cracking Techniques, Tools and Protection Recommendations
 

A password is a protected string of characters that is used to authenticate a user. Passwords are the most widely used authentication method, yet they are also the weakest. Users sometimes choose passwords that are exceedingly easy to guess or are based on personal information about the user (e.g. their birth month or the name of their pet). They may even scribble it down on a piece of paper, hide it in a location where it may be easily taken, or share it with others. Organizations that utilize passwords as the primary or one of the sources of authentication should implement proper security controls to prevent them from being compromised as it can have severe implications. This article will go over the basics of password cracking, as well as the techniques and tools used to crack passwords and password protection mechanisms.

## Password Cracking:

Password cracking can be defined as an attack that involves stealing or determining a user's password. It is typically performed after hashed passwords have been extracted from a website's or organization's database. Password cracking can be performed manually or with the help of automated tools. Password cracking is performed for a variety of reasons. The motives of the attacker behind password cracking can be some of the following:

* Gain unauthorized access to a user's account
* Gain unauthorized access to an organization's resources
* Steal sensitive/confidential data
* Planting backdoors
* Selling your data on the dark web
* Escalate privileges to gain a stronger foothold
* Lateral movement to compromise more machines

and so much more. Password cracking can also be performed for benign purposes such as recovering a user's forgotten password, recovering password-protected files, or testing for weak passwords in a network. 

## Techniques for Password Cracking:

Some of the most commonly used techniques for obtaining/cracking passwords are as follows:

### Brute-force Attack:

A brute-force attack is a password cracking technique in which an attacker uses a software program to try various combinations of numbers, characters, and symbols to crack/uncover a user password. This password cracking approach works well with passwords that are only a few characters long. As the length of the password grows, so does the amount of resources needed to crack it. As a result, brute force attacks are the least effective form of password cracking.

### Dictionary Attack:

A dictionary attack is a password cracking method in which an attacker uses files containing thousands of regularly used passwords to crack the password. This attack works by iterating over all of the library's passwords in the hopes of finding a match. This technique will work if the user is in charge of password formation and uses a password that contains regularly used passwords such as a well-known movie, a character, or a commonly used nickname, for example.

### Rainbow Table Attack:

A rainbow table consists of possible passwords in a hashed format. In a rainbow table attack, the attacker compares the hashes of stolen passwords against the hashes contained in the rainbow table to uncover the plaintext password. This attack takes much less time than compared to dictionary attack or brute-force attack and thus it is more efficient for recovering passwords. User passwords are not stored in plaintext in the database; instead, they are hashed. The attacker, after recovering the user passwords from the database, performs the rainbow attack in order to discover user passwords.

### Credential Stuffing:

In a Credential Stuffing attack, an attacker uses a tool to automatically inject a previously acquired list of username and password pairs into a variety of websites in order to recover valid credentials. An attacker obtains these lists through data breaches, password dumps found online, or phishing attacks. These lists are used by the attacker to conduct tests on other websites with the aim of discovering legitimate usernames and passwords. This technique is successful if a user uses the same password on multiple websites, such as his social network accounts, email accounts, marketplace accounts, and so on.

### Person-in-the-Middle Attack:

In the Person-in-the-Middle attack, an attacker intercepts the communication between the sender and the receiver nodes in a network. The motive of the attacker is to recover confidential/sensitive information such as passwords, pins, credit/debit card details, etc. by hijacking and reading the information being exchanged between two devices.

### Social Engineering:

An attacker takes advantage of human behavior and trust instincts to deceive a victim into revealing sensitive/confidential information in a Social Engineering attack. The attacker employs a variety of techniques to persuade the user to reveal sensitive information such as his credentials or financial information. Malicious emails that appear to be legitimate are commonly used in social engineering attempts to get users to visit a link to the attacker's website. Other forms of this attack are carried out through the phone, text messaging, video messages, website advertisements, or even in person in order to steal sensitive user information.

### Keyloggers:

A keylogger is a form of spyware that gets installed on a system and is used to monitor and record a user's keystrokes. Keyloggers are used to steal important information typed by the user such as his username and password, pins, OTPs, account details, and much more. 

### Shoulder Surfing:

Shoulder Surfing attack happens when an attacker/intruder watches over another person's shoulder and closely observes the keystrokes or characters appearing on the screen in order to uncover important information in an unauthorized manner. Shoulder surfing is commonly carried out by adversaries to obtain sensitive information such as passwords, ATM pins, access codes, and much more.

## Commonly used tools for Password Cracking:

Some of the most commonly used to tools used for password cracking are reviewed below:

### John The Ripper:

John the Ripper is an open-source password cracking tool that may be downloaded for a variety of operating systems, including macOS, Windows, and Linux. It is one of the most widely used password cracking tools. In order to find a match, this program autodetects the hashing algorithm used to hash the password and compares it to the hashes of the passwords contained in the plaintext file. It comes pre-installed on the Kali Linux virtual machine for penetration testing purposes.

**How to use it:**
Let's suppose you want to crack a single user password that is contained in the hashed format in a text file named hash.txt. If the password has been hashed using the SHA-1 hashing algorithm, then you use the following command to crack the password:

`john --single --format=raw-SHA1 hash.txt`

You can also use this tool to crack password-protected zip files. In order to generate a hash of the password, we will use the zip2john command and store its output (using > operator) in a file called output.txt. Let's suppose our password-protected zip file is called test.zip. You can use this command to create its hash and store it in output.txt:

`zip2john test.zip > output.txt`

Now use this hash file to crack the password of the zip file as follows:

`john --format=zip output.txt`

You can also specify wordlists to be used in password cracking. A wordlist is a large collection of passwords in plaintext. In kali linux wordlists are found in the /usr/share/wordlists folder. Some of the most commonly used wordlists are rockyou.txt.gz, password.lst(a part of John the ripper), fasttrack.txt,nmap.lst, etc.

In order to use the rockyou.txt wordlist use the following command to unzip it:

`gzip -d /usr/share/wordlists/rockyou.txt.gz`

Next, to crack the file containing password hashes (called hashes.txt) using the rockyou.txt wordlist, use the following command:

`john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-SHA1 hashes.txt`

### Hashcat:

Hashcat is an open-source password recovery tool that can be used on Windows, macOS, and Linux operating systems. This tool can be used for cracking passwords in numerous hashed formats and supports different attack modes. This tool is used for automated recovery of passwords and can also be used for penetration testing purposes to discover weak or default passwords used in an organization's infrastructure. This tool also comes preinstalled on different versions of Kali Linux.

**How to use HashCat:**

Before you can start using this tool for password recovery purposes, it is important to understand different parameters that are used with hashcat. 

* -m indicates the type of the hashing algorithm. This type is specified with a numerical value (0 for MD5, 900 for MD4, 100 for SHA1, 1700 for SHA-512, etc.)
* -a indicates the attack mode. The type is also specified with a numerical value (0 for a dictionary attack, 3 for a brute-force attack, 6 for a hybrid attack, etc.)
* -h is used for the help menu
* -o is used for storing the output in the file specified by the user

Let's suppose that we have a file containing password hashes in a file called hashes.txt in SHA-1 format. Now if we want to perform a dictionary attack on the hashes.txt file using the rockyou.txt wordlist, we can use the following command:

`hashcat -m 100 -a 0 -o output.txt hashes.txt /usr/share/wordlists/rockyou.txt`

The output will be stored in the output.txt file in the current working directory and it will contain the passwords that have been cracked successfully. You can check the contents of the file using:

`cat output.txt`

### THC Hydra:

THC Hydra is a multi-threaded, high-performance logon password cracker that works with a wide range of network protocols (FTP, HTTP, SMTP, HTTPS, IMAP, SNMP, etc.). It can be used to recover forgotten credentials by brute-forcing passwords. It is an open source tool that may be downloaded for Windows, Mac OS X, and Linux operating systems. This program can run concurrent searches on many protocols at the same time. This tool can also be used to assess the security of a company's passwords in order to identify weak or default passwords. It is also preinstalled on Kali Linux.

**How to use THC Hydra:**

Before you can start using THC Hydra it is very important to understand its different parameters. Let's review them one by one:

* -l for the login name, -L for the file containing different login names
* -p for the password, -P for the file containing password hashes
* -s port number for the service(it can also be used to specify the port if the service is using a port other than the default port)
* -t for number of parallel tasks per target, -T for parallel tasks overall
* -o for specifying the file for storing the output
* -h for the help menu
* -v for verbose mode

There are many other parameters that can be explored by going through the help menu.

Let us suppose you want to brute force an FTP login with the name 'root' on a target IP address(e.g. 192.168.100.20) and you want to use the rockyou.txt wordlist. If the number of parallel connections to be used is 4 and the output is to be stored in a file output.txt, you can use the following command:

`hydra -l root -P /usr/share/wordlists/rockyou.txt -s 21 -t 4 -o output.txt ftp://192.168.100.20`

In order to understand the process of brute forcing the login form of a website, consider the following example. Let's say the website's login form has the following address and parameters `https://examplesite.com/home/login.php?username=admin&password=password&Login=Login` with an IP address of 192.168.100.20. In order to perform the brute force password cracking, you can use the following command:

`hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.100.20 http-post-form "/home/login.php?username=admin&password=^PASS^&Login=Login:Incorrect Password" -v`

Here ^PASS tells hydra to use the passwords from the wordlist. The text returned for a failed password attempt is 'Incorrect Password'.

### Medusa:

Medusa is a powerful, modular and fast password cracking tool. It supports a wide variety of network protocols and allows for multi-threaded testing of multiple hosts simultaneously. This tool also allows for flexible user input for hostnames, usernames, and passwords. This tool is also preinstalled on Kali Linux.

**How to use Medusa:**

Before you can start using THC Hydra it is very important to understand its different parameters. Let's review them one by one:

* h for hostname/IP address, H for specifying the filename containing hostnames or IP addresses
* u for username, U for specifying the filename containing a list of usernames
* p for the password, P for password wordlist
* t for number of logins to be tested concurrently, T for number of hosts to be tested concurrently
* v for verbosity level 0-6
* h is for the help menu
* O for specifying the output file to store the output
* M for the module (for the service) to be used
* m for specifying the parameters of the module

Let us suppose that we have an FTP service running on port 21 and the IP address is 192.168.100.20. If we want to brute force the login credentials of the root account using rockyou.txt wordlist, we can use the following command:

`medusa -h 192.168.100.20 -u root -P /usr/share/password/rockyou.txt -M ftp`

## Password Protection Recommendations:
This section goes over some of the recommendations for protecting user passwords in an organization or an application. These recommendations are as follows:

1. Enforce strict password requirements through the use of password policies and security controls. The passwords should be at least 8 characters long with the requirement of at least one uppercase, one lowercase, one number, and one special character. 

2. Users should be prompted to change passwords periodically and password reuse should be discouraged.

3. Users should not be allowed to use passwords that are very common or be based on the information that can be easily discoverable about them from their digital footprint.

4. Regular security awareness training sessions should be held to inform employees on safe password practices, how to protect their passwords, and how to avoid social engineering attacks.

5. Security auditing of the passwords should be carried out using reliable password cracking tools to discover weak or default passwords.

6. The default passwords on all the devices must be changed. Avoid using the same username and password for different devices.

7. User login activities should be carefully monitored and logged. The user should be notified of any logins from unknown devices and locations along with the date/time of the login. 

8. Define and implement the threshold for failed login attempts to thwart brute-force attacks, dictionary attacks, or any other exhaustive attacks.

9. Use strong password hashing algorithms to store user passwords in the database. Use password salting to generate stronger password hashes that make them quite difficult to be reverse engineered by the attackers.

10. Use multifactor authentication to protect user accounts from being compromised.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**