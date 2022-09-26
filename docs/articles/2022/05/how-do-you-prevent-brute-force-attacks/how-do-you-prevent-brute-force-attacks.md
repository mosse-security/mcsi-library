:orphan:
(how-do-you-prevent-brute-force-attacks)=

# How Do You Prevent Brute Force Attacks?

If you want to recover a password, the simplest method is to use a brute force attack. Is brute force really effective? Well, many users appear to utilize birthdates or other historical dates as passwords, or other readily guessed numbers or phrases. Today we are going to examine what a brute force attack is and how we can protect our systems against it.

## Password attacks

Password attacks are particularly widespread since they are simple to execute and frequently result in a successful incursion.

There are two forms of password guessing attacks: brute force and dictionary-based attacks.

## Brute force attacks

- A brute force attack is trying to guess a password by attempting each conceivable combination of characters one at a time (a so-called brute force attack). This is an automated procedure.

- The longer the password, the longer it takes to test every possible combination. There are 2.8 trillion possible password combinations, using eight random characters. Even a powerful computer may take weeks to process all potential combinations.

- Most passwords are between four and sixteen characters long. Despite being enormous, the number of potential password combinations is limited and hence subject to brute force attack.

- Brute force password discovery often entails getting a copy of the login and hashed password listing and then encrypting probable passwords using the same hashing mechanism.

- Some brute force approaches include merely sending probable passwords to the system via remote login attempts. However, due to account lockout features included on most commercial systems (which restrict further login attempts after a set number of wrong inputs) and the fact that they can be easily seen and traced by system administrators, these variations are rarely encountered nowadays.

- They are also very slow.

## How to prevent brute force ?

- Running your own brute-force attack may be an approach to safeguarding your system from one. It is a good idea to run a password cracking tool on your PC on a regular basis. Confirm that you have formal authorization to carry out the attack.

- Set your monitoring system to warn you when unusual activity occurs. You can also set aggressive lockout policies.

- Passwords should be changed once a certain amount of time has passed. You should enforce users to change their password every 45 to 90 days at the maximum.

- Strong password policies should be applied. Strong passwords may still be cracked using a program that executes a brute force attack. However, this method of cracking a password can take a long time.

- Longer passwords make brute force password cracking more difficult, hence the policy should stipulate a minimum password length. The complexity for an attacker trying a brute force attack increases with each bit added. You can create and apply a policy which specifies that passwords can be 8 characters in length at a minimum.

## Conclusion

In this blog post, we explained what a brute force attack is and how to protect our keys.

In its most basic form, brute force refers to attempting as many password combinations as possible until you find the appropriate one. It is a common method for obtaining passwords, particularly if the encrypted password list is available.

Brute force attacks are very simple yet effective, and as security practitioners, we need to prevent unauthorized access to sensitive assets.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
