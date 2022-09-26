:orphan:
(an-insight-into-multi-factor-authentication)=
# An Insight into Multi Factor Authentication
 
The process of authenticating a user's identification is known as authentication. When you log in to a website, the website uses your username and password to verify your identity. You will be unable to log in if the website is unable to authenticate your identity. There are several methods for confirming a user's identity. Using a username and password is the most popular technique. Passwords can be guessed or stolen, making this the least secure option. Other technologies, like fingerprint and iris scanners, are becoming increasingly common.

Although biometrics, such as fingerprint or iris scanners, are more secure than passwords, they may be circumvented. Two-factor authentication, which necessitates two pieces of identity, is more secure than passwords or fingerprints but can be cumbersome. Regardless of the mechanism employed, the purpose of authentication is to ensure that only those who are supposed to have access to a website or system may receive access. This is critical for security reasons.

## Two-Factor Authentication (2FA)

Two-factor authentication is a vital security technique that may aid in the protection of your online accounts. After entering your login and password, you will be requested to input a second factor, such as a code from a mobile app, if Two-Factor Authentication is enabled. This makes it far more difficult for someone, even if they have your password, to access your account. Although two-factor authentication is not perfect, it is a solid security technique that may help safeguard your online accounts. It is critical to use a strong password and to turn on Two-Factor Authentication whenever feasible. Two-factor authentication (2FA) has several advantages, but the three main advantages are that it gives an extra layer of protection to your account, it helps to safeguard your account if your password is hacked, and it may be used as a recovery mechanism if you forget it.

## One-time Passwords (OTP)

As a second factor, so-called one-time passwords are frequently utilised. These can be drawn from a list or produced by a generator. In any event, while using these OTPs, it must be assured that the server and client (system and user) always know which OTP is now valid synchronously. One-time passwords (OTPs) are frequently employed as a second factor in two-factor authentication, but they may also be used as an autonomous security mechanism in addition to two-factor authentication. This method is really extremely ingenious since it reduces the dangers associated with maintaining a password with the online service provider. In the case of a security compromise, attackers would be unable to get vital login information.

There are two kinds of OTP:

### TOTP

TOTP is a time-based one-time password (OTP). TOTP has a static seed, but the movement factor is time-based rather than counter-based. A timestep is the period of time that each password is valid. Timesteps are typically 30 seconds or 60 seconds long. If you haven't used your password within that window, it will be invalid and you will need to get a new one to access your application.

### HOTP

HMAC-based One Time Password (HOTP) is a one-time password generation technique that employs a cryptographic key and a message digest. A hashing method, such as SHA-1, is used to construct the message digest, which is then paired with a symmetric key algorithm, such as HMAC. The one-time password generated is then used to authenticate a user.

## Multi-Factor Authentication (MFA)

As the combination of different authentication techniques grew, 2FA has now been superseded by MFA. Multi-factor authentication is simply the combination of 2 or more authentication techniques. When it comes to authentication, there isn’t any solution that fits all the cases. The optimal strategy is to utilise a mix of approaches, such as something the user knows (such as a password), something the user has (such as a token or key), and something the user is aware of (like their biometric data). You may make it far more difficult for someone to obtain illegal access to your systems by employing various ways.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::