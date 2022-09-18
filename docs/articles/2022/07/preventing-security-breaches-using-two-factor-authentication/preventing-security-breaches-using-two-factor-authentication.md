:orphan:
(preventing-security-breaches-using-two-factor-authentication)=
# Preventing Security breaches using Two Factor authentication
 
As we continue to use our phones, laptops, and tablets as the hub for all of our digital lives, it becomes increasingly important to protect these devices. Setting passcodes or passwords alone can no longer suffice in protecting the sensitive data housed in our devices, this has given rise to a need for additional layers of stricter and safer controls to fight against unwanted breaches to our critical data, this is where two-factor authentication comes in. 

Two-factor authentication also known as 2FA is a type of multi-factor authentication that requires that a user verifies in two different ways before access to the safeguarded data can be given. This type of authentication is generally considered more secure than single-factor ones because an attacker may figure out the first factor which is usually the username and password, the second factor however requires greater skill to crack.  

Two-factor authentication adds an additional layer of security beyond what you can achieve with just a username and password alone. It requires ‘something you have, ‘something you know, and ‘something you are to verify ownership of an account before access is granted. 

 

## The three methods of authentication are: 

**Something you know:** this can be a combination of a username and a password or code that a user uniquely generates as an authorization identifier.  

**Something you have:** these are things in the possession of a user, for example, a phone, USB drive, smart cards, hardware tokens, etc 

**Something you are:** these are things that are inherent in the user’s physical being such as biometrics which includes facial recognition, fingerprints, voice recognition, retina scan, etc  

 
## Elements of Two-factor authentication

In this section, we will discuss authentications that are often used in to protect user accounts and their pros and cons. 

 **1. Code sent via Sms/Email:** here, a user will be required to submit a phone number or email address that is recorded as a recipient so that after the user must have inputted their username and password, a code will be sent to the phone or device carrying this information in form of a text message or an email, this code is usually a compilation of 6 random numbers that serve as a temporary key which is used to grant access to the account. 

 **Pros:**
  
- This technique is easy to use since most people have a phone that can receive SMS or a smart device that can access emails. 

 - It is a safer option than using only a username and password that can be breached through several malicious techniques like brute force, password spraying, or social engineering. 

 **Cons:**  

- Tendering personal phone numbers to third-party platforms is a risk in itself that a user will have to incur if the platform is compromised   

 - Some websites use registered phone numbers for other purposes users do not consent to like sending targeted advertisements.  

 - Sim swapping: SMS 2FA is susceptible to sim swapping attack, this is when a hacker equipped with all the right information of an unsuspecting user, calls the user’s service provider and requests that their phone number be transferred to another number, as a result, the attacker will receive every message or phone call intended for the legitimate user via the new number. 

 -  Phishing risk: an attacker can send a text message or email using an identical template typically used by the service the user is attempting to access. The message usually contains instructions asking the user to forward the code sent by the legitimate source to the attacker.  

 - SMS are overly simplified: messages sent via text do not have any form of encryption, and the contents flow in the network in plaintext which can be easily intercepted by malicious actors.  

 - Users will be locked out of their accounts if the device that carries the registered phone number or email is dead.  

 **2. Authenticator applications:** To use this method, a user needs to first of all register the accounts they want to protect in the application, this is done by scanning the QR code of the account into the application’s database. Once the account has been registered, anytime a user needs to access their account, the application generates a time-based one-time password (TOTP) as soon as the registered QR code is scanned. The TOTP is a time-sensitive code that refreshes for a particular duration of time, mostly every 30 seconds. During a login process, If a user fails to input the code before the designated time elapses, the code automatically disables and another one is generated to be utilized for the same time duration. 

**Pro:**  

- This technique makes for a more secure option compared to SMS verification because it doesn’t need mobile network services to function since the application is tied to the device directly. 

 - Some authenticator application supports usage on multiple devices, all a user has to do is to download the application into the available device in their possession to assess their accounts.  

 **Cons:**  

 - If the Authenticator app does not have multi-device support, a user may be locked out of their account if the device on which the app was registered is unavailable.  

 - Its time-sensitive nature may get compromised if the application and the device’s clock fail to synchronize.  

 

**3. Hardware token:** The hardware token method has two variants, on one hand, is the disconnected key that has its own LED screen which generates an access code that a user inputs on a login page, this method is popular for e-banking platforms. On the other hand is a device in form of a USB drive that requires physically connecting it to a computer, once the drive is registered on a web application, all you have to do is press a button on it, and access is immediately granted.  

 **Pros:** 

 - This type of authentication is ranked as one of the most secure forms of authentication because it requires just one single key that carries a unique identifier for an account. 

 - Physical security is all the protection it needs since it can’t be digitally compromised or intercepted by hackers, this is why this method is adopted by financial organizations because of the sensitivity of their data.  

- They are not susceptible to phishing attacks because they can only work with the sites they are registered to on your browser so attackers can’t redirect or use the codes on any other unregistered site.  

**Cons:** 

- This method is more expensive because it requires purchasing the device. 

- If the device is lost, a user can lose access to their account completely because a single key grants access to the account. 

 - A user may need to incur extra cost by purchasing an adapter with the key if the USB port of their device is different from that of the token.  

 **4. Biometrics:** this is when the physical characteristics of an individual are used as proof of identity and/or ownership of an account like a fingerprint, voice, retina scan, or facial features . As the name implies this technique measures the biological metrics of a registered user and compares this data against the data it receives during a log-in attempt. After it must have calculated and compared these two sets of data, it will then grant access if there is a match or reject the user if a flaw is detected.  

 **Pros:**  

- Speed: It takes a very short time (barely a second) to authenticate a user's identity. 

 - Almost impossible to hack: It will take extreme measures like facial surgery or some form of bodily augmentation to replicate making it difficult to crack  

 - Attackers will have to be physically close to the user to steal the data needed to access your account, which makes it easier to identify a suspect if the account is breached.  

 **Cons:** 

- They cannot be easily modified: unlike passwords that can be changed at will, a user cannot change their registered biometrics in the event that it gets compromised, for example, if a hacker manages to lift your fingerprint off a surface and uses it to gain access to your account, you will either have to change to passwords or use another finger’s print entirely but during this process the damage has already been done.  

 - Remote account recovery: When email authentication is enabled, a user can attempt to log into their account using any device to recover the authentication code, for biometrics authentication , the user must have the device in possession to make any security changes to the account.  

## Benefits of 2FA 

- Adding 2FA as an extra safeguard plays a crucial role in strengthening the overall security of our devices  

- It takes away the burden of having to remember passwords and manually logging into an account because it simplifies the login process.  

- Using 2FA helps organizations reduce the risk of fraud significantly because its technology is dificult to hack. 

- Adopting 2FA helps businesses save the extra operational cost of employing help desk support to assist customers in recovering forgotten passwords. 

- It reduces the possibility of identity theft because of the something you ‘have’ and ‘are’ factors which are usually difficult to breach by cyber attackers.  

- It helps organizations meet compliance requirements of regulatory bodies like GDPR and HIPAA, mandating the use of 2FA for customer rights, data protection and also to reduce risk. 

## Final thoughts  

2FA as a security measure is one of the most efficient technologies an individual or organization can adopt to reduce the likelihood of security violations, while the contribution and importance of its implementation in shrinking the cyber threat landscape cannot be overemphasized, utilizing 2FA alone is not enough, some best practices to ensure that we further protect and lessen the possibility of being breached are: 

 **1. Avoid oversharing on social media:** As social animals, we constantly feel the need to share information about our lives online but where do we draw the line between sharing too much and just enough? Attackers can use the basic information we share as a tool to launch phishing attacks or to guess possible account passwords. 

**2. Automate software updates:** updating application software does not only enable cool new features on our devices, new versions are often created to fix vulnerabilities and bugs that have been detected by the manufacturers. Ensure to enable automatic software updates to correct loopholes in the system immediately one in launched, to reduce the likelihood of cybercriminals will gaining unauthorized access to your devices. 

**3. Anti-malware and Antivirus software:** This software uses advanced analytics to detect, prevent and delete any malicious activities in a system. It serves as a protective measure to block infected files or data that tries to enter a device. 

**4. Utilize firewall:** A firewall is a system that uses predetermined rules as a security measure to assess, monitor, and control traffic going in and out of a network. A firewall will only enable data that has been green-lighted to flow into a network and inhibits unauthorized files from entering into your systems. 

**5. VPN:** a virtual private network creates a safe pathway in a public network for users to assess a network connection. It encrypts a user's activity with unique codes, making it difficult for cybercriminals to interpret or steal the data flowing through that network.  

**6. Physical security:** Do not write down passwords in plain sight, stay vigillant and ensure not to leave financial information and bank card data lying around, keep your cards in a safe place at all times. 

 > **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**