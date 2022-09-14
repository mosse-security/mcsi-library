:orphan:
(basic-authentication-models)=
# Basic Authentication Models
 
The first line of protection is authentication. It is the process of determining whether or not a user is who they claim to be. Not to be confused with the phase that comes before it, authorization, authentication is just a technique of validating digital identification, so users have the amount of rights they need to access or accomplish a job. There are several authentication systems available, ranging from passwords to fingerprints, to check a user's identity before granting access. This offers another layer of security and avoids security shortcomings such as data leaks. However, it is frequently the combination of many methods of authentication that offers safe system reinforcement against potential attacks.

## What are the types of authentication?

Authentication prevents unauthorised individuals from accessing databases, networks, and other resources. These authentication methods employ factors, a form of credential for verification, to prove user identification. Here are a few examples of these strategies.

### Single-Factor/Primary Authentication

Single-Element Authentication, which has historically been the most used type of authentication, but also the least secure because it only requires one factor to acquire complete system access. It might be a username and password, a pin number, or another straightforward code. While user-friendly, Single-Factor authenticated systems are very easy to compromise through phishing, key recording, or guessing. This strategy is very open to attack since there is no alternative authentication gate to get through.

### Two-Factor Authentication (2FA)

Two-factor authentication strengthens security measures by providing a second step for verification. It's an extra layer that basically double-checks that a user is, in fact, the person they're attempting to log in as, making it much more difficult to crack. Users utilise this approach by entering their primary login credentials (such as the username/password stated above) and then a secondary piece of identifying information.

The secondary component is generally more challenging and it can be a one-time password from an authenticator app, a phone number or device that may receive a push notification or SMS code, or a biometric like fingerprint (Touch ID) or facial (Face ID). Because an invalid user is unlikely to know or have access to both authentication factors, 2FA considerably reduces the danger of system or resource compromise. While two-factor authentication is becoming increasingly extensively used for this reason, it can create some user discomfort, which should be considered throughout installation.

### Single Sign-On (SSO)

With SSO, users simply need to log in to one application to have access to a plethora of others. This solution is more convenient for consumers since it eliminates the need to have different sets of credentials and delivers a more seamless experience during surgical sessions Organizations can do this by first designating a central domain (preferably, an IAM system) and then establishing secure SSO linkages across resources. This procedure enables domain-monitored user authentication and, when combined with single sign-on, ensures that when legitimate users terminate their session, they securely log out of all related resources and applications.

### Multi-Factor Authentication (MFA)

Because it employs additional system-irrelevant elements to validate users, multi-factor authentication is a high-assurance technique. MFA, like 2FA, confirms user identification by using biometrics, device-based validation, extra passwords, and even location or behavior-based information (e.g., keystroke pattern or typing speed). However, while 2FA always uses only two factors, MFA can employ two or three, with the possibility to change across sessions, adding an elusive aspect for invalid users.

### Context-aware authentication

Context-aware authentication is a sort of authentication that considers the context in which a user attempts to access a resource. This sort of authentication may be used to give a more granular degree of security since it can consider aspects such as the user's location, time of day, and device type. Context-aware authentication may be used to provide an extra degree of protection to typical authentication techniques like passwords or security tokens. Context-aware authentication can give a better level of assurance that the user requesting to access a resource is allowed to do so by considering extra contextual information. Context-aware authentication may be used to replace traditional authentication in many circumstances.

### Federated Identity Management

Federated Identity Management, or FIdM, is a system that allows for the management of digital identities in a decentralized manner. FIdM is based on the concept of federated identity, which is an identity that is jointly controlled by two or more parties. In the context of FIdM, these parties are known as identity providers. FIdM allows for the management of digital identities in a way that is both secure and efficient. FIdM is based on the concept of federated identity, which is an identity that is jointly controlled by two or more parties. In the context of FIdM, these parties are known as identity providers.

There are several authentication models that may be used to secure access to information and systems. The optimum approach for a certain company will be determined by its security requirements. However, all authentication mechanisms have advantages and disadvantages that must be evaluated prior to adoption.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**