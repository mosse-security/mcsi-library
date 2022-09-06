:orphan:
(owasp-top-10-the-most-common-security-flaws-in-web-applications)=

# OWASP Top 10: The Most Common Security Flaws in Web Applications

Web applications are created with a major emphasis on functionality, not security. As a result of this focus, malicious actors exploit vulnerabilities to steal/modify sensitive information or carry out unauthorized activities. Security always comes as an afterthought in the form of patches to deal with security flaws in web applications.

A web application vulnerability is a flaw or weakness in the design of the application that can be exploited by malicious entities. The result of the vulnerability being exploited can be one of the following:

- Exposure to sensitive information
- Stealing the data
- Modification of the data
- Data Loss
- Deletion of the Data
- Failure of the application

With the rise of cyber-attacks, businesses all over the world have begun to transition from a reactive to a proactive strategy to web application security. It is important to integrate secure coding practices at each stage of the development of these applications.

The advantage of building secure code from the beginning is that it helps protect web applications against different risks and vulnerabilities. This saves the companies from the reputational and monetary losses incurred due to the commonly occurring security weaknesses.

## OWASP Foundation

OWASP (Open Web Application Security Project) is a non-profit organization dedicated to strengthening the security of web applications. OWASP is a worldwide community of security specialists who collaborate to create publicly available educational tools and training material. This foundation's main goal is to assist developers in developing secure web applications.

## What is OWASP Top 10

Every two to three years, the OWASP top 10 paper is published, which highlights the top ten vulnerabilities in web applications. It also includes prevention techniques for protecting your apps against these flaws. This list is the set of most common vulnerabilities that have been exploited most often and is developed by experts and mentors from the OWASP community. The main purpose of this report is to educate the developers about the most common security weaknesses in web apps and how they can incorporate the guidelines given in this document to produce web applications that are optimized and secure.

The advantage of using this document to produce web apps is that it ensures compliance with security regulations and maintains a high standard of secure code development.

## OWASP Top 10 2021

Three new categories have been added to the OWASP report for the year 2021. It also changed the title and scope of four earlier categories, as well as consolidated them. This is the list of 2021's most commonly occurring security flaws in web apps:

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server Side Request Forgery

### What Each Vulnerability means and how can you prevent it?

This section will give you a description of each vulnerability, its causes, and techniques to prevent it.

#### Broken Access Control:

Access control is the security mechanism that restricts access to resources depending upon the user's role and identity. Broken access control occurs when these security mechanisms fail to provide the expected level of protection to these resources. The result of this situation is that the attacker can now access, steal, modify or perform actions on the system or application that are outside the intended permissions.

_Causes:_

Broken access control vulnerability can be caused in one of the following ways:

- Bypassing access control checks in web apps by modifying the URL input parameters, application state, HTML page, or using a tool to send modified API requests to the web application

- Providing/Modifying the security identifier for a user to allow the intruder to view/modify the account details of another user

- Elevating the privileges of a normal user account to administrative privileges or acting as a legitimate user without a user account
- Replaying or Modifying the contents of JSON web token, or manipulating the session token or hidden fields to elevate privileges
- Allowing unauthorized APIs access to website resources due to improper CORS (Cross-Origin Resource Sharing) settings
- Using the browser to forcefully access authenticated pages without authentication or restricted pages as a normal user

_Prevention techniques:_

Broken access control can be prevented by:

- Access to the resources except for the public ones should be denied by default
- Instead of allowing the users to create, read, edit, or delete any record, use access control lists and role-based authentication mechanisms
- Apply rate-limiting techniques (restrict an individual from performing a repeated action in a certain time interval) to discourage automated attacks
- Disable webserver directory listing
- Log access control failures and alert the administrator in case of some unusual activity
- Session tokens or cookies should be expired after a certain time interval to prevent replay attacks
- Only allow trusted sites to access the website resources and implement proper server-side security policies

#### Cryptographic Failures:

This vulnerability was previously labeled as Sensitive data exposure. Now it has been renamed cryptographic failures as a result of sensitive data being exposed due to lack of encryption.

Encryption is the transformation of the digital data into a scrambled format so that it is protected against unauthorized access. The encrypted text is also called ciphertext. Only authorized people with a key (also called a decryption key) can translate and access the data.

Companies these days store and use a plethora of sensitive information such as passwords, credit card numbers, social security numbers, health records, confidential company information and so much more. This data must be protected at rest and in motion.

Data at rest means information that is stored in external or auxiliary storage devices such as hard disks, solid-state devices, optical disks, etc., Whereas data in motion means data that is moving between computing nodes over a data network such as the internet.

If a web application doesn't use strong encryption algorithms to protect the sensitive data, then the attackers can easily gain access to this data and commit crimes such as credit card fraud, identity theft or cause other damage.

If certain data falls under privacy laws such as GDPR (General Data Protection Regulation) or regulations for financial institutions such as PCI DSS (Payment Card Industry Data Security Standard) then it requires specific security safeguards. Compliance failures with the privacy laws or regulations can result in huge penalties or financial/reputational damage for the organization.

_Causes:_

Cryptographic failures vulnerability can arise in the following situations:

- Sensitive data being transported over unprotected channels (HTTP, SMTP, FTP, etc.)

- Use of old/weak encryption algorithms or deprecated Hash functions (MD5 or SHA-1)

- Use of default/weak cryptographic keys or reuse of previously generated weak keys. Lack of key rotation and management

- Lack of proper validation of server-side certificates and not enforcing encryption while communicating with them
- Initialization vectors being ignored, reused, or lack cryptographic strength
- Insufficient randomness used in cryptographic function making the ciphertext predictable
- Passwords are being used as cryptographic keys in absence of password derivation functions.
- Use of deprecated padding methods such as PKCS number 1 v1.5

_Prevention techniques:_

Cryptographic failures can be prevented by:

- Properly classify all the data that is being stored, used, or transmitted to understand what data needs to be protected. Identify which data falls under privacy laws or regulations
- Encrypt all the sensitive data that is stored by your organization
- Data retention policies should ensure that all the unnecessary sensitive data is discarded after a certain time duration
- Use of strong encryption algorithms, hash functions, padding functions, and keys. Ensure proper key rotation/management
- Use secure transmission protocols to transmit sensitive information and enforce encryption using HSTS (HTTP Strict Transport Security)
- Use strong salted hashing functions to store passwords
- Never cache sensitive information
- Ensure cryptographic randomness in the initialization vector
- Ensure cryptographic random generation of keys and store them as byte arrays. Use appropriate password derivation function if passwords are being used as keys
- Verify the security mechanisms are functioning as required

#### Injection:

This vulnerability has fallen to the third position from number one and now includes Cross-Site scripting as well. Injection flaws occur when an application accepts untrusted data input by the user without properly checking it. The attacker can exploit this vulnerability to execute malicious commands/queries on the website's server and gain access to sensitive data.

The most common type of Injection attacks is SQL Injection, Cross-Site Scripting, OS Command Injection, LDAP Injection, CRLF Injection, ORM Injection, EL Injection, and OGNL Injection.

_Causes:_

Injection vulnerability can exist in one of the following situations:

- Improper validation, filtering, and sanitization of data being input by the user
- No or improper escaping of dynamic content
- Sensitive records can be stolen by using hostile data in ORM (Object Relational Mapping) search parameters
- Hostile data directly used or concatenated

_Prevention techniques_

Some of the techniques used to prevent injection attacks are:

- Validating all inputs on the client as well as the server sides
- Encoding and escaping all user inputs
- Use parameterized queries or stored procedures when designing a web application

#### Insecure Design:

This is a new category included OWASP Top 10 document which calls for the use of a proactive approach to dealing with security threats and incorporating security in web app development right from the beginning.

Insecure design can be referred to as the security weaknesses related to the design and logic introduced into the web app by not taking into account different ways by which security can be compromised.

Secure design is a proactive way of web app development that evaluates all the threat scenarios and performs extensive testing to prevent commonly occurring security flaws. It ensures that web apps are developed with a strong focus on security from the beginning.

_Causes:_

Some but not all the scenarios of Insecure Design include:

- Using only client-side controls for protection
- Failure to apply rate-limiting controls to defend against automated attacks
- Improper access control
- Failure to handle unconventional Input

_Prevention techniques:_

- Use secure software development lifecycle techniques to design and test your code to ensure the effectiveness of security controls.
- Make use of threat modeling when designing different functionalities in your web app
- Perform unit and integration testing to evaluate how each security control is working.
- Develop use and misuse cases to contemplate all the threat scenarios and data flows
- Apply rate-limiting techniques to limit resource consumption by a user or service
- Perform extensive testing before deploying code into production
- Use Segmentation to separate systems with different security needs

#### Security Misconfiguration:

This vulnerability has moved up from number 6 to number 5 in the OWASP top ten list and now includes former category XXE (External XML Entities) as well.

Security misconfiguration can be defined as using default or lax security settings in our systems/software that can be exploited by the attackers to break through them.

_Causes:_

Some examples of Security Misconfiguration are:

- Lack of Application security hardening or improperly configured permissions on cloud services
- Having unnecessary features enabled/installed such as open ports, pages, accounts or privileges, etc.
- Use of default accounts and password
- Revealing the stack traces or inner details of web app through errors messages
- Latest features being disabled or misconfigured on upgraded systems
- Using software riddled with security flaws or using out of date software
- Not enforcing security through strict header values

_Prevention techniques:_

Avoid security misconfiguration by using the techniques given below:

- Automate the process of hardening your systems or software with correct security settings
- Disable all necessary features or components or services
- Regularly review and update the security settings of your web server and web app through patch management
- Review cloud storage permissions
- Use HSTS to send security directives to browsers
- Do not use default accounts and passwords

#### Vulnerable and Outdated Components:

Previously known as Using Components with Known Vulnerabilities, this vulnerability has moved from number 9 to number 6 in OWASP Top ten list.

Sometimes web applications contain components such as libraries, frameworks, or other software modules that are running with the same privileges as the application itself. If these components are vulnerable, it can lead to attackers taking over the webserver or unauthorized access/modification of data.

_Causes:_

Some of the situations that can make you vulnerable are:

- Being unaware of the version of the client and server-side components
- Using out-of-date or vulnerable software. This can include the webserver OS software, Database software, APIs, libraries, etc.
- Not performing vulnerability scanning regularly
- Not upgrading the underlying platforms, frameworks, or components in a timely fashion
- Patches released and used without proper testing
- Using misconfigured settings on different components

_Prevention techniques:_

Vulnerabilities due to using Vulnerable or Outdated components can be prevented by :

- Automating and regularly repeating the process of inventory of all the components on the client and server-side.
- Removing all unused dependencies, features, or components
- Acquiring signed components from known and trusted vendors
- If you are using unsupported libraries or components then use a virtual patch to monitor, detect and protect against security weaknesses discovered.
- Continuous monitoring of the web app to discover vulnerabilities and mitigate them in the form of updates or patches.

#### Identification and Authentication Failures:

Previously known as Broken Authentication, this vulnerability fell from the second spot to number 7.

Improper implementation of authentication mechanisms and session management can lead to attackers compromising user passwords or keys, session tokens, escalating their privileges, or assuming the identity of a legitimate user.

_Causes:_

Your application has Identification and Authentication vulnerabilities when:

- There's no or little protection against automated attacks such as credential stuffing, brute force attacks, etc.
- Users can set default, weak, or well-known passwords
- Weak mechanisms for forgotten passwords or credential recovery
- Passwords are stored in the database using plaintext or using weak encryption methods
- Absence of multi-factor authentication
- Session identifier can be reused after login or it is exposed in the URL
- The session token remains valid even after logout or a certain period of inactivity

_Prevention techniques:_

- Implement multi-factor authentication to deter automated attacks
- Do not use default account and passwords
- Test your application for weak or commonly used user passwords
- Implement a strong password policy
- Session token should be generated on the server-side and should be random. These tokens should not be leaked in the URL and should be expired after logout or a certain period of inactivity.

#### Software and Data Integrity Failures:

This is a new vulnerability and makes it to the eighth spot on OWASP's top ten list.

Software and Data integrity failures occur due to the lack of integrity verification in software updates, critical data, and CI/CD (continuous integration/continuous delivery) pipelines. This vulnerability can be exploited by the hackers to access sensitive data, insert malicious code into the web app or compromise the webserver.

_Causes:_

An application can have software and data integrity vulnerabilities when:

- Web application depends upon plugins, libraries, and modules from untrusted sources, repositories, or Content Delivery Networks.
- Use of CI/CD pipelines without integrity verification
- Sending unencrypted or unsigned serialized data to untrusted clients without digital signatures

_Prevention techniques:_

Some of the techniques to safeguard against this vulnerability are:

- Use digital signatures to verify the integrity of software or data
- Ensure libraries or code dependencies used are coming from trusted repositories
- Use tools such as OWASP Dependency-Check to verify that your dependencies don't contain any known vulnerabilities
- Your CI/CD pipelines should have proper security mechanisms such as segregation and access control to ensure the integrity of the code
- Using digital signatures with serialized data to detect tampering or replay of this data

#### Security Logging and Monitoring Failures:

Previously known as Insufficient logging and monitoring, this vulnerability has come up from number 10 to number 9.

Security logging and monitoring is very important to detect, escalate and respond to security incidents in a timely manner. It is very important to have robust logging and monitoring system to detect data breaches and other security attacks.

_Causes:_

Insufficient logging and monitoring occurs when:

- Auditable events such as logins, failed logins and high-value transactions are not logged
- Warnings or errors generate unclear log messages
- Application logs are not monitored for suspicious activity
- Penetration testing or scans don't produce security alerts
- There is no threshold for generating alerts and escalation procedures in place for suspicious activity
- Logs are stored only locally
- Inability to detect, escalate and respond to attacks taking place in real-time

_Prevention techniques:_

Some of the techniques that can help prevent insufficient logging and monitoring are :

- All failure events relating to login, access control, or input validation should be logged. These logs should contain sufficient user information to detect the signs of malicious activity.
- The logs of suspicious activity should be retained for a certain time period to aid forensic investigations
- The logs should be protected from injection through the use of encryption and encoding
- The use of robust logging and monitoring systems to detect, escalate, and respond to security incidents
- High-value transactions should have an audit trail to detect and prevent tampering/deletion

#### Server-Side Request Forgery:

This vulnerability has been a new entry in the OWASP Top 10 list.

Server-side Request Forgery occurs when an attacker sends malicious requests to the web server to read or update a remote resource on the server or direct requests to unintended locations. SSRF attacks can target the internal server even behind firewalls or VPNs. SSRF vulnerability can result in Internal Reconnaissance, DDOS (Distributed Denial of Service Attacks), RCE (Remote Code Execution), or sensitive information exposure.

_Causes:_

An application is vulnerable to SSRF when:

- The user-supplied URL is not properly sanitized

_Prevention techniques:_

- All client-side data should be sanitized and validated
- Whitelist the set of domains or IP addresses that the application needs to access
- Disable all unnecessary schemas for your application such as ftp, file, dict, gopher, etc.
- Never send raw response body to the client
- Disable HTTP redirections

> **Want to learn practical Secure Software Development skills? Enrol in [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).**
