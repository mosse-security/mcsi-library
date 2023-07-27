:orphan:
(ssl-stripping)=

# SSL Stripping

SSL strip, short for "SSL stripping," is a type of attack where a malicious actor intercepts and manipulates HTTP traffic to downgrade secure HTTPS connections to unencrypted HTTP connections. This attack is particularly dangerous because it allows the attacker to intercept sensitive data, such as login credentials, credit card information, or other confidential data, as it is transmitted over the network in plain text. 

In an SSL strip attack, the attacker typically needs to perform a Man-in-the-Middle (MitM) attack using ARP (Address Resolution Protocol) poisoning to intercept and manipulate the traffic between the victim's device and the default gateway.

Here's how the SSL strip attack with ARP poisoning works:

**1.	ARP Poisoning:** The attacker begins by poisoning the ARP cache of the victim's device or the local network's ARP cache. ARP is used to map IP addresses to MAC addresses on a local network. By poisoning the ARP cache, the attacker associates their MAC address with the IP address of the default gateway (usually the router) on the victim's network.

**2.	MitM Position:** Once the ARP poisoning is successful, the attacker now becomes the Man-in-the-Middle. All traffic that the victim's device sends to the default gateway will be routed through the attacker's device instead.

**3.	Traffic Interception:** When the victim's device attempts to access a secure website (HTTPS) by sending an HTTPS request to the default gateway, the attacker intercepts this request due to their MitM position. Instead of forwarding the request to the actual secure website (which would trigger the SSL/TLS handshake for a secure connection), the attacker can manipulate the request and prevent the use of HTTPS.

**4.	SSL Strip Attack:** The attacker responds to the victim's device with a modified version of the website's content. In this modified version, all HTTPS links are changed to unsecured HTTP links. The attacker may also provide an invalid SSL certificate to the victim's device, which the browser might ignore due to the HTTPS downgrade.

**5.	Unencrypted Communication:** The victim's browser, unaware of the attack, follows the provided HTTP links, initiating unencrypted communication with the website. The entire data exchange between the victim and the website occurs in plain text, allowing the attacker to intercept and read the transmitted data.

The combination of ARP poisoning and the manipulation of HTTPS requests allows the attacker to strip away the security provided by SSL/TLS encryption, hence the name "SSL strip."

## Examples of SSL Strip:

**a. Login Credentials Theft:** Let's say a user tries to log in to their online banking account. Normally, the user's browser would establish a secure HTTPS connection to protect their login credentials. However, if an attacker successfully performs an SSL strip attack, the user's browser will be directed to the unsecured HTTP version of the website, exposing their login credentials in plain text. The attacker can now easily intercept and steal the user's username and password.

**b. Credit Card Information Theft:** During an online purchase, a user enters their credit card information to make a secure transaction. If an SSL strip attack is performed, the user's browser will be forced to use unencrypted HTTP for the transaction. As a result, the credit card details are sent over the network without encryption, allowing the attacker to intercept and collect the sensitive data.

## Final words

To defend against SSL strip attacks, users should be cautious when connecting to public or untrusted networks. Additionally, website owners should implement HTTP Strict Transport Security (HSTS) on their websites to enforce the use of HTTPS and protect against downgrade attacks. HSTS instructs the user's browser to only connect to the website via HTTPS, even if the user attempts to access it using an HTTP link. This prevents SSL strip attacks from downgrading the connection to unencrypted HTTP.
