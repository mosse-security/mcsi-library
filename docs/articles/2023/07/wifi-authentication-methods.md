:orphan:
(wifi-authentication-methods)=

# Wi-Fi Authentication Methods

Wi-Fi authentication methods are the mechanisms used to verify the identity of devices and users attempting to connect to a Wi-Fi network. These methods ensure that only authorized devices and users can access the network. There are several authentication methods used in Wi-Fi networks, and they can be broadly categorized into two main types:

## 1. Personal (Pre-Shared Key) Authentication

WPA-Personal, also known as WPA-PSK (Pre-Shared Key), is a commonly used authentication method for home and small office Wi-Fi networks. It uses a pre-shared key (password) that is shared among all devices wishing to connect to the network. Once the correct key is entered, the device is granted access to the network.

First, the network administrator sets up a pre-shared key, which is a secret passphrase or password. This key is shared among all the devices that want to connect to the Wi-Fi network. When a device attempts to connect to the WPA2-PSK-protected network, it initiates a four-way handshake process with the Wi-Fi access point (AP). The four-way handshake is a cryptographic process that establishes a secure connection between the client device and the AP. During the four-way handshake, the client device proves its identity to the AP by demonstrating that it knows the pre-shared key without actually revealing the key itself. This is achieved through cryptographic calculations. Once the client's identity is verified, the client and the AP derive a session key. This key is used to encrypt the data exchanged between the client and the AP during the session. This ensures that the data remains confidential and protected from eavesdropping. After the session key is derived, the client and the AP use it to encrypt and decrypt data during the communication. This process ensures that the data transmitted over the Wi-Fi network is secure and cannot be easily intercepted or tampered with by unauthorized users.

### Advantages of WPA-PSK:

**•	Simplicity:** WPA2-PSK is straightforward to set up and manage, making it suitable for home and small office networks with limited IT resources.

**•	Strong Security:** The use of a pre-shared key and the four-way handshake provide robust security against various attacks, such as brute-force attacks and dictionary attacks.

**•	Individual Device Authentication:** Each device connecting to the network needs the correct pre-shared key to authenticate itself, ensuring that only authorized devices can join the network.

### Limitations of WPA-PSK:

However, it's important to note that WPA2-PSK has some limitations. Since the same pre-shared key is shared among all devices, changing the key can be cumbersome in large networks. Additionally, if the pre-shared key is compromised or shared with unauthorized users, it may result in unauthorized access to the Wi-Fi network. For larger networks or those with more stringent security requirements, WPA2-Enterprise (802.1X/EAP) authentication with individual user credentials and a RADIUS server for central authentication is a more suitable option.

## 2. Enterprise (802.1X/EAP) Authentication

WPA-Enterprise, also known as WPA-802.1X, is a more secure authentication method commonly used in larger organizations and businesses. It uses the IEEE 802.1X standard for network access control and Extensible Authentication Protocol (EAP) for authentication. 

This method requires a RADIUS (Remote Authentication Dial-In User Service) server, which validates user credentials and provides a higher level of security than WPA-Personal.

**•	EAP-TLS (Transport Layer Security):** EAP-TLS is a strong authentication method that uses digital certificates to authenticate both the client device and the authentication server. It provides mutual authentication and secure key exchange.

**•	PEAP (Protected Extensible Authentication Protocol):** PEAP is a popular EAP method that provides an additional layer of security by encapsulating EAP within an encrypted TLS tunnel.

**•	EAP-TTLS (Tunnelled TLS):** EAP-TTLS uses a two-phase authentication process, where the client and the authentication server establish a secure TLS tunnel before the actual authentication takes place.

**•	EAP-FAST (Flexible Authentication via Secure Tunnelling):** EAP-FAST is designed to be more user-friendly and less complex to deploy than other EAP methods. It also utilizes a secure tunnel for authentication.

## Closing Words

Each authentication method has its advantages and use cases. WPA-Personal is suitable for smaller networks with minimal security requirements, while WPA-Enterprise with 802.1X/EAP is more appropriate for larger organizations that require strong user authentication and centralized management. The choice of authentication method depends on the specific security needs and the scale of the Wi-Fi network deployment.