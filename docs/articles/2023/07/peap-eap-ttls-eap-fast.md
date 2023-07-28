:orphan:
(peap-eap-ttls-eap-fast)=

# PEAP, EAP-TTLS, and EAP-FAST

PEAP (Protected Extensible Authentication Protocol), EAP-TTLS (Tunneled TLS), and EAP-FAST (Flexible Authentication via Secure Tunneling) are all authentication methods based on the Extensible Authentication Protocol (EAP). These methods provide a more robust and secure authentication framework compared to simple pre-shared key methods like WPA2-PSK (Wi-Fi Protected Access 2 - Pre-Shared Key).

## PEAP (Protected Extensible Authentication Protocol)

PEAP is an EAP method that encapsulates EAP within an encrypted TLS (Transport Layer Security) tunnel. It provides a secure method for client devices to authenticate with a RADIUS (Remote Authentication Dial-In User Service) server. The main steps in PEAP authentication are as follows:

•	The client initiates a connection to the access point.

•	The access point requests the client's identity.

•	The client responds with its identity, and the access point provides its digital certificate.

•	The client and access point establish a TLS tunnel.

•	The client is then authenticated by the RADIUS server through the secure tunnel.

## EAP-TTLS (Tunneled TLS)

EAP-TTLS is another EAP method that uses TLS for tunneling and authentication. EAP-TTLS is a more flexible protocol that can support multiple authentication methods within the secure tunnel. The main steps in EAP-TTLS authentication are as follows:

•	The client initiates a connection to the access point.

•	The access point requests the client's identity.

•	The client responds with its identity, and the access point provides its digital certificate.

•	The client and access point establish a TLS tunnel.

•	Within the secure tunnel, the client's credentials are securely transmitted to the RADIUS server for authentication.

## EAP-FAST (Flexible Authentication via Secure Tunneling)

EAP-FAST is designed to be more user-friendly and less complex to deploy than some other EAP methods. It uses a secure tunneling protocol similar to EAP-TTLS. EAP-FAST includes a two-phase authentication process:

•	The client and access point establish a secure tunnel using Protected Access Credentials (PACs).

•	After the tunnel is established, the client's credentials are securely transmitted to the RADIUS server for authentication.

## Why Do We Need Them?

PEAP, EAP-TTLS, and EAP-FAST are essential for several reasons:

**1.	Strong Authentication:** These EAP methods provide stronger authentication than pre-shared keys, making them suitable for environments where higher security is required.

**2.	User Privacy:** EAP methods like PEAP and EAP-TTLS protect user credentials and identity information by securely transmitting them through encrypted tunnels.

**3.	Centralized Authentication:** These methods allow for centralized user authentication and management through RADIUS servers, making it easier to manage large networks with multiple access points and devices.

**4.	Flexibility:** EAP-TTLS and EAP-FAST support multiple authentication methods within the secure tunnel, providing flexibility to accommodate various user authentication requirements.

## Closing Words

Overall, these EAP methods play a crucial role in ensuring secure and robust authentication for Wi-Fi networks, especially in enterprise and larger organizational settings. They offer stronger security measures and more sophisticated authentication mechanisms compared to simpler Wi-Fi security methods like WPA2-PSK.