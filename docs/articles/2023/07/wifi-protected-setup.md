:orphan:
(wifi-protected-setup)=

# Wi-Fi Protected Setup

Wi-Fi Protected Setup (WPS) is a feature designed to simplify the process of connecting devices to a Wi-Fi network by using a PIN or a push-button configuration. The main goal of WPS is to make it easier for users to set up a secure Wi-Fi connection without having to manually enter the network's passphrase (pre-shared key).

There are two main methods for configuring devices using WPS:

**1.	PIN Method:** In this method, a unique eight-digit PIN is generated and provided either on a sticker attached to the Wi-Fi router or in the router's settings. When a device attempts to connect to the Wi-Fi network using WPS, the user can enter this PIN into the device's Wi-Fi settings, and the router will verify the PIN's validity. If the PIN matches, the device is granted access to the network without needing to enter the actual Wi-Fi passphrase.

**2.	Push-Button Method:** With the push-button method, the user presses a physical button on the router and then initiates the WPS connection on the device they want to connect. The router broadcasts its WPS information, allowing the device to connect securely without entering the Wi-Fi passphrase.

## Vulnerabilities of WPS

Despite its convenience, WPS has been found to have significant security vulnerabilities, making it a potential risk to Wi-Fi network security. Some of the main vulnerabilities include:

**1.	Brute-Force Attack on WPS PIN:** The eight-digit PIN used in WPS is susceptible to brute-force attacks. Since there are only 10^8 possible combinations (00000000 to 99999999), attackers can try all combinations relatively quickly to find the correct PIN.

**2.	Weak Implementation of Lockout Mechanism:** Some routers do not implement a proper lockout mechanism to prevent multiple unsuccessful PIN attempts. This allows attackers to conduct brute-force attacks without being locked out, making it easier to guess the PIN.

**3.	Predictable Default PINs:** Some routers use predictable default PINs (e.g., based on the router's MAC address), which can be easily determined by attackers.

**4.	Reaver and Pixie Dust Attacks:** Reaver and Pixie Dust attacks are specific techniques used to exploit vulnerabilities in WPS and recover the Wi-Fi passphrase by brute-forcing the PIN.

Due to these vulnerabilities, WPS has been largely deprecated in modern routers, and many manufacturers have disabled WPS by default. In some cases, users have the option to enable or disable WPS in their router settings. However, it is generally recommended to avoid using WPS and rely on standard WPA2 or WPA3 authentication methods with strong, unique passphrases for a more secure Wi-Fi network.

## Easy Connect

Easy Connect, also known as Wi-Fi Easy Connect or Device Provisioning Protocol (DPP), is a more secure and modern method intended to replace Wi-Fi Protected Setup (WPS) for securely configuring client devices to access a Wi-Fi network. Easy Connect is designed to simplify the process of connecting devices to a Wi-Fi network while addressing the security vulnerabilities present in WPS. It is defined by the Wi-Fi Alliance and is part of the Wi-Fi CERTIFIED Easy Connect program.

Here's how Easy Connect works:

**1.	Device Enrollment:** The Wi-Fi network administrator generates a configuration package (a "credential" or "enrollee") that includes the network's SSID, security settings (such as the encryption method and credentials), and other necessary network information.

**2.	QR Code or NFC:** The configuration package is typically encoded as a QR code or an NFC (Near Field Communication) tag. It can be displayed on the device (e.g., a smartphone or tablet) or printed as a physical label.

**3.	Provisioning Device:** The client device (e.g., a smartphone, laptop, or IoT device) that needs to connect to the Wi-Fi network acts as a provisioning device. It has a built-in Easy Connect client.

**4.	Scanning or Tapping:** The user scans the QR code or taps the NFC tag using the provisioning device's camera or NFC capabilities.

**5.	Credential Exchange:** The provisioning device extracts the configuration information from the scanned QR code or NFC tag. It then securely exchanges this information with the Wi-Fi access point using cryptographic mechanisms.

**6.	Secure Authentication:** The access point authenticates the provisioning device and verifies the received credentials. This process is designed to be resistant to brute-force attacks and other security threats.

**7.	Secure Connection:** Upon successful authentication, the client device securely connects to the Wi-Fi network using the exchanged credentials.

### Advantages of Easy Connect

**1.	Improved Security:** Easy Connect addresses the security vulnerabilities present in WPS. It uses modern cryptographic mechanisms and is designed to be more resistant to brute-force attacks on the credentials.

**2.	Simplified Setup:** Easy Connect simplifies the process of connecting devices to a Wi-Fi network, making it easier for users to set up their devices without manually entering complex passphrases.

**3.	Scalability:** Easy Connect can be used to provision multiple devices simultaneously, making it suitable for scenarios with a large number of IoT devices or smart home devices.

**4.	Compatibility:** Easy Connect is backward compatible with older devices that support WPA2 or later security protocols.

## Limitations

**1.	Device Support:** While Easy Connect offers enhanced security and convenience, its adoption depends on both the network infrastructure (Wi-Fi access points) and client devices supporting the Easy Connect standard.

**2.	Deployment:** As with any new technology, widespread adoption may take time, and older routers or access points may not support Easy Connect by default.

## Closing Words

Overall, Easy Connect is a promising method for securely configuring client devices to connect to Wi-Fi networks, offering improved security and ease of use compared to traditional WPS. As more devices and routers support Easy Connect, it is expected to become a standard method for setting up Wi-Fi connections securely.