:orphan:
(network-access-controls)=

# Network Access Controls

Network Access Control (NAC) is a security framework that helps organizations control and manage access to their networks. It is designed to enforce policies that dictate which devices and users can connect to the network and what level of access they are granted. NAC solutions aim to ensure that only authorized and compliant devices gain access to the network while blocking or restricting access for unauthorized or non-compliant devices.

## How NAC Works:

**1.	Authentication:** When a device attempts to connect to the network, NAC initiates an authentication process. This process requires users and devices to provide credentials such as usernames, passwords, digital certificates, or other forms of identification.

**2.	Authorization:** Once the device is authenticated, NAC determines the appropriate level of access based on pre-configured policies. These policies take into account factors like the user's role, the type of device, its security posture, and the location from which the connection is originating.

**3.	Posture Assessment:** One crucial aspect of NAC is posture assessment. During this step, NAC evaluates the security posture and compliance status of the connecting device. It checks whether the device has the necessary security software, patches, and configurations to meet the organization's security standards.

**4.	Remediation:** If the device does not meet the required security standards, NAC may place it in a restricted network segment called a "remediation network." The device is then provided with limited access, and instructions are given to the user on how to update or configure their device to meet the required security posture.

**5.	Access Control Enforcement:** Once the device is authenticated, authorized, and meets the security posture requirements, NAC allows it to connect to the appropriate network segment with the appropriate level of access.

**6. Port-Based Network Access Control (PNAC):** Port-Based Network Access Control is a specific type of NAC that operates at the network switch port level. It is also known as "802.1X Port-Based Network Access Control." With PNAC, each network switch port is individually controlled, and devices attempting to connect to a port must undergo the authentication and authorization process described above.

### PNAC works as follows

•	When a device connects to a network switch port, the port is in a closed or unauthorized state.

•	The device sends an authentication request to the switch, and the switch forwards it to the NAC server.

•	The NAC server evaluates the request and responds with an authentication result.

•	If the device is authenticated and compliant, the switch opens the port and grants access to the network. If not, the port remains closed, and the device is restricted or placed in a remediation network.

## Posture Assessment

As mentioned earlier, posture assessment is a crucial part of the NAC process. It involves evaluating the security posture and compliance status of a device attempting to connect to the network. The assessment may include checking for the following:

•	Presence of up-to-date antivirus software.

•	Installed security patches and updates.

•	Properly configured firewalls and security settings.

•	Encryption protocols enabled for wireless connections.

•	Compliance with specific organizational security policies.

## Closing Words

By performing posture assessments, NAC solutions help ensure that only devices meeting the organization's security requirements gain access to the network, reducing the risk of security breaches and unauthorized access. It also promotes overall network hygiene and adherence to security best practices.