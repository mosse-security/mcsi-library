:orphan:
(network-device-hardening)=



# Network Device Hardening

Network devices are a critical part of any IT infrastructure, however, they’re often overlooked when it comes to security hardening. In this article, we’ll look at some common steps that you can take to significantly improve the security of your network devices. For our examples we’ll focus on Cisco IOS, however, similar steps can be performed on devices from other vendors. 

 

## Basic Hardening

First and foremost, look to secure access to the device and prevent the leakage of password data.

### Set a Strong Password for Enable Mode

Cisco IOS devices come with an "enable" mode, which grants elevated privileges to users. To fortify this critical access point, it's crucial to set a strong password.

**Configuration Example**

```
enable secret <strong_password>
```

In the example above, replace <strong_password> with a secure, complex password of your choice. This password will be required when entering the enable mode, ensuring that only authorized personnel can make configuration changes with elevated privileges.

 

### Encrypt Passwords in Configuration Files

Protecting passwords stored in configuration files is essential for preventing unauthorized access. By default, Cisco IOS devices store passwords in plaintext in these files, which is a significant security risk.

To mitigate this risk, you can use the following command to encrypt passwords within configuration files

```
service password-encryption
```

When this command is applied, passwords will be stored in encrypted form within the configuration files, adding an extra layer of security. This prevents anyone with access to the configuration files from easily deciphering sensitive credentials.

 

## **Physical Security**

Physical security measures serve as the first line of defence against unauthorized access and tampering – if an attacker can physically access your network device, it’s not really your network device!

### **Secure Physical Access**

The physical security of your network devices begins with controlling access to their physical locations. Here are some key strategies to consider

- **Lock Cabinets** -  Install cabinets or enclosures that house your network equipment and secure them with locks. Only authorized personnel should have access to these cabinets.

- **Control Room Access** -  If your devices are located in a control room, limit access to authorized staff only. Implement access control systems and surveillance measures to monitor and record access.

- **Register Authorised Personnel** - Ensure that people who should be allowed to access network devices have some form of badge or identifier which shows this, keep a register of authorised individuals and ensure security challenges anyone not presenting the correct credentials. 

  

### Protect Console and Auxiliary Ports

Console and auxiliary ports provide direct access to the configuration of  devices. Protecting these ports is essential to prevent unauthorized configuration changes or potential breaches. Look to implement:

- **Physical Locks** Physically lock console and auxiliary ports when they are not in use. This can be achieved using port locks or covers to prevent unauthorized physical connections.
- **Secure Cabling** Ensure that console and auxiliary cables are securely connected and not easily accessible to unauthorized individuals. Use cable locks or cable management solutions to secure them.

 

## Access Control

Access control is a fundamental aspect of network device hardening, and it plays a crucial role in ensuring that only authorized individuals can interact with your devices. 

### Using Access Control Lists (ACLs)

Access Control Lists (ACLs) are a powerful tool for controlling access to network resources. They can be configured to permit or deny traffic based on various criteria, such as source IP address, destination IP address, and port numbers. Look to create ACLs that explicitly permit or deny specific traffic to and from your network devices. For example, you might create an ACL to allow management traffic from trusted IP addresses and deny all other traffic.

**Configuration Example**

```
access-list 10 permit <trusted_IP>
access-list 10 deny any
line vty 0 4
access-class 10 in
```

In the above example, an ACL with ID 10 is created to permit traffic from a trusted IP address and deny all other traffic. The ACL is then applied to the VTY lines (used for remote management) to control incoming access.

### Additional Access Control Measures

In addition to ACLs, also consider implementing: 

- **Exec-Timeout** - Set an inactivity timeout to automatically log users out after a period of inactivity. This prevents unauthorized access if a user leaves their session unattended.
- **Login Block-for** - Implement rate limiting to protect against brute-force login attempts. The "login block-for" command can be used to specify a threshold for login attempts and a block duration for exceeding that threshold.

 

## SSH and Telnet

Securing remote access to your network devices is crucial in network device hardening – if an attacker can harvest credentials by listening to the network they can easily use them to gain access to a device.

### Risks of Telnet

Telnet is a legacy protocol used for remote management of network devices. However, it poses significant security risks, as it transmits data, including passwords, in plain text. Attackers can easily intercept and eavesdrop on Telnet sessions, potentially compromising your network's security.

### Benefits of SSH

Secure  (SSH) is a cryptographic network protocol that provides a secure and encrypted connection for remote access to network devices. SSH encrypts all data transmitted between the client and the network device, making it resistant to eavesdropping. At the same time, SSH supports multiple authentication methods, including password-based and key-based authentication, enhancing security.

**Configuration Example**

```
ip domain-name <domain-name>
crypto key generate rsa
line vty 0 4
transport input ssh
```

In the example above

`<domain-name>` should be replaced with your domain name. This is used for generating SSH keys.

The `crypto key generate rsa` command generates SSH keys.

The `line vty 0 4` command enters the VTY line configuration mode.

`transport input ssh` restricts VTY access to SSH only.

 

### SSH Key Authentication

While password-based SSH authentication is secure, key-based authentication provides an additional layer of security. Users must possess the private key to access the device. To configure key-based authentication, users generate key pairs and upload their public keys to the device.

 

## SNMP Security 

Simple Network Management Protocol (SNMP) is a valuable tool for monitoring and managing network devices, however, SNMP also presents security concerns if not properly configured.

### SNMP Security Concerns

SNMP operates on network devices to allow remote monitoring and management. However, without proper security measures, it can expose your network to various risks, including:

- Unauthorized access to SNMP data, including sensitive information.
- The potential for attackers to exploit SNMP vulnerabilities.
- The potential for an attacker to control your network device remotely.

 

### Use SNMPv3 for Authentication and Encryption

To address SNMP security concerns, it is recommended to use SNMP version 3 (SNMPv3), which provides authentication and encryption features. SNMPv3 ensures that SNMP traffic is secure and can only be accessed by authorized users.

**Configuration Example**

```
snmp-server group <group_name> v3 auth
snmp-server user <user_name> <group_name> v3 auth md5 <auth_key> priv aes 128 <priv_key>
```

- <group_name> is the name of the SNMP group.
- <user_name> is the SNMPv3 username.
- <auth_key> is the authentication key (password).
- <priv_key> is the privacy key (used for encryption).

This configuration example sets up SNMPv3 with authentication and encryption.

 

## **Password Policy and Authentication**

Effective password management is critical for network device hardening – while authentication with SSH keys is preferable, password authentication is still used and sometimes required for backwards compatibility. Thankfully, we can increase the strength and security of password-based authentication. 

### **Password Complexity Rules**

A strong password policy is essential to prevent unauthorized access and protect your network devices. Here are some key components of a password policy

**Minimum Password Length** - Set a minimum password length to ensure that passwords are not too short. Longer passwords are generally more secure.

**Complexity Requirements** - Require passwords to contain a mix of uppercase and lowercase letters, numbers, and special characters to increase their complexity.

**Configuration Example**

```
security passwords min-length 8
```

In the example above, a minimum password length of 8 characters is enforced. You can adjust the length requirement according to your security needs.

 

### **Authentication Settings**

Authentication settings determine how users access and authenticate themselves on Cisco IOS devices. Here are some additional considerations to keep in mind:

**Authentication Methods -** Cisco IOS devices support various authentication methods, including local authentication, TACACS+ (Terminal Access Controller Access Control System Plus), and RADIUS (Remote Authentication Dial-In User Service). Choose the method that best suits your organization's needs and security policies.

**Local Authentication** - When using local authentication, user accounts and passwords are managed directly on the Cisco IOS device. Ensure that strong, unique passwords are set for each user account.

**Configuration Example (Local Authentication)**

```
username <username> privilege <privilege_level> secret <password>
```

In the example above, replace `<username>`, `<privilege_level>`, and `<password>` with the appropriate values for creating a local user account.

 

## Role-Based Access Control (RBAC)

Role-Based Access Control (RBAC) is a powerful security concept that plays a pivotal role in network device hardening – RBAC can be a more secure and flexible approach to user authorisation which works well for network devices when properly implemented. 

### Understanding RBAC

RBAC is a method of managing user access to network resources based on their roles and responsibilities within an organization. Instead of assigning broad access privileges to all users, RBAC allows you to assign specific permissions and access levels to individuals or groups based on their job functions.

### Configuring and Using Roles

In Cisco IOS, you can configure and use roles to implement RBAC – we use privilege levels to achieve this. Privilege levels represent the permissions associated with specific roles. For example, you can define privilege level 15 for administrators with full access and privilege level 0 for guests with minimal access.

**Configuration Example**

```
privilege exec level 15 show running-config
```

In this example, privilege level 15 grants the user the ability to execute the "show running-config" command with full access privileges.

Next, Create User Accounts and Assign Roles -  Create user accounts for individuals or groups and assign them to specific roles based on their responsibilities.

```
username <username> privilege <privilege_level> secret <password>
```

In this example, replace <username>, <privilege_level>, and <password> with the appropriate values for creating a user account and specifying their privilege level.

 

### Role-Based Access Control in Action

RBAC ensures that users only have access to the commands and actions necessary for their roles. For instance, network administrators might have privilege level 15, allowing them to make configuration changes, while guest users might have privilege level 0, restricting them to basic monitoring commands.

By implementing RBAC, you reduce the risk of accidental or intentional misconfigurations, as users are limited to commands and actions within their designated roles.

 

## Disable Unnecessary Services

One of the fundamental principles of network device hardening (and to be fair, any system hardening) is minimizing the attack surface by disabling unnecessary services and features – many of which may be enabled by default. 

### The Importance of Disabling Unnecessary Services

Network devices often come with a variety of services and features enabled by default. While some of these services are essential for device operation, others may not be needed for your specific network environment. Disabling unnecessary services is critical for the following reasons

- **Reduced Attack Surface** Every enabled service represents a potential entry point for attackers. By disabling services you don't need, you reduce the attack surface and minimize vulnerabilities.
- **Resource Optimization** Unnecessary services consume device resources, such as CPU and memory. Disabling them can free up resources for critical functions.

An excellent example is HTTP or HTTPS **-**  If you're not using the web interface for device management or monitoring, disable the HTTP and HTTPS services to prevent unauthorized access or brute force attempts via the web interface.

**Configuration Example (Disabling HTTP and HTTPS)**

```
no ip http server
no ip http secure-server
```

Cisco Discovery Protocol (CDP) is another good example. CDP is used for network discovery and can reveal device information to potential attackers. Disable it on interfaces where it's not needed.

**Configuration Example (Disabling CDP on an Interface)**

```
interface GigabitEthernet0/1
no cdp enable
```

FTP and TFTP Services are also often enabled on a network device by default **-**  If you don't require file transfers via FTP or TFTP, disable these services to prevent unauthorized file access.

**Configuration Example (Disabling FTP and TFTP)**

```
no ip ftp server
no ip tftp server
```

**Unused Interfaces –** On a server, we don’t tend to have many interfaces, so unused interfaces may well escape the notice of administrators without much networking experience. Many devices nonetheless ship with all their interfaces enabled and ready to communicate -  If you have unused interfaces on your device, consider administratively shutting them down to prevent unauthorized access.

**Configuration Example (Shutting Down an Interface)**

```
interface GigabitEthernet0/2
shutdown
```

 

 

## Control Plane Policing (CoPP)

Control Plane Policing (CoPP) is a critical security mechanism that helps protect the control plane of Cisco IOS devices from various types of attacks and traffic anomalies. 

### Understanding Control Plane Policing (CoPP)

The control plane of a network device is responsible for managing and maintaining the device's control and management functions. These functions include routing, management interfaces, and control protocols such as OSPF and BGP. Protecting the control plane is essential for maintaining network stability and security.

CoPP is a security feature that allows you to control and limit the rate of traffic destined for the control plane. By doing so, CoPP helps prevent denial-of-service (DoS) attacks, route table overflows, and other forms of control plane abuse.



### Configuring Control Plane Policing (CoPP)

To configure CoPP on your Cisco IOS devices, you need to define a CoPP policy and apply it to an interface or interfaces. Here are the steps involved in configuring CoPP



**Example - Define a CoPP Policy**

Firstly, create an Access Control List (ACL) Define an ACL that identifies the traffic you want to police. This ACL should include the types of traffic you want to protect your control plane from.

```
access-list 101 permit icmp any any echo
```

In this example, an ACL is created to permit ICMP echo requests (ping) to the control plane.

Next, Create a Class Map that matches the ACL you've defined.

```
class-map control-plane
match access-group 101
```

In this example, a class map named "control-plane" is created to match the previously defined ACL.

Now, define a Policy Map - Create a policy map that specifies the action to take on traffic matched by the class map. You can set the desired policing parameters, such as the rate limit.

```
policy-map control-plane-policy
class control-plane
police 80000 1500 1500 conform-action transmit exceed-action drop
```

In this example, a policy map named "control-plane-policy" is created. It applies policing with a rate limit of 80,000 bits per second, a normal burst size of 1500 bytes, and an excess burst size of 1500 bytes. Conforming traffic is transmitted, while exceeding traffic is dropped.

Finally, apply the CoPP policy map to one or more interfaces on your device. Typically, you would apply it to the ingress (input) direction of interfaces connected to untrusted networks.

```
interface GigabitEthernet0/0
service-policy input control-plane-policy
```

In this example, the "control-plane-policy" is applied to the input direction of interface GigabitEthernet0/0.

 

## Port Security

Port security is a powerful feature to prevent an attacker from trying to gain physical access to your network by attaching to an open port, or by attaching a rouge wireless access point. 

### Importance of Port Security

Network switches are at the heart of many network infrastructures, and the ports on these switches are entry points for devices and users. Unauthorized access to switch ports can lead to security breaches, data leakage, and network disruptions. Port security aims to address these concerns by controlling which devices can connect to switch ports.

### Configuring Port Security on Cisco Switches

Cisco switches offer robust port security features that allow you to define and enforce security policies on switch ports. Here's how to configure port security

**Configuration Example - Enable Port Security**

To enable port security on a Cisco switch port, access the interface configuration mode for the specific switch port

```
interface GigabitEthernet0/1
```

then enable port security

```
switchport port-security
```

This command activates port security on the specified interface.

 

**Set Maximum Number of Secure MAC Addresses**

Next, you can specify the maximum number of MAC addresses allowed on the secure port. This limits the number of devices that can connect to the port.

```
switchport port-security maximum <max_mac_addresses>
```

Replace <max_mac_addresses> with the maximum number of MAC addresses you want to allow on the port.

**Configure Violation Modes**

Port security allows you to define what happens when a violation occurs (e.g., when more MAC addresses are detected than allowed). There are three violation modes to choose from

- **Protect** In this mode, traffic from violating MAC addresses is dropped, but the switch port remains operational.
- **Restrict** In this mode, traffic from violating MAC addresses is dropped, and a syslog message is generated. The switch port remains operational.
- **Shutdown** In this mode, the switch port is effectively shut down if a violation occurs. It must be manually re-enabled.

Choose the appropriate violation mode based on your security requirements

```
switchport port-security violation <mode>
Replace <mode> with either "protect," "restrict," or "shutdown."
```

**Specify Allowed MAC Addresses**

You can configure the specific MAC addresses that are allowed on the port

```
switchport port-security mac-address <mac_address>
```

Replace <mac_address> with the MAC address you want to allow on the port. You can repeat this command to add multiple allowed MAC addresses.



**Verify and Monitor Port Security**

You can use the following commands to verify and monitor port security on a Cisco switch

To display port security settings for a specific interface

```
show port-security interface <interface>
```

To display the current port security status for all interfaces

```
show port-security
```

 

## **Virtual LAN (VLAN) Security**

Virtual LANs (VLANs) are a fundamental part of network segmentation and can enhance security by isolating network traffic. 

### **VLAN Security Considerations**

VLANs are used to segment a network into smaller, isolated broadcast domains, which can enhance security by controlling the flow of traffic and limiting its reach. Here are some VLAN security considerations

**Isolation** VLANs separate network traffic into isolated segments, reducing the risk of unauthorized access to sensitive data.

**Broadcast Control** Smaller broadcast domains reduce unnecessary broadcast traffic, which can help prevent network congestion and attacks like ARP spoofing.

**Configuration Example - VLAN Access Control Lists (VACLs)**

VACLs provide access control for traffic within a VLAN. You can define rules to permit or deny traffic between devices within the same VLAN. This helps control and secure traffic flow within your network.

 

**Configuration Example (Creating a VACL)**

```
ip access-list extended <vacl_name>
 permit ip <source_subnet> <source_mask> <destination_subnet> <destination_mask>
 deny ip any any
```

In this example, replace `<vacl_name>`, `<source_subnet>`, `<source_mask>`, `<destination_subnet>`, and `<destination_mask>` with your specific values to create a VACL.

 

**Implement VLAN Access Lists (VACLs)**

VLAN Access Lists (VACLs) are used to filter traffic entering or leaving a VLAN. You can define rules to permit or deny traffic based on source and destination IP addresses, ports, and protocols.

**Configuration Example (Applying a VACL to a VLAN)**

```
vlan access-map <vacl_name> 10
 match ip address <vacl_name>
 action drop
vlan filter <vacl_name> vlan-list <vlan_id>
```

In this example, replace `<vacl_name>`, `<vlan_id>`, and `<vacl_name>` with your specific values to apply a VACL to a VLAN.

### **Disable Unused VLANs**

If you're not using specific VLANs, it's a good practice to disable them. This prevents unauthorized devices from connecting to these unused VLANs.

**Configuration Example (Disabling a VLAN)**

```
no vlan <vlan_id>
```

Replace `<vlan_id>` with the ID of the VLAN you want to disable.

 

## Logging and Monitoring

Effective logging and monitoring are essential components of network device hardening and overall network security. In this section, we'll explore the importance of logging and monitoring, and how to configure logging on your Cisco devices for enhanced security.

### Importance of Logging and Monitoring

Logging and monitoring provide visibility into network activities, help identify security incidents, and aid in troubleshooting. Here's why they are crucial

- **Security Incident Detection** - Logs can reveal suspicious or unauthorized activities, helping you detect security incidents promptly.
- **Troubleshooting** - Logs provide valuable information for diagnosing and resolving network issues.
- **Compliance** - Many regulatory requirements mandate comprehensive logging and monitoring as part of cybersecurity best practices.



**Configuration Example - Set up logging**

You can specify which types of events and messages to log. Cisco devices categorize messages into severity levels, such as debug, information, notice, warning, error, and critical.

**Defining Log Messages**

```
logging buffered <log_level>
```

Replace `<log_level>` with the desired severity level (e.g., "warning" or "error").

**Specify Logging Destinations**

You can send log messages to different destinations, such as the console, terminal lines, syslog server, or a log file. It's recommended to send logs to an external syslog server for centralized storage and analysis.

**Sending Logs to an External Syslog Server**

```

logging host <syslog_server_ip>
```

Replace `<syslog_server_ip>` with the IP address of your syslog server.

Finally, we should determine how long logs should be retained. Retention policies depend on regulatory requirements and your organization's needs but should be long enough to enable incident response and monitoring.

**Configuration Example (Setting Log Retention)**

```

logging history <log_size>
logging history <log_age>
```

Replace `<log_size>` with the maximum log size in bytes and `<log_age>` with the maximum log age in minutes.

**Implement Log Rotation**

Optionally, to prevent logs from consuming excessive storage, configure log rotation. This ensures that old log entries are overwritten or archived when storage limits are reached.

**Configuration Example (Configuring Log Rotation)**

```

logging history size <log_size>
logging history <log_age>
```

Replace `<log_size>` with the desired log size threshold and `<log_age>` with the log age threshold.

By configuring logging and monitoring on your devices, you gain valuable insights into network activities, detect security incidents, and facilitate troubleshooting. It's essential to regularly review and analyze logs to maintain a secure and well-functioning network.

# Final Words

In this article we've taken a look at some practical steps which you can take to secure your network devices - if you have Cisco devices you can simply implement these configurations, however most networking vendors offer these features (even if the configuration is slightly different).