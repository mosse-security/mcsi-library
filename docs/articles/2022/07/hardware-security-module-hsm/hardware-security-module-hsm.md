:orphan:
(hardware-security-module-hsm)=
# Hardware Security Module HSM
 
A general-purpose hardware security module is a cryptographic device that complies with standards and employs strong encryption, physical security measures, and logical security controls to safeguard sensitive data. A hardware cryptographic module (HCM), secure application module (SAM), or personal computer security module (PCSM) are further names for an HSM.

A trusted environment is created by the hardware security module so that various cryptographic processes, such as key management, key exchange, and encryption, may be carried out. "Trusted" here refers to being free of viruses and malware as well as secure from exploits and unwanted access.

An HSM is reliable because of:
- It is constructed on tested, specialized hardware that has been certified, and it runs an OS that is security-focused.
- Cryptographic data is actively protected and concealed throughout the whole design.
- Through a regulated interface that is rigorously governed by internal regulations, it has restricted access to the network.

Without a hardware security module, regular operations and cryptographic operations occur in the same places, allowing attackers to access both sensitive data like keys and certificates as well as regular business logic data. Hackers have the ability to install arbitrary certificates, increase unwanted access, change code, and negatively affect cryptographic processes in various ways.

## The Function of Hardware Security Modules

The foundation of an HSM's fundamental operation is encryption, which is the act of transforming sensitive data into something that only those with authorized access can decipher. HSM capability also includes safe decryption and message authentication.

Because they are needed to build encryption keys, randomly generated values are crucial to the encryption procedure. Storage of encryption keys in a safe setting is crucial since having the keys in hand always puts decrypting that sensitive information just one step away.

The encryption keys used by various devices are generated and stored by hardware security modules. They have specialized hardware that generates high-quality random keys and entropy. Larger businesses could use more than one HSM at once as opposed to simply one. A simplified, central key management system based on both strict internal security norms and external requirements enhances security and compliance whether one or several HSMs are implemented.

Typically, HSMs are certified in accordance with widely accepted standards like FIPS 140 or Common Criteria. This has to do with the crucial role that HSMs play in protecting systems and software, as well as the requirement to reassure users that products and cryptographic algorithms are designed and implemented in a proper way. Security Level 4 is the highest certification level of FIPS 140 security that is practicable. Users frequently check an HSM's security in financial payments applications against the guidelines set out by the Payment Card Industry Security Standards Council.

## Architecture for Hardware Security Modules

HSMs may have features that are tamper-proof or tamper-resistant. Hardware security modules, for instance, may provide outward indications of logging and alerting or may stop functioning if they are tampered with. Keys may be deleted by some HSMs if tampering is found. Hardware security modules often comprise one or more cryptoprocessor chips or a module including a mix of chips to thwart bus probing and manipulation. They are shielded by tamper obvious, tamper resistant, or tamper responsive packaging.

Since HSMs are frequently a part of mission-critical infrastructures like an online banking service or a public key infrastructure, they may typically be clustered for high availability. Some hardware security modules provide business continuity and adhere to the data center environments' high availability standards.

Some HSMs have the ability to internally run modules that have been particularly created in native C, Java, or other languages. An enterprise that has to run business logic or unique algorithms in a secure environment may benefit from such a capability. In many cases, COTS software and operating systems, as well as other complicated activities, may be loaded and executed by next-generation hardware security modules without requiring extensive reprogramming.

## Applications for Hardware Security Modules

A hardware security module can be used by any program that uses digital keys. In general, a compromise of the keys would need to have a significant, detrimental effect in order to justify the deployment of an HSM. In other words, a hardware security module USB or other device can only produce and retain very valuable digital keys.

The following are a HSM's primary duties:
- For a certificate authority, the HSM serves as an onboard key generation and secure key storage facility, especially for primary keys, or the top-level keys that are the most private and sensitive.
- Supports authentication by confirming digital signatures.
- Checks the accuracy of sensitive data stored in places that are comparatively less secure, including databases, and securely encrypts the data for storage.
- Produces safe keys for the creation of smart cards.
- Controls keys for databases and transparent data encryption keys for tape or disk storage systems.
- Protects sensitive data, including cryptographic keys, both physically and logically against unauthorized use, disclosure, and prospective attackers.
- Supports both symmetric and asymmetric encryption, sometimes known as public-key cryptography.
- Many HSM systems provide considerable CPU offload for asymmetric key operations, and some HSM systems function as hardware cryptographic accelerators for SSL links. Additionally, the majority of HSMs now support elliptic curve cryptography (ECC), which although using lower key lengths, offers greater encryption.
- An SSL acceleration HSM can move RSA operations from the host CPU to the HSM device for applications that are performance-critical and must use HTTPS (SSL/TLS). Typically, RSA operations need several big integer multiplications, and 1024-bit RSA operations may be carried out at a rate of 1 to 10,000 by standard hardware security module. Some security modules based on specialized hardware are capable of 20,000 operations per second.
- In PKI contexts, asymmetric key pairs may be generated, managed, and stored by registration authorities (RAs) and certification authorities (CAs) using HSM.
- The payment card sector uses specialized HSMs called bank hardware security modules. As a result, these HSMs support both the normal hardware security module operations as well as the specific capabilities required for transaction processing and industry standards compliance. Personalizing credit and debit cards and approving transactions are typical applications. The Payment Card Industry Security Standards Council (PCISSC), ISO, and ANS X9 are the principal standard-setting bodies for banking HSMs.
- Some registries save the essential data in HSMs for signing big zone files. For controlling DNS zone file signing, OpenDNSSEC is an open source hardware security module utility.
- Cryptocurrency wallets may be created using HSMs.

## Hardware security modules' features and advantages

Physical access prevention, secure key management, safe key generation, and secure execution environment are the major advantages of hardware security modules.
It is impossible to fully shield conventional IT systems from outside assault. HSMs, in contrast, are equipped with a number of safeguards that are intended to thwart external assault and any physical manipulation. Voltage and temperature sensors, chips with resin embedding, and drill protective foil are examples of these.

For instance, sensors would immediately detect an attempt to drill open an HSM device, whether it be through breaking open the casing or using acid or icing to erode the layers. This would then set off an alarm and launch any specified countermeasures specified in the configuration, such as the deletion of keys.

Keys are only valuable if they are unreliable, well-protected, and difficult for attackers to guess. Because they rely on conventional instructions that handle if-then scenarios, typical IT systems have limited capabilities for creating safe keys. Unfortunately, a smart attacker may be able to guess the "then" or output data by knowing the "if" or input data for every given command.

This problem is solved by HSMs by producing really random keys. In order to do this, they register data from nearby random physical processes, such as air noise or atomic decay processes, in order to provide unexpected values that serve as the foundation for random keys.
The creation, storage, and usage of these keys by a hardware security module (HSM) for the execution of signatures, encryptions, and other cryptographic operations are significant since all of these security-critical actions take place inside the HSM's protected environment.

The environment offers the highest level of defense against logical attack since the keys for cryptographic operations never leave the HSM; it is practically impossible to steal. By supplying a safe execution environment for user programs, certain hardware security modules also shield users from Trojans and insider threats. Inside the secure space of the HSM, the whole application is coded and performed in these systems.

## Hardware security modules' disadvantages

Ironically, hardware security has advantages over software-based security as well as disadvantages. 

The disadvantages of hardware-based security are generally as follows:
1.	Because it uses a dedicated security IC, or a CPU with specific security hardware, it is more expensive than software security. 
2.	Since hardware security, such as hardware encryption, is typically coupled to a specific device, one solution cannot be used to secure the entire system and all of its components, making it less versatile than its software counterpart.
3.	Compared to software-based solutions, hardware-based solutions are more difficult to upgrade and/or update since those functions can only be performed through device substitution.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::