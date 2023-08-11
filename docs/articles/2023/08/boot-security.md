:orphan:
(boot-security)=

# Boot Integrity and Advanced Boot Security Mechanisms

In the realm of cybersecurity, ensuring the integrity of a system's boot process is of paramount importance – boot time is a critical aspect of starting any system, not least because most traditional security mechanisms cannot operate, since the OS is not yet loaded! With this in mind, attackers often target the boot sequence to gain unauthorized access, plant malware, or manipulate the system's operation. A compromised boot processes can lead to a cascade of security breaches, compromising the confidentiality, integrity, and availability of sensitive data and critical services. What’s worse, a malware infection which interferes with the boot process can be very hard, and sometimes impossible, to detect.

To safeguard against such threats, modern security measures has been developed – these include boot security, Unified Extensible Firmware Interface (UEFI), measured boot, and boot attestation.

 

## Boot Security and Unified Extensible Firmware Interface (UEFI)

Traditionally, computers used Basic Input/Output System (BIOS) firmware to initiate the boot process. Today, BIOS has been replaced by the Unified Extensible Firmware Interface (UEFI), which offers several security enhancements. UEFI is actually not a single system, but rather a specification that defines a more sophisticated interface between the operating system, hardware, and firmware during system startup.

One of the most important services provided by UEFI is known as “secure boot”. Secure boot aims to protect the boot process by enforcing digital signatures on boot-related components such as boot loaders and operating system kernels. In theory, this ensures that only authorized and digitally signed components are loaded into memory during the boot process, therefore Secure Boot helps prevent malware from tampering with the boot sequence and loading malicious code. To achieve this, UEFI maintains a set of Platform Key (PK) and Key Exchange Key (KEK) pairs, which are used to validate signatures.

Additionally, UEFI supports the Trusted Platform Module (TPM), a hardware-based security component that can store cryptographic keys and measurements. The TPM can be used to enhance boot security by securely storing encryption keys, ensuring system integrity, and providing a foundation for advanced security features like measured boot and boot attestation (See below)

*Tip: Remember that any security system based upon key validation only works so long as the keys themselves are secure. There have been numerous high-profile attacks in which a vendor's keys have been compromised, therefore allowing an attacker to push out software and patches which appear to be legitimate.* 

 

## Measured Boot

Measured boot is a security feature that aims to establish a trustworthy and verifiable record of the system's boot process. During measured boot, each stage of the boot sequence is measured and hashed. These measurements are stored in the TPM, creating a cryptographic log of the boot process. By comparing these measurements with known good values, administrators can detect any unauthorized changes that might have occurred in the boot sequence.

Measured boot can therefore provide an additional layer of protection against rootkits and other advanced malware that attempt to subvert the boot process. In addition, as we mentioned above, measured boot can help to mitigate a situation where an element of the key validation system has been compromised or has otherwise failed. 

 

## Boot Attestation

Boot attestation builds upon the concept of measured boot to enable *external* entities to verify the integrity of a system's boot process. This is particularly useful in scenarios where a remote server or service (perhaps a network access control server) needs to ascertain that a client's system is in a trusted state before granting access to resources 

Boot attestation involves the generation of an attestation report that includes the cryptographic measurements taken during the measured boot process. This report can then be presented to an external verifier, such as a remote server, to prove the integrity of the boot sequence. If the measurements match the expected values, the verifier can trust that the system has booted into a secure state. If the boot attestation processes yields values which are not expected, the system can be prevented from accessing the network or resources. 

The attestation process relies on cryptographic principles, ensuring that the measurements and the resulting report cannot be tampered with or forged. The combination of measured boot and boot attestation enhances security by extending trust beyond the local system, enabling remote parties to make informed decisions based on the verifiable state of the system's boot process.

 

## Benefits and Considerations

Implementing boot integrity mechanisms, UEFI, measured boot, and boot attestation offers a range of benefits for system security:

1. **Early Detection of Tampering**: These mechanisms provide early detection of unauthorized modifications to the boot process, helping to prevent the installation of rootkits and other malware.
2. **Chance to Detect Zero****-Day Exploits:** Options such as Boot attestation offer the chance to detect unauthorised modification to a boot component which has nonetheless passed a signature check. 
3. **Trustworthy Remote Access**: Boot attestation enables remote servers to trust the integrity of client systems, enhancing the security of remote access scenarios.
4. **Protection Against Supply Chain Attacks**: By verifying the integrity of boot components, organizations can mitigate the risk of compromised hardware or software being introduced during the supply chain.
5. **Compliance Requirements**: Many security standards and regulations, such as the Payment Card Industry Data Security Standard (PCI DSS), require the implementation of secure boot processes.

However, there are some considerations to keep in mind:

1. **Complexity**: Implementing these advanced security mechanisms requires a solid understanding of cryptographic concepts and may introduce complexities to the boot process.
2. **Compatibility**: Older hardware and operating systems might not fully support UEFI, measured boot, or boot attestation, limiting their applicability. UEFI is supported on most user devices today – all current Windows versions, most larger Linux distributions and all current versions of MacOS utilise UEFI – however, many IoT older devices and older ICS/SCADA devices cannot use these features. 
3. **Management and Maintenance**: Proper management and maintenance of cryptographic keys, certificates, and boot policies are essential to ensure the ongoing effectiveness of these mechanisms. While the implementation of these options together presents a significant hurdle for an attacker there are still conceivable ways to bypass these protections. 

 

## An Example

Keep in mind that it's not just user workstations which utilise boot security - many modern network devices, IoT devices and mobile devices also use the same process. This example shows the checksum record for the boot stages on a Cisco Switch. The hash measurements are displayed for each of the three stages of software successively booted. These hashes can be compared against Cisco-provided reference values to ensure the boot process succeeded as expected.

```
show platform integrity sign nonce 123
Platform: C9300-24U
Boot 0 Version: F01144R16.216e68ad62019-02-13
Boot 0 Hash: 523DD459C650AF0F5AB5396060605E412C1BE99AF51F4FA88AD26049612921FF
Boot Loader Version: System Bootstrap, Version 17.1.1r, RELEASE SOFTWARE (P)
Boot Loader Hash: 34A2070D9EAE97E4FC4315A9BAF0E31FFD285E09F0B7F621955607A0FBC1D134ACC0068D8918F15B01975187458F6A46DF0F3DF9BA1593A3CD7BB4DF12487473
OS Version: BLD_POLARIS_DEV_LATEST_20191023_070152
OS Hashes:
cat9k_iosxe.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.bin: 8656F31DE26886F555B93258ADA7F354E083F1AFD22E676D3D83E956F6AA3307F9553E0D94FF752BD6E08DED5DAE067528CE44B16F3DD30A9FB4793E38BAE952
cat9k-wlc.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: 33DDC53F932C9EC4CED2B402DA600511D2E2C5F4EF8037CE5D7D8E70B7050936D060467E7533FC7064073F6B3D9ED5AE53F756DD3493A38D564E96E7A49E25E5
cat9k-guestshell.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: 4F2057EC660DCDE8EAE08CBE932E035338C7DE0A482B12CB443B506EA2298DE3B8EA1F805A28C0BBBFCDA089AE280E6953870161DD5E7F0C16C66A75FEB48546
cat9k-webui.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: 45F3315C88E57A45F21A508C3771FADF0C8DB952F8848CA1C81F5588FFE466B9AF96295A8247DEFC47CD26A39D1802F0507109897297A4B5A86EFCADB3CFC261
cat9k-cc_srdriver.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: EE6B1B1920145F5C978374ECB8374917E4E2825B059B7C95D409312C2C19271317AB349F775D4E1860DD0B22E2F68A961566A00466259D93323972F98E8B17E9
cat9k-srdriver.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: EAF591B3945F14596A8C8AE8022722B6FC2073DFCEC4D24FE2518CAD7338F73A26F4AD29D00602A56E0B8EF6FAA4463239094BA8446D7B074AAF00930253C281
cat9k-sipbase.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: 27155ECC5007A7A457C3E32632576132317EBF905972454C0305932B9A97591D37AFFC7AB40EC19E7B82DE042B31078309C38F4B81AA756F8D4180662D10F051
cat9k-sipspa.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: EDC255EC04D267055BE433D60F8CB4CCC426773C12442A291B15838E0D742F99CD45FD01B7E03AC139FDCA3143D83630052B45CCCBC834A84778CFEFF938CBC9
cat9k-espbase.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: 65B0C8305E572247AAFE188A8C0B5081697CDD60BD8501FC2C88A8101862A63FED8B4AEF276D008F03F28978175FC3C4BF0B8FB3C238CDB619952F46CCF19CF1
cat9k-rpbase.BLD_POLARIS_DEV_LATEST_20191023_070152.SSA.pkg: A297AA546323F63751F1CDA42558975D549E83A8D928A6CAFBD5A77AE19C6645620488E5A40E99FD8BE0F9726B12FF9591D3107825B885C9F7C7244FB31491F9
PCR0: 32E782AF9D75D12AC55BA5F67E9E8F375589CAF9C3558BC90E0EB969A84CDE95
PCR8: F0637823517D08D145F3E4DF207673D194FCB437E8B07170887E7AE279F88178
Signature version: 1
Signature:
BD8D6493B376918C1F47FA1B5FDE7CDD2DF5D51E8DD29D31C4C6744BEF96ECFF797AEFBA2992C404823B3049E8FE81123A6B27374E1D34333418381525653AEF856C976DEEF5C6CB4DA88DEF8EB0BA2E418D4A0725438B57B68477385621358587500C83DAFD7F55DC77A531735CDE95E12667E8F80B3E2A71721E4124A9D7F40085D042F3CA23CE5D91DAED3D590A90950C5227140F2F657E3FE74A6F459B55ABEC8ADCB4A8D18D1B19814BB130512925E64FFB18EB79900C0AB64F2550A7ACAFC4F2F755CA554FC9DEC3067474FF4292489BF0EBCA4E91DA6F5C85DA55B3DE4682EC899D93169FC1C8ADC4744900CEECC29694FC8777BDFF8CA47D1365827C
 
```

# Final words

Boot integrity is a critical aspect of cybersecurity, as it forms the foundation of a secure computing environment. Although it’s often an aspect we don’t think much about, it’s impossible to have a secure system without a secure boot process. Modern security mechanisms such as UEFI, measured boot, and boot attestation provide advanced protection against unauthorized modifications to the boot process, rootkits, and other malware. 

By leveraging cryptographic principles, these mechanisms help to establish trust in the boot sequence and extend this trust to remote entities, ensuring the security and integrity of systems in various scenarios. While their implementation might introduce complexity, the benefits in terms of early threat detection and improved system security make these mechanisms indispensable tools in the modern cybersecurity toolkit. Nonetheless, do not forget that no security mechanism is totally foolproof, so wherever possible implement as many safeguards as possible. 

 
