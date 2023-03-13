:orphan:
(learn-how-to-secure-your-personal-devices-and-improve-your-cyber-skills)=

# MCSI #009: Learn how to secure your personal devices and improve your cyber skills

It is important to note that you already possess the tools necessary to begin learning about cybersecurity. Your personal computer and cell phone are excellent resources for gaining knowledge about operating systems, software, and network security. In fact, if you dedicate time to researching and implementing safeguards on your own personal devices, you will know more about security than the majority of IT professionals.

This week, I challenge you to take on this task!

## Step 1 - Create a bastion Virtual Machine (Beginner)

If you are a beginner in the field of cybersecurity, it is recommended to begin by setting up a secure virtual machine. Those who are familiar with Windows may wish to start with that operating system before attempting Linux and OSX.

- Download and install VirtualBox
- Download and install Windows 11
- In the virtual machine, install:
  * A VPN client
  * The TOR Browser
- Create covert email and social media accounts:
  * Create a Proton Mail address
  * Create fictitious social media profiles on Twitter, LinkedIn, Instagram and Facebook

Congratulations! You now have access to a secure environment. These simple tasks will provide you with a great deal of knowledge about cybersecurity.

## Step 2 - Implement the ACSC Hardening Guide (Intermediate)

Ready to take your security to the next level? The Australian Cyber Security Centre has released an outstanding guide outlining key steps to harden Windows 10 workstations. Although Windows 11 is now available, the majority of the guide's suggested protections remain applicable.

- Harden Microsoft Office against common spear-phishing attack techniques
- Ensure that all applications are up-to-date and configured to auto-update
- Enable Application Control to prevent malicious executables from running
- Mitigate malware attacks using the Attack Surface Reduction (ASR) feature

We urge you to take a few days to study and put into practice as much of the guide as you can. Make sure you comprehend the purpose of each security control. You may want to test them in a virtual machine before implementing them on your host machine.

Once you’ve done that, go to [MS-Guard](https://www.mosse-security.com/products/msguard.html) and use an automated scan to check if your PC has met all the security standards.

## Step 3 - Monitor your devices and write your own detection rules (Advanced)

```{thumbnail} ../images/newsletter/2023-009-costin-raiu.png
:class: block max-width-500 mb-4 mt-4 mx-auto
```

> “I honestly I do operate on the principle that my computer is owned by at least three APTs” - Costin Raiu

For those of you who are more advanced in their practical skills, we challenge you to deploy a SIEM solution on your devices. Options include setting up the ELK Stack with Sysmon, or installing a more economical EDR such as Lima Charlie. Once that is accomplished, you may proceed to monitor any potential gaps within your prevention capabilities.

1. Which security controls could not be enabled on the device?
2. If an attacker takes advantage of this gap, where would they generate logs?
3. How can I capture these logs in real-time and save them in the cloud?
4. How do I write detection rules to alert me of an attack?

## Final Words

Protecting your devices is an excellent way to gain expertise in the field of cybersecurity. We have mainly discussed methods for defending Windows operating systems, but the same principles can be applied to other operating systems, devices and cloud services. To ensure optimal protection, consider the following strategies:

1. Research security features that are not active by default and enable them
2. Develop scripts to audit the settings of your devices and accounts automatically
3. Install tools to monitor your devices and accounts in real-time
4. Create detection rules to monitor gaps within your defenses

## When you’re ready, we offer 2 courses that can help you

Are you looking to gain skills in how to protect computer networks? If so, we offer two outstanding courses which will instruct you on how to make Windows networks more secure on a large scale, and detect intrusions:

- [Network Security Essentials:](https://www.mosse-institute.com/certifications/mnse-network-security-essentials.html) This certification in network and endpoint security will give you the skillset needed to safeguard small and medium size organizations from cybercrime. You will learn how to prevent cyber adversaries from gaining access to systems, through implemented prevention techniques.

- [SIEM Tactics Bootcamp:](https://www.mosse-institute.com/bootcamps/siem-tactics.html) The SIEM Tactics bootcamp is ideal for individuals who want to learn threat detection and hunting. This intensive, 20-hour course provides participants with the knowledge and skills necessary to defend their organization against sophisticated cyber threats. You will learn how to identify, investigate, and respond to incidents using a SIEM platform.