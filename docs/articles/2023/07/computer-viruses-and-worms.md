:orphan:
(computer-viruses-and-worms)=

# Computer Viruses and Worms

Malware sophistication is rapidly advancing, surpassing the effectiveness of traditional detection methods. Previously, basic signs of infection like new file creation, configuration changes, and system file alterations sufficed for detection with standard antimalware solutions. However, modern malware has evolved to evade such simplistic detection methods. Viruses and worms particularly stand out as formidable adversaries capable of causing widespread damage to networks and devices. To protect our digital environment and maintain the security of our data and systems, we must comprehend the mechanisms, characteristics, and distinctions of these threats. This article explores the key attributes, indicators of attack, and differences between viruses and worms, while also discussing some high-profile attacks that have been based on them.

## What is a Virus?

A virus is a small piece of code or application designed to infect software. Its primary purpose is to reproduce and carry out its intended action, but it relies on a host application to achieve this. In other words, viruses cannot replicate independently. When infecting a file, a virus inserts or attaches a copy of itself to the file. However, the virus itself is merely the "delivery mechanism". It can contain various payloads, such as deleting system files, displaying specific messages, altering system configurations, stealing sensitive data, installing sniffers or back doors, and more.

The transmission of viruses commonly occurs through infected email attachments, compromised websites, or downloaded files. These viruses exploit security vulnerabilities in operating systems or applications. Viruses can be categorized based on the infection techniques they employ:

* **File Virus:** A file virus specifically targets executable files which typically have extensions like .exe, .com, or .dll.

* **Boot Sector Virus:** A boot sector virus infects the boot sector of a computer and either moves data within the boot sector or overwrites the sector with new information.

* **Macro Virus:** Macros are programs written in Visual Basic and are generally used with Microsoft Office products. A macro virus is a specific type of computer virus that targets applications that support macro functionality, such as word processing software (e.g., Microsoft Word) or spreadsheet programs (e.g., Microsoft Excel). 

* **Script Virus:** A script virus infects scripts or script-based files. Scripts are sets of instructions or commands written in scripting languages like JavaScript, VBScript, or PowerShell. Script viruses can exploit vulnerabilities in scripting languages or their interpreters to inject malicious code into script files.

## What is a Worm?

Worms are segments of code designed to penetrate computer systems and networks. Upon infiltrating a system, worms actively scan the network for other susceptible devices in order to infect more devices. With their ability to self-replicate swiftly, worms consume valuable network resources. This can lead to network congestion and potential system failures. Moreover, worms engage in a range of malicious actions, such as data theft, establishing unauthorized backdoors, or initiating distributed denial-of-service (DDoS) attacks. Worms frequently target outdated software or devices lacking robust security measures, posing a substantial risk to overall security.

## Differences between Viruses and Worms

Viruses and worms share similarities as malicious software, but they also possess distinct characteristics and behaviors. Here are the key differences between viruses and worms:

Viruses rely on user actions or the execution of infected files to spread, which means they are dependent on human behavior or user negligence. For a virus to propagate, an infected file must be shared or executed by someone. Worms, however, are self-propagating and can spread automatically without human intervention. They exploit vulnerabilities in network protocols, operating systems, or software applications to infect systems and continue their propagation.

Viruses need a host program to reproduce and spread. When an infected file or program is executed, the virus activates and infects other files by modifying or replacing them with infected copies. In contrast, worms can reproduce on their own without a host application and are self-contained programs.

## Popular Examples of Viruses and Worms

A few notable examples of viruses and worms include the following:

* **Melissa Virus:** This virus emerged in 1999 and spread by tricking users into opening an infected Word document received via email. This virus primarily affected computers running Microsoft Word and Outlook, targeting the Windows operating system.

* **ILOVEYOU:** This virus spread through email in 2000, infecting millions of Windows computers by tricking users into opening an email attachment. It caused widespread damage by overwriting files and stealing passwords.

* **Code Red:** Code Red worm emerged in 2001 and targeted Microsoft IIS web servers running on Windows NT and 2000. It exploited a vulnerability to propagate and launch distributed denial-of-service (DDoS) attacks.

* **SQL Slammer:** The SQL Slammer worm emerged in 2003 and spread rapidly by exploiting a vulnerability in Microsoft SQL Server. It caused widespread internet slowdowns due to its rapid propagation, leading to significant disruptions.

* **Mydoom:** Mydoom was a major computer worm that emerged in 2004. Mydoom spread through email and infected Windows systems, creating a massive botnet and launching DDoS attacks. 

* **WannaCry:** WannaCry was also a major worm that emerged in 2017. It spread globally, targeting computers running Microsoft Windows. It exploited a vulnerability in the Windows operating system and encrypted files, demanding ransom payments in exchange for decryption.

## Conclusion

To this day, both viruses and worms represent a major threat to the security and privacy of organizations worldwide. Infection caused by them can lead to significant damage, including system disruptions, data breaches, financial losses, privacy breaches, and compromised trust in technology.