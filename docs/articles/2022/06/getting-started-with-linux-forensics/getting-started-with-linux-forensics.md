:orphan:
(getting-started-with-linux-forensics)=

# Getting started with Linux Forensics

The use of Linux systems is increasing every day – in personal computers, servers, IoT devices, etc. When cyber incidents occur, professionals capable of performing forensics on Linux systems are in great demand. It would be a great idea to include ‘Ability to perform Linux Forensics’ in your skill set. Are you wondering how to get started? This blog post will give you a brief introduction to performing Linux forensics.

## How is Linux Forensics different from Windows Forensics?

On Windows machines, most files of forensic interest like _[prefetch files](windows-prefetch-files-may-be-the-answer-to-your-investigation)_, _[event logs](windows-event-logs-in-digital-forensics)_, _[file system journal](windows-file-system-journal-in-digital-forensics)_, _[registry hives](get-the-most-out-of-the-windows-registry-in-your-digital-forensic-investigations)_, etc. can be viewed and processed only using specific tools; either command-line tools or GUI based tools. On Linux machines, most files of forensic interest are plain text files that can be viewed easily in a text editor application.

On Windows machines, most forensic operations can be performed via the GUI. On Linux, forensic processes rely on heavy use of the terminal. For this, the investigator must be well-acquainted with using various command-line tools.

There are fewer flavours of Windows OS – Windows 7/8/10/Server versions. There are many flavours of Linux OS, depending on the distribution type. Although each Linux OS flavour has its unique features, the underlying terminology and concepts are the same. If you are able to perform forensics on a Debian-based distribution, then you will easily be able to do the same on a Red-Had based distribution. All it takes is practice!

## What data can be acquired as evidence from a Linux computer?

Now that you have an idea about the basic differences between Windows forensics and Linux forensics, it would be great to be aware of the different sources of data that can be treated as evidence on a Linux computer.

**System Information**: Due to the various flavors and versions of Linux OS available, when you commence investigation on a system, start with identifying basic system information like OS version and kernel version. _[](collecting-linux-system-information-for-dfir)_ post discusses how this task can be performed.

**Memory Dump**: If the system has been found in powered on state, you can begin by acquiring memory from that machine. You will gain access to critical evidence like list of active processes, active network connections, etc.

**Critical Logs**: Most of the critical log files are stored within the _/var_ _[folder](a-note-on-linux-directory-structure-for-dfir)_. Logs relevant to user authentication, installed software packages, kernel logs, system logs, etc. can be found here.

**Command Line History**: If a system has been configured to store the command line history, then it gives insight into the commands typed into the _Terminal_ application recently. Execution of malicious scripts or commands can be identified by processing the command line history.

**Loaded Kernel Modules**: Some malware load malicious kernel modules to perform its task. Acquiring the list of loaded kernel modules would help track activity on the system.

**System Configuration**: If the user had installed various services like web server, FTP server, etc. then the configuration used by those services would be stored within the _/etc_ folder. If a service has been suspected of being a part of malicious activity, its stored configuration could provide clues about its capability on the system.

**User Files**: Every user is assigned a specific _/home_ directory to store their files. Files would be created, deleted and downloaded. Deleted files can be found within the trash folder. Some critical services also store their files as hidden files, to prevent accidental modification by the user. It is possible to hide files in Linux, simply by adding a dot (.) in front of the file name. All the types of user files serve as critical evidence. With command-line tools, it is possible to create a timeline of all the files on a system. During a forensic investigation, when the critical time window has been identified, it becomes easy to identify the list of files that had been modified/created during that window.

**External devices**: It is possible to find evidence about external devices attached to the computer like USB devices and external hard disks.

**Application Data**: Various user applications like web browsers store their own logs. Identifying the applications installed on the system and acquiring the logs stored by those applications would come in handy during an investigation.

**SSH Keys**: One of the common ways of connecting to a Linux system is via SSH. For this SSH keys will be required, which are usually stored in a hidden folder in a user’s home directory. Identifying if there are any SSH keys on the system will provide an idea about possible remote connections made.

**Networking Data**: Information about the network interfaces on the machine and their configuration will give an idea about the available networking capabilities.

Here is a tip to get started with Linux forensics: start using Linux on a daily basis. You can install Linux on a virtual machine and use it to perform simple tasks – even browsing the web. You will get used to how the interface works and eventually you can learn how to perform advanced digital forensics operations.

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)**
