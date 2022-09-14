:orphan:
(linux-distributions-for-dfir)=
# Linux Distributions for DFIR
 
Every DFIR professional requires a forensic lab ready with various tools that can assist with handling incidents. Some software tools may need to be installed by the professional manually on their workstation. For example: tools that can process *[forensic images](get-the-evidence-you-need-with-forensic-images)*, hex file viewer/editor, log analysis tools, etc. There are some *[Linux distributions](a-gentle-introduction-to-digital-forensics-on-linux)* that come pre-installed with tools to assist in DFIR activities. This blog post gives a brief overview of some Linux distros for DFIR.

## Paladin

Paladin is a ‘live’ Linux distribution based on Ubuntu developed by a company called Sumuri. What is a ‘live’ distribution? On your computer, the operating system you are currently using is installed on disk. It is possible to run Linux distributions on your computer via a USB drive without installing it on disk. This is accomplished by:

- Installing the distribution on a USB drive in bootable mode (there are software tools that help you copy a distro in bootable mode)
- Plugging the USB onto your computer 
- Booting your computer from the USB (this can be done by modifying the OS boot order on your computer)

Paladin is capable of acquiring forensic images from Windows and Intel MAC computers. It has a huge library of forensic tools to process evidence like windows *[registry hives](get-the-most-out-of-the-windows-registry-in-your-digital-forensic-investigations)*, windows *[recycle bin data](windows-recycle-bin-forensics-dumpster-diving-for-evidence)*, *[memory dumps](uncover-crucial-information-within-memory-dumps)*, passwords, *[web browser artifacts](web-browser-forensics-uncovering-the-hidden-evidence-in-your-browser)*, *[network traffic data](stay-one-step-ahead-of-the-hackers-by-hunting-suspicious-traffic)*, etc. 

## SIFT Workstation

SIFT Workstation is a VMWare virtual machine image developed by SANS to assist with DFIR. The image can be downloaded and exported into VMWare for use. It is built on top of Ubuntu.

SIFT has a huge library of tools to assist with incident response, memory forensics, malware analysis, threat hunting, disk forensics, image forensics, etc. You can download the VM image and easily set this up on your computer.

## CAINE

CAINE is also a live distribution build on top of Ubuntu that has various tools and scripts to perform digital forensics on Windows and MAC computers. It also has tools to for OSINT (Open Source Intelligence).

## BlackArch Linux

BlackArch is a distribution built on top of Arch Linux having a library of tools for digital forensics and penetration testing. There are various tools to process evidence like *[windows event logs](windows-event-logs-in-digital-forensics)*, registry hives, prefetch files, *[windows file system journal](windows-file-system-journal-in-digital-forensics)*, memory dumps and critical data from MAC computers. 

## Others

There are many other Linux distros like Kali, Pentoo, ArchStrike, Parrot OS that ship with tools to assist in digital forensic investigations. Most of these distros also have tools to perform penetration testing.

A DFIR professional benefits from having multiple tools in their toolkit and also having the ability to use them. 

## Project Idea

Here is a project idea for you: you can *[set up your own DFIR lab at home](build-your-own-digital-forensics-lab-at-home)*!

- Download any of the Linux distros for DFIR and set it up on a virtual machine, eg: Parrot OS
- See the tools available on the distro
- What tools do you observe that can assist in processing evidence from a windows computer?

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MDFIR - Certified DFIR Specialist](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**