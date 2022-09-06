:orphan:
(uncover-crucial-information-within-memory-dumps)=

# Uncover Crucial Information within Memory Dumps

You are a Junior Digital Forensics Investigator. Your manager has asked you to get familiar with performing forensics on memory dumps. This blog post will give you a brief overview about the potential information you can find in a memory dump.

## What is memory forensics?

A memory dump represents data present on a computer's RAM at the time when memory is acquired. Processing a memory dump for evidence of recent activity on a system is formally referred to as memory forensics. You can read more about an introduction to memory forensics _[Discover the Truth with Memory Forensics](discover-the-truth-with-memory-forensics)_

Although most memory dumps contain generic information like active process listing, networking information, etc.; some critical information depends on the operating system used on the computer from which the dump was taken.

## Information in a memory dump

The following section provides a brief overview of information you can find in a memory dump and what it may indicate.

**Process Information**: Let’s assume that you are in a department store. You fill up a shopping cart with the items you need, purchase them and leave the store when you are done. Now let’s map this scenario to processes in memory.

Every time you execute an application, say `notepad.exe`, the binary for it is brought into memory and a process is created. This can be likened to you entering a department store. As you enter data into the notepad application, that data can also be found in the memory dump in a region called _process memory_. That data can be likened to the shopping cart that you use in the department store. This means, in memory you can find the binary (executable file) that was used to start the process and also the data used by the process.

Consider that you have left the department store. Store employees may be able to identify you as a customer. Similarly, once you close an application on your computer, you may find evidence in a memory dump that it was previously used.

Within a memory dump, you can find the names of applications that were in use at the time the dump was taken, data used by those applications and even applications that had been used previously on the computer.

**Networking Information**: If web browser applications, video conferencing applications, streaming applications, or any other applications using the internet; were in use at the time the memory dump was taken, you can extract information about the activities performed using those applications. This is quite useful when malware activity is suspected on a computer.

**Kernel Related Information**: A cup of coffee can wake you up in the morning. You may even add supplements like milk and sugar. The kernel is a software program that wakes up the rest of the operating system. The kernel sometimes uses ‘supplements’ like drivers or modules to help bring up the operating system.

Within a memory dump you can find information about the drivers loaded by the kernel. This is particularly useful when you are investigating a malware attack.

## Operating System Specific Information in a memory dump

**Windows**: In a memory dump acquired from a machine running Windows, you can find information about recently modified registry keys, recently generated event logs, recently created files on disk, any existing master boot records, dynamic link libraries (DLLs) loaded etc.

**Linux-based**: In a memory dump acquired from a machine running a Linux-based OS, you can find information about temporary filesystems used, kernel buffer messages, current mountpoints on the system, IO devices used, etc.

**Mac**: In a memory dump acquired from a machine running Mac OS, you can find information like the version of Mac used, mounted filesystems, user sessions, kernel buffer messages, arguments passed to the kernel at boot time, etc.

It is okay if you do not understand some of these terms right now.

## How can I get started with memory forensics?

You can practice memory forensics right now! Here is a project idea that you can try on a Windows machine. If you are using a Linux-based or Mac computer, you can try this out using a text editor application. You can also use virtual machines.

1. Create a notepad file called `fruits.txt` and enter the names of five fruits
2. Take a memory dump of the machine
3. Identify a tool to process the memory dump
4. List the processes from the memory dump
5. Attempt to identify the process entry for notepad (or text editor application)
6. Dump the memory of notepad process (this is equivalent to viewing the items on your shopping cart)
7. Use ‘strings’ tool to identify the human-readable strings from the process memory dump. See if you can spot the names of the fruits you entered in `fruits.txt`
8. Open the memory dump in a hex viewer and see if you can spot the name of any fruit you entered in `fruits.txt`

If you did, great!

This is just a small example. In the real world, maybe you can find information about contraband drugs or critical passwords or keys or offshore bank account details that proves to be significant in a case.

Memory forensics helps uncover critical evidence, that is otherwise not easily available to a forensic investigator.

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**
