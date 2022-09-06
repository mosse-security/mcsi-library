:orphan:
(discover-the-truth-with-memory-forensics)=

# Discover the Truth with Memory Forensics

Memory forensics is the process of analyzing a computer's memory dump for evidence of a compromise. This process can be used to identify malicious software, track down system intrusions, and recover deleted data. Memory forensics is a critical tool for incident response and digital forensics investigations.

## What is memory forensics?

Here is a sequence of numbers: 130, 62, 78, 54. If your friend asks you to remember this exact sequence and repeat it after an hour, maybe you would remember it. If your friend asks you to repeat this exact sequence after three days, you may not easily remember it. The sequence exists in your mind, in memory only for a short period of time.

Likewise, every computer has a memory region which holds data about recent activity on the system for a short period of time. Data in the hard disk is brought into memory before being processed by the various applications on the system.

Let’s assume that a computer incident has occurred. You are a digital forensic investigator who has been called in to assist with the investigation. In order to identify details surrounding the incident, you need to know about recent activity on the system. A computer’s memory holds information about the tasks performed on the system recently, the applications used recently, application data, etc.

Memory forensics is the technique of acquiring the memory from a target computer using special tools and processing the acquired memory for evidence of recent activity. In other words, it is acquisition of data in the computer’s RAM. The acquired memory is referred to as ‘memory dump’ and its file size is almost equivalent to the size of RAM on the target machine.

## When should you perform memory forensics?

Data that is present in computer memory exists only until the system is in powered on state. The data disappears when the system is powered down. This aspect is referred to as ‘volatility’ of data.

During an investigation, if the target machine is present in powered on state, then the first recommended task would be to acquire its memory. If the machine is in powered down state, then it is not possible to acquire its memory.

## Why should you perform memory forensics?

Typically in a forensic investigation, [memory dumps, forensic images and other artifacts would be collected](get-the-evidence-you-need-with-forensic-images).

Some volatile data present in memory like encryption keys, passwords, clipboard data, list of active processes, hidden processes, changes to registry data, loaded dynamic link libraries (DLLs), network connection information, etc. may not be present in forensic images or other artifacts. In many situations, the memory dump had critical evidence that helped identify recent activity on a system.

Memory forensics is performed to gain access to significant evidence that may not be accessible otherwise.

## How to acquire and analyze a computer’s memory?

Memory can be acquired directly using hardware or using various commercial and open-source software tools designed to help acquire memory. An example of a free software tool is dumpit.exe.

Once a memory dump has been taken, it can be analyzed using free tools like Volatility, Redline, etc.

The acquisition and analysis tasks can be performed on Windows, Linux-based or Mac systems.

## Best practices for memory forensics

Here are some best practices to consider when performing memory forensics:

1. Identify the operating system type and version of the machine from which memory is to be acquired.
2. Ensure that you acquire the memory of the system as soon as the investigation starts.
3. Make sure that you store the acquired memory on external storage media and not on the target machine itself. It prevents any modification to existing evidence on the target computer. (When you purchase a product from a store, you would carry the product with you and not leave it at the store!)

Let’s assume you are reading this blog post using Firefox browser. Right now, if you take a memory dump from your computer and analyze it, you can infer that Firefox application is being used. You may even recover a copy of this webpage stored in memory!

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**
