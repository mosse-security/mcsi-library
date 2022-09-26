:orphan:
(performing-digital-forensics-on-a-windows-machine)=

# Performing digital forensics on a windows machine – where do I start?

You have just taken up a role as a Junior Digital Forensic Analyst. You have been informed that your regular duties would involve searching for evidence on windows machines suspected of being compromised. If you knew what evidence to collect, when to collect it and how to collect it; then you will be in a great position to help your team with the investigation. This blog post will provide a high-level overview of the various sources of evidence on a windows machine and how they may prove useful during an investigation.

## Assess the Situation

Consider a pre-heated oven. If the oven is connected to the power outlet and set at a particular operating temperature, the temperature inside the oven remains high. Once the oven is disconnected from the power outlet, the heat begins to dissipate and the device eventually comes back to room temperature. It can be said that the heat is ‘volatile’.

Likewise on a Windows machine, some data that exists when the device is in a powered-on state, disappears when the device is powered down. That data is referred to as ‘volatile’.

When presented with a Windows machine for investigation, you can begin by checking if the machine is in the powered-on state. If so, you can begin collecting volatile data from it, before proceeding to collect other non-volatile data. In most situations, volatile data contains critical evidence for an investigation.

## Volatile Data

The following section provides a brief overview of the volatile data available on a Windows machine.

**1. RAM data**

The memory of a computer stores critical volatile information like list of active processes, services, loaded drivers, encryption keys, command line history, network connections, critical registry data not written to disk, clipboard data, etc. It is typically the first piece of evidence acquired on a compromised machine. It provides insight into the activity on the machine at the time the compromise was identified.

**2. Page file**

When a computer’s RAM is used beyond capacity, a page file is used to store sections of memory. Within the page file, it is possible to find data that had previously existed in memory. This source of evidence is valid only if a computer is not configured to clear the page file on system shutdown. A page file is typically present at `C:\pagefile.sys`.

**3. Hibernation file**

If hibernation mode has been enabled on a machine, the hibernation file stores information about the system’s current state: inclusive of active processes, services, etc at `C:\hiberfil.sys`.

## Non-Volatile Data

The following section provides a brief overview of the volatile data available on a Windows machine.

**1. Event logs**

Every Windows computer stores information about critical system, software and user events in a central location referred to as event logs. During a forensic investigation, event logs are helpful to identify the recently logged on users to the machine, recently modified software and user accounts, recently executed software and even changes to system configuration. Event logs can be found at `%SYSTEMROOT%\System32\Config`.

**2. Prefetch files**

Every executable run on a machine has a prefetch file stored in `%SYSTEMROOT%\Prefetch`. A prefetch file has information about when the executable was run last, how many times it was executed, the files and directories referenced by the executable, etc. However, this feature works only if prefetching is enabled on a computer.

**3. Registry hives**

The registry hives store critical system configuration information and user-specific information. Information about which executables are run at system boot time, which USB devices were plugged into the computer, user accounts on the system, configuration of installed applications, etc. can be found here.

**4. Amcache hive**

The Amcache hive is part of the registry. It stores information about recently executed applications on the system. Once it is identified from this file that an application has been executed, you can proceed to look for a prefetch file for that application to get more information about its activity on a computer. The Amcache file can be found at `%SYSTEMROOT%\AppCompat\Programs\Amcache`.

**5. Scrum dump**

A System Resource Utilization Manager (SRUM) dump provides information about the applications that have been run on the system in the last 30 days. It can be found at `%SYSTEMROOT%\System32\sru\srudb`.

**6. Background Activity Moderator**

BAM service was introduced in Windows 10 version 1709 to record information about the full path of the executable that was run on the system, along with its last execution time. The service stores its data within the registry.

**7. Recycle bin**

If a perpetrator attempts to remove files from a computer by deleting them, there is a chance that the files can be found in the recycle bin. Files that have been deleted using the GUI or delete key can be found here. However, if a user deletes a file using Shift + Delete key combination, then it is not possible to retrieve the deleted file.

**8. Application data**

The various applications installed on the machine also store their own logs. For example, web browser applications like Firefox store browser history, cookie data, user profiles, etc. which is a rich source of evidence about recent Internet activity on the system.

**9. User account information**

Some adversaries create unauthorized user accounts on a machine to gain uninterrupted access. Analysing the user accounts present on a machine gives an idea about the full extent of compromise if any.

**10. User Downloads folder**

In some cases, a user may download a malicious file and execute it. The contents of the Downloads folder are indicative of the files recently downloaded on the system.

**11. Temporary files**

Every user on a Windows machine is assigned a location `%SYSTEMROOT%\AppData\Local\Temp` to store temporary internet files, temporary files used when an executable is run and also holds temporary copy of documents that are being edited.

**12. File system log**

Every Windows machine stores a log of recent changes to its files and directories in a hidden system file called `$UsnJrnl`. Many forensic tools can acquire and process this file.

Although all windows machines process and store data in the same way, the data to be acquired as evidence depends on the investigation. Being aware of the various sources of evidence specified in this post and knowing how to process them, would put you in a position to act efficiently during an investigation.

**13. Scheduled tasks**

A user can schedule a specific task to occur on the Windows machine. Some adversaries can schedule malicious activities like running an application at a specific time, sending or receiving data, starting or stopping services, etc. An investigator can find information about scheduled tasks at `%SYSTEMROOT%\System32\Tasks`.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
