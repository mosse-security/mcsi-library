:orphan:
(forensic-importance-of-windows-file-management)=

# Forensic Importance of Windows File Management

Have you ever wondered how many files exist on your hard disk right now? Thousands. How does Windows operating system manage thousands of files efficiently? This blog post will give you a brief introduction to how Windows performs file management and its forensic significance.

## A quick analogy

Consider an airplane. It would have a pilot, co-pilot, cabin crew and passengers. The pilot, co-pilot and cabin crew all have duties assigned to them. The passengers are free to spend their time as they please.

Consider a Windows computer with a large number of files. Most Windows systems use New Technology File System (NTFS) to handle these files. You cannot see NTFS, but it is managing all the files on your computer right now. Just like the pilot and cabin crew with assigned duties, some files on your computer are assigned ‘file management duties’. These are referred to as 'system files'. Other files like your photographs, e-books, movies, music, etc., can simply exist on your hard disk. These are referred to as ‘user files’.

## What are these ‘System Files’?

The following is a list of all the major NTFS System files:

**`$MFT`**: This is a large file that has a record (an entry) of every file that exists on the hard disk. Every time you create a file, an entry for it is created in the `$MFT`. Every time you delete a file, the relevant entry for that file in the `$MFT` is deleted. The cabin crew would have a list of all the passengers on an airplace. The `$MFT` has such a list of all files on the hard disk.

**`$MFTMirr`**: This file has a copy of the first four entries in the `$MFT` for recovery purposes.

**`$LogFile`**: This file maintains a log of recent file operations like file/directory creation, deletion, modification and renaming. It was designed to help bring back the system quickly in the event of a failure or crash.

**`$Volume`**: This file has information about the name assigned to the hard disk. By default, your hard disk is assigned single alphabets. If you rename your hard disk to ‘My Secret Vault’, you can find that name in the `$Volume` file.

**`$AttrDef`**: Every file has attributes like file name, data and maybe even shortcuts. `$AttrDef` has a list of all the possible attributes a file can have.

**`$BitMap`**: On an airplane, every passenger is assigned a seat. Some seats may be unassigned and empty. The cabin crew would have a list of assigned and unassigned seats. Likewise, `$BitMap` file has information about regions on the hard disk which are used for storing files and which remain unused.

**`$Boot`**: This file has critical boot code to bring up the operating system.

**`$BadClus`**: This file is similar to the `$BitMap` file, but has information about corrupted regions on the hard disk, that are not suitable to store any data.

**`$Secure`**: For a file, you may include security permissions to specify who can read the file and who can write to it. `$Secure` file has a list of all the security permissions for all the files on the hard disk.

**`$Upcase`**: This file contains mapping between uppercase and lowercase Unicode characters.

**`$Extend`**: This is a directory with some more system files having information about recent changes to the file system, user quotas, etc.

## Why should I know about ‘System Files’ for Digital Forensics?

System files sometimes hold critical evidence for an investigation.

**`$MFT` in action**: Let’s assume you are performing memory forensics on a dump taken from a Windows computer. You are investigating a ransomware attack. You are trying to find out how malware got into the system. If you need an _[introduction to memory forensics](discover-the-truth-with-memory-forensics)_, read this post.

We know that `$MFT` has a list of all files on disk. Every time you create a file, an entry for it is created in the `$MFT` along with the timestamp. In memory, you can find a copy of recently created `$MFT` entries, relevant to recently created files. There are forensic tools that help you carve and interpret `$MFT` entries in memory. You may even find the exact timestamp when malware got into the system!

**`$Boot` in action**: Some malware attack the code used to boot the operating system. Contents of the `$Boot` file may be modified by malware. Accessing and viewing the contents of `$Boot` file may give you clues about malware behaviour.

**`$LogFile` in action**: `$LogFile` has records of recent file operations on the system. Although it was designed for system recovery, it is also useful in forensic investigations to identify files that were created, deleted, renamed or modified recently. There are tools that can parse the `$LogFile`.

**`$Extend/$UsnJrnl` in action**: Within `$Extend` directory, there is a file called `$UsnJrnl` which has some more information about changes to files. It is like a file change journal. Apart from recording creation, deletion, renaming of files and directories, `$UsnJrnl` also records if a file or directory was compressed, encrypted, or even had a shortcut created. Parsing the `$UsnJrnl` file also gives clues about recent activity on a system.

## Where do these ‘System Files’ exist?

These system files exist in the _C:_ drive. But they are hidden from the regular user. They can be seen using forensic tools capable of browsing the entire file system.

Do you want to see them? Here’s is a small project idea for you.

1. Identify a forensic tool that lets you view the entire contents of your hard drive
2. View the contents of the _C:_ drive using the forensic tool
3. Can you spot `$MFT` or `$LogFile`?

Even if a USB drive is formatted with NTFS, it would still have all these system files.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
