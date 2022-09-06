:orphan:
(windows-master-file-table-mft-in-digital-forensics)=

# Windows Master File Table (MFT) in Digital Forensics

In a classroom, a teacher would have details of all the students who have enrolled in a particular course. Details about each student like student ID, name, enrolment date, etc. are stored in an organized way, probably within a table in a word document or a spreadsheet. Likewise, details about every file on your Windows computer are stored in an organized way by the Master File Table. This blog post gives you a brief introduction to the Windows Master File Table and its significance in digital forensics.

## What is the Master File Table?

Most Windows computers use the New Technology File System (NTFS) to handle all files on the hard disk. NTFS uses some files with designated file-handling responsibilities called as _system files_. You can read more about _[NTFS system files](forensic-importance-of-windows-file-management)_.

One of the NTFS System Files is the Master File Table, abbreviated as MFT and also known as `$MFT`. NTFS system files have a `$` symbol before its name. True to its name, the MFT has information tabulated about each and every file on the hard disk. Information about a file is stored in an _MFT entry_. Every file is assigned a unique number, referred to as _MFT number_ or _MFT entry number_. Each MFT entry has the MFT entry number, file name, timestamps relevant to file creation and modification, access control information and the file data itself.

The Master File Table on a Windows computer is a register having information about all the files on a hard disk. Every time you create a file on your computer, an entry is created for it in the MFT. Every time you delete a file, its relevant MFT entry is not deleted, but it is ‘marked’ for deletion. Let’s say you missed class for a day – the teacher simply marks you as absent, you are not removed from the class.

Once an MFT entry is marked for deletion, details about the file which previously used it remain, until that MFT entry is taken up for use by another file.

## Significance of MFT in Digital Forensics

Cyber adversaries perform many operations on a target computer – executing malware, downloading malicious documents, planting secret files, etc. It all boils down to the creation, deletion and modification of files.

To uncover the activities of cyber adversaries, digital forensic investigators attempt to identify files that were recently created or deleted or modified. What other place to look at than the Master File Table?

The MFT is not accessible to a regular user. Specially designed forensic software can extract the MFT from a computer. The following sections provide a brief overview about how the MFT can be helpful in a forensic investigation:

**Forensic Image:** When you acquire the forensic image of a target computer’s hard disk, you will have access to the complete MFT on it. If you are wondering _[what a forensic image is](get-the-evidence-you-need-with-forensic-images)_ you can read the article. Most forensic tools can extract the MFT from a forensic image.

**Memory Dump:** Within the memory dump of a target computer, there is the possibility of finding MFT entries which recently underwent changes. You will find a whole bunch of them. Let’s say an adversary executed malware on your computer, you are not able to find any trace of the binary within the Downloads folder or temporary files folder. One place to look for clues is the _[memory dump](uncover-crucial-information-within-memory-dumps)_

Every time a binary is executed on a computer, a prefetch file is created for it. Whenever a _[prefetch file](windows-prefetch-files-may-be-the-answer-to-your-investigation)_ is created, an entry is created for it in the MFT. Within the memory dump, it is possible to find the MFT entry indicating creation of the prefetch file, along with it’s creation timestamp. Creation time of the prefetch time can be corelated with execution time of the binary! Using a memory dump, it is possible for a forensic investigator to prove that a malicious binary was executed on a computer.

**Shadow Copies:** It is also possible to find a copy of the MFT within volume _[shadow copies](windows-volume-shadow-copies-in-digital-forensics)._

Within the MFT it is also possible to find information about files that had previously existed on a system and have since been deleted.

## What can you do with the acquired MFT?

Regardless of where you acquire the MFT from – a forensic image or a memory dump or a shadow copy, the contents of the MFT are not in human-readable form. Tools must be used to parse the contents of the MFT into data useful for a forensic investigation. Some examples are _Mft2Csv_ and _MFTExplorer_.

These tools can parse the MFT and create a _[timeline](importance-of-timelines-in-a-forensic-investigation)_ of all the entries on it. This means the tools can generate output where all the MFT entries are sorted according to recent modification time. This helps a forensic investigator narrow down the search radius specific to the time window of interest.

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**
