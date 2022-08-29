:orphan:
(windows-file-system-journal-in-digital-forensics)=
# Windows File System Journal in Digital Forensics
 

Windows operating system stores a lot of information about the activities performed by a user. Ranging from which binaries were executed, to how applications were used, to even storing information about which files/directories were created or deleted or modified recently. This blog post discusses about one log source called the $UsnJrnl file, which records information about every operation performed on files and directories.

## Introducing $UsnJrnl

Most Windows systems use New Technology File System (NTFS) to efficiently handle the large number of files on the hard disk. NTFS has some special files called *System Files* that are responsible to perform this file management. You can read more about *[NTFS System Files](forensic-importance-of-windows-file-management)*.

One of the NTFS system files is a file called $UsnJrnl that is stored within $Extend directory. $UsnJrnl is referred as the file system change journal. It is a file that holds information about every change that occurs to files and directories on disk. Some of them are:

- file/folder creation
- file/folder deletion
- file/folder renaming
- file/folder modification by compression or encryption
- shortcut created for file/folder
- access control data for file/folder was changed
- data added or removed from file/folder

## How to use $UsnJrnl for digital forensics?

Cyber adversaries are getting smarter by the day. They are aware of footprints they leave behind and now take steps to wipe away those footprints. This wiping away of footprints is formally referred to as *anti-forensic technique* - steps taken to hinder the digital forensic process. On a Windows computer, it could be deleting the binary for a recently executed malware, hiding a file they intend to use again later, or even deleting prefetch files. You can read *[more about prefetch files](windows-prefetch-files-may-be-the-answer-to-your-investigation)*.

It is possible to find evidence of anti-forensic steps performed from the $UsnJrnl file. If an adversary had deleted a prefetch file, within the $UsnJrnl file you can find evidence about this deletion.

## Realising the usefulness of $UsnJrnl

Here is a quick walk through of how $UsnJrnl can provide clues about recent file/folder activity.

Within *Pictures* folder, a new folder called *mysecrets* was created. Within the new folder, a new text document was created and renamed as *pet-cat-names.txt*. An image file has also been placed in this folder. Let’s see if we can find any information about this activity from the $UsnJrnl.

![$UsnJrnl](images/usn-1.png)

On your Windows computer, it is not possible for a regular user to view the $Extend folder and its contents. $UsnJrnl can be extracted using tools like *UsnExtractor* or *ExtractUsnJrnl*. Most of the commercial forensic tools can also perform this task for you.

Upon extraction, you will have access to the contents of $UsnJrnl file as shown below. The tool used for this demo has extracted the change journal to *usn.bin*.

![usn.bin](images/usn-2.png)

The contents of *usn.bin* will not be human-readable. To interpret this, $UsnJrnl parsing tools like *UsnJrnl2Csv* or *USN-Record-Carver* can be used. When the resulting output was parsed, there were a sequence of log entries to indicate that a folder called *New Folder* was renamed to *mysecrets* on 6th May at 12:14 hours.

![$UsnJrnl](images/usn-3.png)

There were some more entries indicating that *New Text Document.txt* was renamed to *pet-cat-names.txt* on 6th May at 12:15 hours. 

![$UsnJrnl](images/usn-4.png)

Likewise, there will also be log entries to indicate the copying of *cats.jpeg* into *mysecrets* folder. 

You may have noticed that within the output of $UsnJrnl file, we can see only the file names. How is it possible to know the exact location of that file in a hard disk? In the screenshots shown above, there are some more fields of information to the right of the timestamp. Co-relating those fields with other pieces of evidence will help you identify the complete path of a suspicious file on disk. 

## Project Idea

Do you want to try acquiring evidence from $UsnJrnl?

1. Create a folder, add some files to it. Rename some files. Delete some files. 
2. Acquire the contents of $UsnJrnl
3. Parse the contents of $UsnJrnl
4. Look for log entries relevant to the activities you performed

Once you identify a sequence of interesting operations from $UsnJrnl, you can proceed to create a timeline of activity that had occurred on the system. You can read more about timelines *[read more about timelines](importance-of-timelines-in-a-forensic-investigation)*

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**