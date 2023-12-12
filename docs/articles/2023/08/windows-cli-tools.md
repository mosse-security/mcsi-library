:orphan:
(windows-cli-tools)=

# Microsoft Command-Line Tools

Microsoft's Command-Line Tools provide users with a powerful and efficient way to navigate the file system, manage system information, and perform a wide range of tasks within the operating system environment. These tools are particularly valuable for users who prefer text-based interactions and want to perform tasks swiftly and effectively. In this article, we will explore an array of essential Microsoft Command-Line Tools, including navigation, system information retrieval, and various administrative tasks. We will provide examples of their usage along with the corresponding outputs.

## `cd`

The `cd` command, short for "change directory," enables users to navigate the file system within the command-line interface. This command is crucial for switching between different directories. The syntax for using the `cd` command is:

cd [directory_path]

Here, `[directory_path]` represents the path of the directory you want to navigate to.

**Example Usage and Output:**

Assuming you are in the `C:\Users` directory and want to navigate to the `Documents` directory within it, you would use the following command:

C:\Users>cd Documents

C:\Users\Documents>

After executing the command, you will be within the `C:\Users\Documents` directory.


## `dir`

The `dir` command is employed to display the contents of a directory. It provides a list of files and subdirectories within the specified directory. The basic syntax for using the `dir` command is:

dir [directory_path]

If no `[directory_path]` is provided, the `dir` command will list the contents of the current directory.

**Example Usage and Output:**

If you are in the `C:\Users\alice` directory and wish to list its contents, execute the following command:

C:\Users\alice>dir
 Volume in drive C is OS
 Volume Serial Number is ABCD-EFGH

 Directory of C:\Users\alice

08/31/2023  10:00 AM    <DIR>          .
08/31/2023  10:00 AM    <DIR>          ..
08/31/2023  09:45 AM               512 file1.txt
08/31/2023  09:46 AM               789 file2.txt
08/31/2023  09:50 AM    <DIR>          Documents
08/31/2023  09:51 AM    <DIR>          Pictures
               2 File(s)          1,301 bytes
               4 Dir(s)  100,123,456,789 bytes free

The command will produce an output displaying the files and subdirectories within the `C:\Users\alice` directory.

## `mkdir`

The `mkdir` command allows users to create new directories within the file system. This command is essential for organizing files and maintaining a structured hierarchy of directories. The syntax for using the `mkdir` command is:

mkdir [directory_name]

Here, `[directory_name]` is the desired name of the directory to be created.

**Example Usage and Output:**

Suppose you are in the `C:\Users\alice` directory and intend to create a new directory called `NewDirectory`. Execute the following command:

mkdir NewDirectory

The `NewDirectory` will be created within the `C:\Users\alice` directory.

## `copy`

The `copy` command is employed to duplicate files from one location to another. This command is useful for creating backups or transferring files between directories. The syntax for using the `copy` command is:

copy [source_file] [destination_path]

In this syntax, `[source_file]` is the file to be copied, and `[destination_path]` is the location where the copied file will reside.

**Example Usage and Output:**

Let's assume you have a file named `report.docx` in the `C:\Users\alice` directory, and you want to make a copy of it in the `C:\Users\bob` directory. Execute the following command:

C:\Users\alice>copy report.docx C:\Users\bob
        1 file(s) copied.

The `report.docx` file will be duplicated in the `C:\Users\bob` directory.

## `move`

The `move` command enables users to move files from one location to another or rename files. When moving a file, it is removed from the source location and placed in the destination location. The syntax for using the `move` command is:

move [source_file] [destination_path]

Here, `[source_file]` is the file to be moved or renamed, and `[destination_path]` is the location where the file will be moved or the new name for the file.

**Example Usage and Output:**

Suppose you have a file named `data.csv` in the `C:\Users\alice` directory, and you want to move it to the `C:\Users\bob` directory. Execute the following command:

C:\Users\alice>move data.csv C:\Users\bob
        1 file(s) moved.

The `data.csv` file will be moved to the `C:\Users\bob` directory.

## `del` and `rmdir`

The `del` command is used to delete files from the file system, while the `rmdir` command is used to remove empty directories. It's important to note that these commands permanently delete files and directories, and the action cannot be undone. The syntax for using the `del` and `rmdir` commands is:

del [file_path]
rmdir [directory_path]

In this syntax, `[file_path]` is the path to the file to be deleted, and `[directory_path]` is the

 path to the empty directory to be removed.

**Example Usage and Output:**

Suppose you have a file named `obsolete.txt` in the `C:\Users\alice` directory that you want to delete. Execute the following command:

C:\Users\alice>del obsolete.txt

The `obsolete.txt` file will be permanently deleted.

If you have an empty directory named `OldFolder` in the `C:\Users\alice` directory that you want to remove, execute the following command:

C:\Users\alice>rmdir OldFolder
The directory is not empty.

C:\Users\alice>rmdir OldFolder /s /q

The `OldFolder` directory will be removed.

## `systeminfo`

The `systeminfo` command is used to retrieve detailed information about the computer's hardware and software configuration. It provides a comprehensive overview of the system's specifications, including the operating system version, installed updates, processor details, memory information, and more.

**Example Usage and Output:**

Execute the following command to retrieve system information:

C:\Users>systeminfo

Host Name:                 DESKTOP-ABC123
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19043 N/A Build 19043
...

The command will generate an extensive output containing details about the computer's configuration, software updates, and more.

## `fc`

The `fc` command is employed to compare the contents of two text files. This command is particularly useful when you need to identify differences between two versions of a file. The syntax for using the `fc` command is:

fc [file1] [file2]

In this syntax, `[file1]` and `[file2]` are the paths to the files you want to compare.

**Example Usage and Output:**

Assume you have two text files, `old.txt` and `new.txt`, in the `C:\Users\alice` directory. To compare the contents of these files, execute the following command:

C:\Users\alice>fc old.txt new.txt
Comparing files old.txt and NEW.TXT
***** old.txt
this is the content of the old file.
***** NEW.TXT
this is the content of the new file.

The command will display the differences between the contents of the two files.

## `ipconfig`

The `ipconfig` command is used to retrieve information about the network configuration of the computer. It provides details about the IP addresses, subnet masks, default gateways, and more for all network interfaces.

**Example Usage and Output:**

Execute the following command to retrieve network configuration information:

C:\Users>ipconfig

Windows IP Configuration

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . : example.com
   IPv4 Address. . . . . . . . . . . : 192.168.1.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
...

The command will display information about the network interfaces and their associated configuration.

## `netstat`

The `netstat` command provides information about network connections, routing tables, interface statistics, masquerade connections, and more. It is particularly useful for diagnosing network-related issues and monitoring network activity.

**Example Usage and Output:**

To view active network connections, execute the following command:

C:\Users>netstat -a

Active Connections

Proto  Local Address          Foreign Address        State
TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
...

The command will display a list of active network connections along with their status.

## `ping`

The `ping` command is used to test network connectivity between your computer and a target host. It sends ICMP echo request packets to the target and measures the response time.

**Example Usage and Output:**

To test connectivity to a website (e.g., www.google.com), execute the following command:

C:\Users>ping www.google.com

Pinging www.google.com [172.217.11.164] with 32 bytes of data:
Reply from 172.217.11.164: bytes=32 time=10ms TTL=119
...

The command will display information about the ping requests and responses.

## `sfc`

The `sfc` (System File Checker) command is used to scan and repair corrupted or missing system files. It is a useful tool for maintaining the integrity of the Windows operating system.

**Example Usage and Output:**

Execute the following command to run the System File Checker:

C:\Users>sfc /scannow

Beginning system scan. This process will take some time.

Beginning verification phase of system scan.
Verification 100% complete.
Windows Resource Protection did not find any integrity violations.

The command will initiate a scan of system files and repair any detected issues.

## `attrib`

The `attrib` command is employed to view and modify file attributes such as read-only, hidden, archive, and system attributes.

**Example Usage and Output:**

To remove the "read-only" attribute from a file named `file.txt`, execute the following command:

C:\Users\alice>attrib -r file.txt

The command will modify the file's attributes accordingly.

## `tree`

The `tree` command is used to display the directory structure of a specified path in a tree-like format. It provides a visual representation of folders and subfolders.

**Example Usage and Output:**

Execute the following command to display the directory structure of the `C:\Users\alice` directory:

C:\Users>tree C:\Users\alice
Folder PATH listing
Volume serial number is ABCD-EFGH
C:\USERS\ALICE
├───Documents
│       doc1.txt
│       doc2.txt
└───Pictures
        pic1.jpg
        pic2.jpg

The command will generate a hierarchical display of the directory structure.

## `ver`

The `ver` command is used to display the version number of the Windows operating system currently running.

**Example Usage and Output:**

Execute the following command to view the operating system version:

C:\Users>ver

Microsoft Windows [Version 10.0.19043.1237]

The command will display the version number of the Windows operating system.

## `tasklist`

The `tasklist` command is used to list all currently running processes on the computer. It provides information about process names, process IDs (PIDs), memory usage, and more.

**Example Usage and Output:**

Execute the following command to list running processes:

C:\Users>tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0         24 K
System                           4 Services                   0        528 K
smss.exe                       320 Services                   0      1,160 K
...

The command will display a list of active processes along with relevant details.

## `taskkill`

The `taskkill` command is used to terminate or end a running process based on its process ID or image name.

**Example Usage and Output:**

To terminate a process named `notepad.exe`, execute the following command:

C:\Users>taskkill /im notepad.exe /f
SUCCESS: The process "notepad.exe" with PID 1234 has been terminated.

The command will forcibly terminate the specified process.

## `cls`

The `cls` command is used to clear the contents of the command prompt window, providing a clean slate for new commands and output.

**Example Usage and Output:**

Execute the following command to clear the command prompt window:

C:\Users>cls

The command prompt window's contents will be cleared.

## `assoc`

The `assoc` command is used to display or modify file associations. File associations determine which program is used to open a specific file type.

**Example Usage and Output:**

To display the file association for `.txt` files, execute the following command:

C:\Users>assoc .txt
.txt=txtfile

The command will display the associated program for opening `.txt` files.

# Final Words

Microsoft Command-Line Tools encompass a diverse array of utilities that empower users to efficiently navigate the file system, manage system information, and execute various tasks. These tools are indispensable for users who prefer text-based interactions and seek to streamline their workflow. Whether you are navigating directories, managing files, retrieving system information, or performing administrative tasks, these command-line tools offer a robust and flexible means to interact with your operating system. By understanding and utilizing these tools, users can enhance their efficiency, troubleshooting capabilities, and overall control over their computing environment.