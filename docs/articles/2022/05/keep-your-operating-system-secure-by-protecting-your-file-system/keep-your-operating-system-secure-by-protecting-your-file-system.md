:orphan:
(keep-your-operating-system-secure-by-protecting-your-file-system)=

# Keep your Operating System Secure by Protecting your File System

The file system is one of the most essential parts of your operating system that you must safeguard. To secure our file systems, first, we need to understand their structure and nature. In this blog post, we are going to do a very quick primer on the introduction to file systems.

## The File System

The file system is a cluster of applications that organizes and saves information, and files, on storing mediums. Each directory and file can have its own set of permissions that regulate which users can read and edit the file system.

**Windows**

- Each file system in Windows has a drive letter of its own.
- Each disk on Microsoft Windows has its directory, beginning with its root (such as C, D).

On Windows, the "Address" column includes the directory name after the backslash "\" character.

**Linux**

- UNIX file systems each have their directories which are used as a root (also referred to as “mount points”).
- The system drive is the root in Unix-based systems.
  In the hierarchy, all other drives' folders appear beneath it.

**OS X**

Volumes is a subfolder in OS X that links to the directories for individual drives. We go one level down in the directory structure if we click on a folder within another folder.

### Tree structure

The file system uses a tree structure of directories and/or folders to make it easier to discover files. To arrange files, both UNIX and Windows file systems employ tree-like designs.

### Root directory

The root directory is the point of entry into the tree. A computer may contain many drives, each of which can be partitioned into various portions known as partitions. Each disk partition typically has its file system and root directory. "\" character represents the root directory by itself.

### Directories

File systems, are typically divided into two types:
Windows-based and Unix-based systems.
Although OS X has a unique file system, it has the characteristics of Unix.

Files on our hard drive have their distinctive markup. They contain:

- name
- list of related directories that link to it.

Directory names are divided by a backslash. Listed in alphabetical order.

| System    | Character |
| --------- | --------- |
| Windows   | \         |
| Unix-like | /         |
| Mac       | /         |

## File access rights

We have four basic access rights to resources. The acronym CRUD is made up of the names of these four rights:

- create,
- update (write, modify),
- read,
- delete

When you initiate a process, all the resources you create will inherit the privileges of your current account status.

## File protection

When you create a new file or directory, the system automatically applies the appropriate permissions.
Systems typically use one of two mechanisms:

1. Default rights: The system applies a standard set of permissions to all files created by a certain user.
2. Inherited rights: the system uses permissions inherited from one or more parent directories.

Here is a full list of different access privileges to a directory that a system might grant such as create new files, delete, create, seek, read and delete files.

## Conclusion

Securing our operating system starts with protecting our resources. Understanding the basics of file systems and their functions helps us to apply best practices in protection.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
