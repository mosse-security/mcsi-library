:orphan:
(pstools)=
# The sysinternal command line tools

Mark Russinovich created the PS Tools Kit, a collection of 13 tools. These utilities are command-line tools that allow you to launch processes on remote computers and redirect console application output to the local system, making it appear that the applications are running locally. All of these tools are compatible with Windows NT and later versions. Because they are console applications, these tools can be used on both a local computer and a remote host. 

The "Ps" prefix in PsList refers to the fact that the basic UNIX process listing command-line tool is called "ps,"  the prefix for all the tools to tie them together into a suite called PsTools.

[Link to PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)

## Psexec 

PsExec is a light-weight telnet replacement that is used to execute processes on other machines while providing full interactivity for console applications and the need to install client software. The most common use case of the PsExec is to launch interactive command prompts on remote machines and remote enabling tools such as ipconfig that otherwise cannot show information about remote systems. 

`psexec \\computer[,computer[,..] [options] command [arguments]` 

## Psfile

Psfile is a command-line utility that shows a list of files that are opened remotely and the psfile can close the files either with help of a name or by a file identifier. Typing a command followed by "- " displays information on the syntax for the command. 

`psfile [\\RemoteComputer [-u Username [-p Password]]] [[Id | path] [-c]]`

**-u** specifies the username for login to the remote machine.

**-p** flag is used to specify the password for the username.

**Id** specifies the identifier of the file for which the information to display

**Path** specifies the path of files to match for information display or to close.

**-c**  This flag specifies closing the files identifies by ID or path.


## PsGetSid 

PsGetSid displays the SIDs of user accounts and translates a SID into the name that represents it. A security identifier (SID) is used to uniquely identify a security principal or security group. Following is the syntax of the PsGetSid command. 
``psgetsid [\\computer[,computer[,...] | @file] [-u username [-p password]]] [account|SID]``

## Pslist 

Pslist is a command-line utility that is used to display the CPU and memory information or thread statistics. 

## PsPasswd 

This command-line tool is used to change the account password on local or remote systems, and administrators can create scripts that run the PsPasswd on a network of computers they control to perform a mass change of the administrator password. PsPasswd does not send the passwords in cleartext over the network as it uses windows password reset APIs.

`pspasswd [[\\computer[,computer[,..] | @file [-u user [-p psswd]]] Username [NewPassword]`

## PsKill 

This command line utility is used to kill processes on remote systems and kill process on the local machine. Pskill can be used with the process ID to kill the process of that ID on the local computer. PsKill will terminate all the process with the name specified to it. Attackers don’t need to install client on the target machine to terminate a remote process.

``pskill [-] [-t] [\\computer [-u username] [-p password]] <process name | process id>``

## PsShutdown 

This command line utility is used to shutdown or reboot a remote or local machine. The syntax of the PsShutdown are given below

`psshutdown [[\\computer[,computer[,..] | @file [-u user [-p psswd]]] -s|-r|-h|-d|-k|-a|-l|-o [-f] [-c] [-t nn|h:m] [-n s] [-v nn] [-e [u|p]:xx:yy] [-m "message"]`

## Conclusion

Pstools suite has total of 13 command line utilities which can be used by the attackers for malicious purposes. Attackers can use Pstools for enumerating user accounts and managing remote systems from the command line. 

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html)
:::