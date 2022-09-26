:orphan:
(common-methods-an-adversary-may-adopt-to-cover-their-tracks)=

# Common methods an adversary may adopt to cover their tracks

It is essential for attackers to understand how to hide their tracks. This is because they don't want to leave any evidence that can be used to track them down. This might be a difficult process because we often have protocols in place to detect and log events. For an attacker who wants to stay anonymous, erasing evidence is necessary. It begins with removing the corrupting logs and any error messages generated during the attack procedure.

The attacker tricks the system administrator into believing that there is no malicious activity in the system and that no intrusion or compromise has occurred by manipulating and modifying event logs. Because the first thing a system administrator does when investigating abnormal activity examines the system log files, intruders commonly use a tool to manipulate these logs.

Attackers must make the system appear as it did prior to gaining access and installing a backdoor.

## Ways to clear online tracks:

Attackers can clear web history, logs, cookies, error messages, downloads, and caches on the victim's machine so that the victims cannot notice the online activities performed on their machine.

- Use private browsing or the Tor network.
- Delete the saved passwords in the browser settings
- Delete the stored history on the browser
- Delete saved sessions and private data
- Clear cache and cookies on exit
- Disable password manager and clear Password manager.

To clear the online tracks of various activities, attackers can follow different methods to clear online tracks with different browsers.

## Clearing Bash shell tracks/Unix

BASH is a UNIX shell and command language designed by Brian Fox for the GNU Project as a free software replacement for the Bourne shell. Bash, or Bourne Again Shell, is a sh-compatible shell that stores command history in a file called the bash history. You can view the saved command history using the more `~/.bash_history` command.

An investigator could check the bash history to track the origin of the attack and the commands used by the attacker to compromise the system.

_Attackers can use the following commands to clear their bash shell tracks:_

1. Disabling history

`export HISTSIZE=0 `

This command disables the Bash shell's ability to save history. The number of commands to be saved is determined by HISTSIZE, which is set to 0. Attackers lose the ability to review previously used commands after performing this command.

2. Clear the history

`history -c`

This command is used to clear the stored history and It is an effective alternative to disabling the history command

`cat /dev/null > ~.bash_history && history –c && exit`

This command clears the current and all previous shells' command histories and terminates the shell.

3. Shredding the history

`shred ~/.bash_history`

This command shreds the history file and makes its contents unrecognizable.

`shred ~/.bash_history&& cat /dev/null > .bash_history && history -c && exit`

This command shreds the history file first, then deletes it, and ultimately removes any traces of its usage.

In UNIX, files can be hidden simply by inserting a `dot (.)` before the file name. However, while using this file-hiding strategy, an attacker may leave a trail because the command used to open a file is logged in a .bash history file. A clever attacker understands how to get around this problem by using the export `HISTSIZE=0` command.

## Covering tracks on windows OS

In windows Operating system, NTFS has as feature called as ADS (alternative data stream) which can be used to hide a file behind a normal file.

**Deleting files using cipher.exe**

`Cipher.exe` is a built-in Windows command-line tool that may be used to securely destroy data by overwriting it in order to prevent future recovery. This command can also help you encrypt and decrypt data in NTFS volumes.

The attacker can delete files using `Cipher.exe` by implementing the following steps:

- Start the command prompt as an administrator.

- To overwrite deleted files in a specified folder, use the following command:

  `cipher /w:<drive letter>:\<folder name>`

- To overwrite all deleted files on the specified drive, run the following command:

  `cipher /w:<drive letter>`

## Final words :

Defending against attackers can be difficult when they try to cover their tracks by modifying the information. However, some precautions can be taken to protect the systems, such as regularly updating and patching operating systems, applications, and firmware, enabling logging functionality on all critical systems and encrypting log files stored on the system so that altering them is impossible without an appropriate decryption key.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
