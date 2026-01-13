:orphan:
(psexec)=

# Using PsExec to login remotely to another machine on the network

## Required: 

1. Two virtual machines on the same subnet, Machine-A and Machine-B.
2. Admin privileges on Machine-A is required.

## Preliminary Steps:

Perform the following two steps on both the machines:

1. In the following registry path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ` create a DWORD titled `LocalAccountTokenFilterPolicy` and set the value to 1.
<br>

1. Allow SMB traffic. This can be done by allowing traffic using the Firewall rules *File and Printer Sharing (SMB-In)*

## Steps:

1. Download PsExec from the official website.
<br>

2. On Machine-A, use *cmd.exe* with admin privileges
<br>

3. Assuming the IP address of Machine-B is 10.0.2.7, use the following command to create an interactive shell prompt with Machine-B: `psexec \\10.0.2.7 -u localAdminName -i cmd`

Provide the user name of Machine-B's local administrator account to perform the login. You will be prompted for the password.
