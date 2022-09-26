:orphan:
(powershell-basics-for-security-professionals)=

# PowerShell Basics for Security Professionals

PowerShell is a Microsoft.Net framework-based open source command-line shell and scripting language. PowerShell is a popular tool for automating tasks and configuring systems. IT professionals use PowerShell to carry out their tasks in the same way as Command Prompt in Windows. It also saves time and effort for system administrators by automating daily repetitive tasks that need to be performed on various workstations and servers. PowerShell also provides complete access to the WIN32API (Windows Application Programing interface). The WIN32API is an application programming interface that allows you to access important Windows functions.

PowerShell is an object-oriented programming language that makes it simple to interact with, manipulate, and create new objects to execute various tasks. A PowerShell object is made up of properties (data) and methods (functions) that can be applied to those properties. This flexibility of PowerShell is what makes it a formidable tool. PowerShell was only accessible on Windows operating systems until 2016. However, due to its increasing popularity, PowerShell is now available as PowerShell core, which can be used on both MacOS and Linux operating systems. This article explains why learning PowerShell is vital for security professionals and goes over the basics of the language.

## Why should security professionals learn PowerShell?

Adversaries all around the world are developing covert malware that uses PowerShell to evade detection mechanisms. Attackers can develop persistent and undetected backdoors using strong obfuscation techniques like the Invoke-Obfuscation module written in PowerShell. PowerShell-based malware may be executed directly in memory and is increasingly being utilized in fileless attacks. A fileless malware does not require the attacker to install any files on the victim's computer and leaves no traces on the hard drive.

Because of the rising sophistication of PowerShell-based attacks, security professionals must be armed with a functional understanding of PowerShell as well as the most up-to-date attack strategies. Many enterprise environments use Windows operating systems, thus security experts must apply robust protection tactics to combat these threats. PowerShell knowledge can be incredibly valuable for offensive penetration testers as well as cybersecurity threat hunters in order to effectively defend against PowerShell-based attacks.

## How to launch PowerShell:

To launch PowerShell, open Windows PowerShell from the Start menu or press Win+R and type powershell.exe. This will open PowerShell prompt Window.

You can also use Windows PowerShell ISE, which allows you to run commands as well as write, test, and debug scripts. PowerShell ISE is a Windows-based GUI (Graphical User Interface) application that allows you to work with PowerShell in a flexible and interactive environment. You can launch Windows PowerShell ISE from the Start Menu.

## Configuration for PowerShell scripts:

Before you can run PowerShell scripts, it is important to configure the script execution settings on your workstation since script execution is blocked by default. This execution policy is a safety feature that prevents the execution of malicious scripts and controls the settings under which a script can be run. To check the current policy configuration settings, type **Get-ExecutionPolicy** in the PowerShell prompt Window.

The output of the above command can have different values/settings. Each of these settings is described below:

<u>Restricted</u> This is the most secure and default setting. It allows the users to run commands but doesn't allow the execution of any script.

<u>AllSigned</u>
This setting requires every script(local or remote)
and all the configuration files to be signed by a trusted developer.

<u>RemoteSigned</u>
This setting requires all the remote scripts(i.e. downloaded from the internet)
to be signed by a trusted developer.

<u>Unrestricted</u> This setting allows any script to run and provides the least protection.

To set the value of the execution policy, launch PowerShell as an administrator. Then use the **Set-ExecutionPolicy** command and use the RemoteSigned policy setting as follows:

`Set-ExecutionPolicy RemoteSiged`

PowerShell script files have a .ps1 extension. You can run them by either double clicking on your script file or navigating to the directory containing the script. Then type the name of your script in the PowerShell prompt window to launch it:

`.\<name_of_your_script_file>.ps1`

## Working with PowerShell Cmdlets:

PowerShell cmdlets (pronounced commandlets) are unique commands in PowerShell that can be invoked directly from the command line or embedded in scripts. These instructions can be used to conduct a variety of tasks.

All cmdlets have optional or required parameters. The cmdlet receives the value of these parameters, which it can use to process the output. The format for providing parameter names and values is as follows:

`<cmdlet_name> -<parameter_name> <parameter_value>`

Let us review some of the most commonly used PowerShell cmdlets:

### Get-Command:

The Get-Command cmdlet lists all the commands that have been installed on the computer such as functions, aliases, filters, scripts, and applications.To get a list of the all commands, use it as follows:

`Get-Command`

To get a list of the commands in the current session, use the ListImported parameter as follows:

`Get-Command -ListImported`

To get the syntax of a particular cmdlet, use the following:

`Get-Command -Name <name_of_cmdlet> -Syntax`

Using the -Syntax parameter will enable you to identify the correct usage format for a particular cmdlet and the required parameters that must be supplied for its execution.

### Get-Host:

This cmdlet is used to get the information about the PowerShell console host. You can use this command to extract important information such as the PowerShell version, language settings, and much more. To get the current console host information, use the following command:

`Get-Host `

To only extract the PowerShell version information, use the following command:

`Get-Host | Select-Object -Version`

Here the Select-Object cmdlet is used to select a specific property(i.e. Version) from the output of the Get-Host cmdlet.

### Get-Process:

The Get-Process cmdlet gets the list of all the processes on the local computer. This cmdlet is used to extract the process name, process Id, process owner, CPU usage, Memory Usage, and so on. In order to display the information about all the background running processes, use the following command:

`Get-Process`

To get the information about a particular process using its name, use the Name parameter with this cmdlet:

`Get-Process -Name <name_of_your_process>`

To get CPU utilization for a process in seconds, use the dot operator to reference the CPU property of the object as follows:

`(Get-Process -Name <name_of_your_process>).CPU`

The full path of a process can be used to see if some malicious process is using the same name as that of a trusted process. In order to view the full path of a process, use the following command:

`(Get-Process -Name <name_of_your_process>).Path`

To view the process owner use -IncludeUserName parameter as follows:

`Get-Process -Name <your_process_name> -IncludeUserName`

To get a list of the first 5 processes with the highest CPU usage, use this command:

`Get-Process | Sort-Object CPU -Descending | Select-Object -First 5`

### Get-Service:

This cmdlet shows all the services on the computer. It also shows the status of each service(Running or Stopped) as well their full names and canonical names. To get a list of all the services on the local computer, use the following command:

`Get-Service`

To get a list of the services that are currently running:

`Get-Service | Where-Object {$_.Status -eq "Running"}`

Here the Where-Object cmdlet is used to check each service from the output of Get-Service for the condition where the Status property is "Running". $\_ represents each service object and the -eq operator is used to compare two values for equality.

To display all the properties of any service:

`Get-Service -Name <name_of_your_service> | Select-Object *`

### Get-Content:

The Get-Content cmdlet is used to extract the contents of the file in the given file location. To get the contents of a file in a certain path:

`Get-Content -Path "<Full_path_of_your_file>"`

This cmdlet can also be used for getting hexdumps of the file as follows:

`Get-Content -Path "<Full_path_of_your_file>" -Encoding Byte |Format-Hex`

The Format-Hex cmdlet is used to show the file's contents in hexadecimal values. It can be used to check the content of a suspicious file, for example, by looking at the first four bytes to see if the file's extension matches these bytes.

### Get-WinEvent:

The Get-WinEvent cmdlet is used to extract events from event logs, including classic logs, such as Application and system logs. The events are displayed in the order of newest to oldest. In order to filter certain events from a very large list of events, we use the parameter FilterHashTable with this cmdlet. For example, if we want to filter the security event id 4672 "Special Privileges assigned to new logon", we can do this as follows:

`Get-WinEvent -FilterHashTable @{logname="Security";id=4672} |Format-List`

Here the Format-List cmdlet is used to display the events in the form of a list.

To get a list of system events with id=7045 "A service was installed in the system" with a starting and ending time , use the following query:

` Get-WinEvent -FilterHashTable @{logname="System";id=7045;starttime="5/29/2022 8:00:00 AM";endtime="5/29/2022 8:10:00 AM"} |Format-List`

### Get-WMIObject:

The Get-WMIObject cmdlet is used to discover information about the computer(local or remote) and its components. It can also be used to perform different actions on the computer. This cmdlet leverages WMI(Windows Management Information) to gather information and carry out different tasks. WMI is a subsystem of PowerShell and provides admin access to system monitoring tools. It is pre-installed on Windows Operating systems and consists of different sets of classes. To get the list of all services on the computer, you can use this command:

`Get-WMIObject -Class Win32_Services `

To get a list of products having a name matching Microsoft Office, use the following command:

`Get-WMIObject -Class Win32_Product | Where Name -LIKE "Microsoft Office*"\| Select-Object *`

Here the -like operator is used to match any product having the string Microsoft Office in their name. Select-Object \* is used to display all the properties of the matched products.

To get a list of all the user accounts on the machine, use the following:

`Get-WMIObject -Class Win32_useraccount`

To get the Command line Arguments for all the processes, use the following command:

`Get-WmiObject -Class Win32_Process|Select-Object CommandLine`

Here the CommandLine property of the object is extracted to get the command line of all the processes. We can use the process command line to check how the process was intended to be used or discover malicious payloads.

To get the antivirus definitions and status, use the following command:

`Get-WmiObject -Namespace root\securitycenter2 -Class AntiVirusProduct`

### Get-ChildItem:

The Get-ChildItem cmdlet gets the items and the child items in one or more locations specified in the command. This cmdlet can get a list of directories, subdirectories, and files in a given location. In order to get a list of files and directories in a specific location, use the Path parameter as follows:

`Get-ChildItem -Path <your_path>`

In order to list all the files, directories, and subdirectories in a given folder, use both -Recurse and -Force parameters as follows:

`Get-ChildItem -Path <your_path> -Recurse -Force`

Here the Force parameter ensures that the cmdlet also iterates through those items that are otherwise not accessible by the user, such as hidden or system files.

To get only the files in a given location recursively, use the File parameter as follows:

`Get-ChildItem -Path <your_path> -File -Recurse -Force `

To get a list of all the files recursively that match a given extension (e.g. .exe files), you can use two methods:

`Get-ChildItem -Path <your_path> -Recurse -Force | Where-Object {$_.Name -LIKE "*.exe"}`

or

`Get-childitem -Path <your_path> -Filter "*.exe" -Recurse -Force`

The second command uses the Filter parameter to search recursively for each file that has a .exe extension.

### Get-ItemProperty and Set-ItemProperty:

The Get-ItemProperty is used to get the properties of the specified item whereas the Set-ItemProperty is used to create/change the values of properties for the specified item. These cmdlets are particularly useful for extracting or setting the registry entries. You can specify the registry key to retrieve the registry entries. An example of the registry path can be HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion. Here HKLM stands for HKEY_LOCAL_MACHINE hive of the registry.

In order to get all the registry entries in a given path or registry key use the following command:

`Get-ItemProperty -Path <your_registry_key_path>`

In order to get a single entry in the registry key, then you use the -Name parameter to specify the name of the particular entry to get its data:

`Get-ItemProperty -Path <your_registry_key_path> -Name <name_of_entry>`

In order to create/change an entry in the registry key, you can use the -Name and -Value parameters with Set-ItemProperty cmdlet as follows:

`Set-ItemProperty -Path <your_registry_key_path> -Name <name_of_entry> -Value <value_of_entry>`

Additionally you can use the type parameter to create a specific type of entry. The types are REG_SZ(string), REG_EXPAND_SZ(ExpandString), REG_BINARY(Binary), REG_DWORD(32-bit binary), REG_QWORD(64-bit binary) and REG_MULTI_SZ (MultiString). To create a resgistry entry with a specific type, use the following command:

`Set-ItemProperty -Path <your_registry_key_path> -Name <name_of_entry> -Value <value_of_entry> -Type <type_of_entry>`

### Get-HotFix:

The Get-Hotfix cmdlet is used to get the list of all the security patches and system upates installed on the local computer. This cmdlet is used to extract the id, name, description, installation date/time, and the account which was used to install the update. In order to get all the updates installed on the computer, use the following command:

`Get-Hotfix`

In order to get all the details about a particular update, you can use its id value with the Id parameter as follows:

`Get-HotFix -Id <the_id_value> |Select-Object *`

To get all the updates containing the string "Security" in its description, use the following two ways:

`Get-HotFix -Description "Security*"`

or

`Get-HotFix |Where-Object {$_.Description -like "Security*"}`

### Get-Acl and Set-Acl:

The Get-Acl cmdlet is used to extract the ACL(access control list) for a particular resource on the computer. ACL is associated with each object and describes the permissions of users on the object. The Set-Acl cmdlet is used to change/set the access persmissions for the folder or a file object.

To the ACL of a folder/file on the system, use the following command:

`Get-Acl <your_folder/file_path>`

To get the details of the access permissions, use the following command:

`(Get-Acl <your_folder/file_path>).Access`

Here the . operator is used to reference the Access property of the output object.

In order to set the access permissions on a file/folder for a particular user/group, you first need to define access rights as follows:

`$acl_rules=New-Object Security.AccessControl.FileSystemAccessRule('<Identity>','<FileSystemRights>','<AccessControlType>')'`

This command creates a new FileSystemAccessRule object using the New-Object cmdlet. Here Identity is the user account, FileSystemRights defines the access rights such as FullControl, Read, Modify, Delete, Write, etc. and AccessControlType can be set to allow or deny. After the creation of this object, its value is stored in the $acl_rules variable.

Then we get the current acl of the required object (file/folder) and store it in the $acl_obj variable as follows:

`$acl_obj = Get-Acl <your_file/folder_path>`

Now we set the access rules using SetAccessRule function of the $acl_obj by using the $acl_rules variable we created earlier as follows:

`$acl_obj.SetAccessRule($acl_rules)`

Finally we apply the access rules on folder/file of our interest as follows:

`Set-Acl -Path <your_file/folder_path> -AclObject $acl_obj`

## Command Execution on Remote Computers:

PowerShell cmdlets can be executed on your local computer or on the remote computers using PowerShell remoting. But before you can execute these commands, you will have to set up PowerShell Remoting as described below:

### How to Setup PowerShell Remoting:

1. Launch Windows PowerShell as an administrator, then type this command in the prompt Window as follows:

`Enable-PSRemoting -Force`

This command starts the WinRM(Windows Remote Management) Service. The Force parameter is used to set up this service without prompting the user for each step.

2. Next you need to configure the TrustedHosts setting on your computer so that both the local and remote computers can trust each other. Use the following command to configure TrustedHosts:

`Set-Item wsman:\localhost\client\trustedhosts *`

The \* is used to accept connections from all PCs. To restrict the TrustedHosts to a few remote computers, you can use a comma-separated list of their IP addresses.

3. Afterwards, restart the WinRM service for the settings to take effect as follows:

`Restart-Service WinRM`

4. Lastly test the connection with the target remote computer using its IP address as follows:

`Test-WsMan <IP_address_of_Remote_Computer>`

### Using Invoke-Command to execute commands:

The Invoke-Command cmdlet is used to execute commands on the local or remote computer. To execute a single command on the remote computer, use the following syntax:

`Invoke-Command -ComputerName <IP_address_of_remote_computer> -Credential Get-Credential -ScriptBlock {<your_command>}`

The Get-Credential cmdlet prompts the user to enter the credentials(username/password) for the user on the remote computer. These credentials are then passed to the Credential parameter. The ScriptBlock parameter accepts the command that is to be executed on the remote computer. Finally, the output of the command is displayed on the local computer.

## Conclusion:

PowerShell is a very powerful scripting language. This article has just scraped the surface of PowerShell's capabilities. In the future articles, we will go over PowerShell cmdlets for Active Directory management and script generation in greater depth, so stay tuned.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
