:orphan:
(an-introduction-to-active-directory-and-how-powershell-can-be-used-as-a-security-auditor)=
# An Introduction to Active Directory and how PowerShell can be used as a Security Auditor
 

The network operating system (NOS) is a software-based networked environment that allows many workstations and computing devices to share resources. In 1990, Microsoft released Windows NT 3.0 that featured a NOS environment. Many aspects of the LAN Manager protocols and the OS/2 operating system were merged in this product. Over the next few years, the Windows NT NOS slowly evolved into Active Directory that was first formally deployed in Windows Server 2000. 

With each subsequent iteration of the Windows Server Operating System, Microsoft continued to build new Active Directory features, and it is now used by a range of other Microsoft solutions, such as Exchange Server and SharePoint Server, as well as third-party apps and services. This article discusses the fundamentals of Active Directory and how PowerShell can be used for its administration.

## What is Active Directory?
Microsoft's Active Directory is a directory service that runs on Windows Domain Networks. A directory is a hierarchical structure that stores information about a network's resources and users. A directory service is used to allow users/applications to access network resources depending on their identity. Administrators can utilize Active Directory to create new users, manage permissions for users and applications, and prevent unwanted access to resources. Users are allowed to access network resources only after successful authentication.

Active Directory maintains a hierarchical structure in the form of domains, trees, and forests that saves information about network resources and user accounts such as names, passwords, and phone numbers, among other things. A forest is the highest level of the Active Directory hierarchy, and it consists of a collection of domains known as trees. In Active Directory, a domain is a logical grouping of many objects (users, groups, computers, policy objects, access control lists, and so on).

## Active Directory Domain Service:
Active Directory Domain Service (AD DS) is the principal directory service that runs on Windows Server operating systems. Domain Controllers (DC) are the machines that host Active Directory Domain Services (AD DS). Multiple DCs can exist in an organization, and each DC has a copy of the AD DS. Domain Controllers are made up of numerous domains in the form of Organizational Units (OU). AD DS is a framework for managing trust between domains and granting users access to the resources located in a certain domain.

## Benefits of Active Directory:
The following are some of the advantages of utilizing Active Directory to manage your network environment:

* Active Directory provides companies with a centralized management platform that allows administrators to manage user access permissions and limit access to network resources.
* Active Directory provides seamless access to different network resources by employing SSO (Single Sign On) services. The user is authenticated once by the Active Directory before being granted access to different resources according to his predefined privilege settings.
* Active Directory allows the organizations to organize and manage their resources according to their unique business requirements.
* Active Directory makes it easier for users to locate different resources in the company network by simply searching the active directory database for the desired resource.

## Why is the security of Active Directory so important?
One of the primary reasons why it is critical to safeguard the Active Directory is that it is where your organization's credentials are stored. These credentials are like crown jewels that must be protected from various threats since they are the key to gaining access to and compromising the security of your valuable assets. An attacker requires valid account credentials to implant malware on a system and use it to either escalate privileges or move laterally across the network in order to carry out a successful attack.

An attack on Active Directory might also damage or impair the organization's critical business functions. The organization may suffer significant operational downtime losses if these operations are disrupted.

Unauthorized disclosure of sensitive/private data can result in huge financial losses, such as legal/regulatory fines, as well as reputational losses for the organization.

In short, the absence of appropriate security controls safeguarding the Active Directory can lead to the following consequences:
* Attacker can plant a  backdoor in your network to carry out malicious activities and evade detection mechanisms.
* Attacker can compromise user accounts and use them to escalate privileges on a system or compromise the security of additional user accounts.
* Attackers can steal sensitive/important company data through data exfiltration techniques or they can modify/corrupt your valuable assets.

As a result, it is critical for security professionals to secure the Active Directory against various attack vectors. The key to safeguarding Active Directory is to gain its functional knowledge and a grasp of its management techniques in order to detect and prevent different security flaws.

## Role of PowerShell in Active Directory Management:
As a part of his job duties, a system administrator is responsible for carrying out different tasks on multiple computers. It is not unlikely for a system administrator to perform some of these tasks that involve hundreds of different workstations or servers. Therefore it is of utmost importance for the system administrator to use some kind of automation tool that makes it easier for him to complete these tasks and save a lot of time.

PowerShell is an ideal contender for automating operations related to active directory administration. Many operations that are performed using the Active Directory GUI (Graphical User Interface) tool may be performed relatively easily using PowerShell. PowerShell makes it simple for system administrators to accomplish these operations quickly and efficiently, whether it's generating a large number of user accounts from a csv/text file, adding users to different groups, or changing different group settings. System administrators frequently use various freely accessible PowerShell scripts for daily operations or create new ones to tackle a time-consuming administrative chore.

## How to install and import PowerShell Active Directory module:
The PowerShell Active Directory module is a collection of distinct cmdlets (pronounced command-lets) that may be used to administer and manage Active Directory domains and objects. Before you can use this module to gather information from the Active Directory, you must first install this module in your system. On different versions of Windows operating system, this module is included as a part of Remote Server Administration Tools (RSAT). You can follow the given instructions to install this module on your workstation or server.

### Installation on Windows 10 operating system:
1. Click on the Start menu and open Settings.
2. From the Settings main menu navigate to Apps->Optional Features.
3. Click on "Add a Feature" and type rsat in the search bar.
4. Select "RSAT: Active Directory Domain Services and Lightweight Directory Services" and install it.

### Installation on Windows Server operating system:
1. Click on the Start menu and open Server Manager.
2. Navigate to Manage-> Add Roles and Features.
3. Click next until you reach the Features menu.
4. Expand the Remote Server Administration Tools->Role Administration Tools->AD DS and AD LDS Tools, and then select the Active Directory Module for Windows PowerShell.
5. Click Next and then Install the module.

### Import the Active Directory Module:
1. Click the Start Menu and launch Windows PowerShell.
2. Verify the installation of the module by typing the following command in the PowerShell prompt window:

`Get-Module -Name ActiveDirectory`

3. After successful verification, type the following command to import the Active Directory module:

`Import-Module -Name ActiveDirectory`

After you have successfully installed and imported this module, you can start using its different cmdlets as demonstrated in the next section.

## Review of Important cmdlets in PowerShell Active Directory module:
This section goes over some of the most important cmdlets that can be used for gathering important information about different objects and domains in the Active Directory.

### Get-ADDomain:
The Get-ADDomain cmdlet is used to get the information about an Active Directory domain specified by different parameters such as a domain identifier, domain of the local computer, or the domain of the currently logged-in user.

In order to get the information about a particular domain, you can use the Identity parameter. The Identity parameter can accept different values such as distinguished name, GUID(Globally unique identifier), SID (Security Identifier), DNS domain name, or NetBIOS domain name. Use this parameter as follows to get the information about a specific domain:

`Get-ADDomain -Identity <your_required_identifier>`

In order to get the information about the domain of the local computer, use the Current parameter with the value LocalComputer as follows:

`Get-ADDomain -Current LocalComputer`

In order to get the information about the domain of the currently logged in user, use the Current parameter with the value LoggedOnUser as follows:

`Get-ADDomain -Current LoggedOnUser`

### Get-ADDomainController:
The Get-ADDomainController cmdlet is used to extract the information about domain controllers using different parameters such as a domain controller identifier, query strings, or specific search criteria. 

In order to get all the DCs in the current domain, run the command without any parameters as follows:

`Get-ADDomainController`

In order to get information about a specific domain controller, you can use the Identity parameter. The Identity parameter can accept different values such as IPv4 address, IPv6 address, GUID, DNS hostname, NetBIOS name, and much more. Use this parameter as follows to get the information about a specific domain controller:

`Get-ADDomainController -Identity <Your_required_Identifier>`

In order to discover all the domain controllers in a specific domain, use the Discover parameter as well as the Domain parameter with your required domain name:

`Get-ADDomainController -Discover -Domain <your_domain_name>`

### Get-ADUsers:
The Get-ADUser cmdlet is used to get one or multiple user objects from the Active Directory. This cmdlet is very powerful as it provides very useful information regarding different user accounts. This cmdlet cannot be run alone and requires the use  of different parameters to extract user account information. In order to get all the users in the current domain, use the following command:

`Get-ADUser -Filter *`

Here the Filter parameter is used to search for users depending upon the provided search query. Using an asterisk means that we want to get the list of all users. 

In order to enumerate all user accounts that are active, use the following command:

`Get-ADUser -Filter * | Where-Object{$_.Enabled -eq "True"}`

Here the Where-Object cmdlet is used to check the output for the Get-ADUser cmdlet for the condition where its Enabled property is set to True. $_ is used to refer to each user object in the output of Get-ADUser.

In order to get the login name of all the user accounts, use the following command:

`Get-ADUser -Filter * | Select-Object SamAccountName`

Here the Select-Object cmdlet is used to select the property SamAccountName from the output of Get-ADUser. SaaAccountName is the name that is associated with the user logging on to any of the systems.

In order to get all the properties associated with a particular user account, you can use the Identity parameter. The Identity can be a distinguished name, a Sam Account Name, GUID, or the SID of the user object. Use the following command to extract all the properties of a single user account:

`Get-ADUser -Identity <your_identifier> -Properties *`

### Get-ADGroup:
The Get-ADGroup cmdlet is used to get one or more groups from the Active Directory. This cmdlet allows you to extract information about a single group or multiple groups using different search parameters. This command cannot be run alone and requires the use of parameters to get group information. In order to extract all the groups in the domain use the following command:

`Get-ADGroup -Filter *`

In order to get the information about a specific group, use the Identity parameter. The Identity can be a distinguished name, a SamAccountName, GUID, or the SID of the group object. Use the following command to extract all the properties of a single group:

`Get-ADGroup -Identity <your_identifier>`

In order to get the all the groups that may have the name "admin" in them and belong to the Security Group Category, you can use the following query:

`Get-ADGroup -Filter {GroupCategory -eq "Security" -and Name -like "admin"}`

Here the Filter parameter is used to check for the presence of the two conditions using the -and operator. The -like operator is used to check for the string "admin" in group names.

### Get-ADGroupMember:
The Get-ADGroupMember gets all the members of a group specified by different parameters. This command cannot be run alone and requires the use of parameters to extract the members of any group. In order to get the members of a specific group, you can use the Identity parameter to identify the group. Use the following command to get the members of a single group:

`Get-ADGroupMember -Identity <your_group_identifier>`

In order to get all the members and child members of the Administrators group use the following command:

`Get-ADGroupMember -Identity "Administrators" -Recursive`

Here the recursive parameter is used to extract the members from the nested group that are within the Administrators group.

### Get-ADPrincipalGroupMembership:
The Get-ADPrincipalGroupMembership is used to extract the groups in which a specific user, computer, group, or service account is a member. You can use the Identity parameter in order to identify the user, group, service account, or computer. The values that can be used for this parameter can be a distinguished name, GUID, SID, or the Sam Account Name. In order to use this cmdlet to get the group membership of a specific object, use the following command:

`Get-ADPrincipalGroupMembership -Identity <identifier_for_the_object>`

### Get-ADComputer:
The Get-ADComputer cmdlet is used to get information about a single or multiple computer objects in a domain. Computer objects are created when the domain user joins a machine. In order to get all the properties of a specific computer use the Identity parameter. The values that can be used for this parameter can be its distinguished name, GUID, SID, or the Sam Account Name. Use this command to get all the properties of a computer object:

`Get-ADComputer -Identity <identifier_for_the_computer> -Properties *`

In order to get all the computers that are enabled and their associated names, IP addresses, Operating systems, and their versions use the following command:

`Get-ADComputer -Filter 'Enabled -eq "true"' -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address`

## Conclusion:
The basics of Active Directory and some of the important PowerShell cmdlets that can be used to gather vital data from the Active Directory have been discussed in this article. These cmdlets can reveal a lot about misconfigured security settings or excessive permissions in Active Directory that an adversary can exploit to carry out successful cyber-attacks on your network.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::