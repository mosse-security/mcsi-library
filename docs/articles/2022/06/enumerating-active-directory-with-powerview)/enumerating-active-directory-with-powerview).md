:orphan:
(enumerating-active-directory-with-powerview)=

# Enumerating Active Directory with Powerview

In this blog post, we will practice enumerating the Active Directory using the Powershell PowerView module.

## Windows `Net` Command utilities

First, let’s remember some examples of helpful commands:

- `net view /domain`: This command displays a list of all hosts in the specified domain.
- `net user /domain`: Displays a list of users.
- `net accounts /domain`: Displays the password policy.
- `net group /domain` : Displays a list of domain groups.
- `net group "Domain Admins" /domain` : Lists people in the group.
- `net share` : Displays the current number of SMB units.
- `net session`: This is used to examine SMB sessions.

Because net commands are incorporated into every Windows machine, understanding how to utilize them may be a valuable tool for testing Windows devices.

## Querying Active Directory groups using PowerView

PowerView is an extremely useful PowerShell tool for obtaining precise information on an organization's Active Directory domain and forest.

To utilize PowerView on our local machine, we first move the directory to where the PowerView module is located and disable PowerShell Execution Policy. The third command is then used to allow the use of PowerView with Powershell.

`cd Downloads`

` powershell -ExecutionPolicy bypass`

`. .\PowerView.ps1`

!enumerating active directoryl](images/powerview-1.png)

To retrieve information about your current domain run this command:

`Get-NetDomain`

In the following image, we get the forest and domain controller hostname.

!enumerating active directoryl](images/powerview-2.png)

We can also get the list of the domain policies of the defined domain with this command:

`Get-DomainPolicy`

!enumerating active directoryl](images/powerview-3.png)

This command shows all operating systems on the domain.

`Get-NetComputer -fulldata | select operatingsystem`

!enumerating active directoryl](images/powerview-4.png)

We can get a list of all users on the domain with this command:

`Get-NetUser | select cn`

!enumerating active directoryl](images/powerview-5.png)

To retrieve the Security Identifier (SID) of the current domain, use the following command:
`Get-DomainSID`

!enumerating active directoryl](images/powerview-6.png)

To easily retrieve the identity of the domain controller on the current domain, use the following command: `Get-NetDomainController`.

As shown in the following snippet, we got specific details about the domain controller such as its operating system, hostname, and IP addresses.

!enumerating active directoryl](images/powerview-7.png)

To get a list of all the users on the current domain, use the following command: `Get-NetUser`

As shown in the following screenshot, we listed all user names which has a lowercase _e_ in their username.

!enumerating active directoryl](images/powerview-8.png)

To list all domain computer accounts on the current domain, use the following command: `Get-NetComputer`

!enumerating active directoryl](images/powerview-9.png)

To list all the groups within the current domain, use the following command: `Get-NetGroup`.
As shown in the following screenshot, all the groups, and their details were retrieved:

!enumerating active directoryl](images/powerview-10.png)

To get a list of all the GPOs from the current domain, use the following command: `Get-NetGPO`

!enumerating active directoryl](images/powerview-11.png)

To get specific details about the current forest, use the following command: `Get-NetForest`. As shown in the following screenshot, we got information about the forest :

!enumerating active directoryl](images/powerview-12.png)

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html)
:::
