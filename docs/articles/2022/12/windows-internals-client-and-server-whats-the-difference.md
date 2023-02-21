:orphan:
(windows-internals-client-and-server-whats-the-difference)=

# Windows Internals: Client and Server. What's the difference?

Windows Internals is a set of technologies and tools that enable developers to gain insight into the inner workings of the Windows operating system. This includes understanding the underlying architecture of the OS, the services and components used to construct a Windows system, and the various interactions between the various components.

Windows comes in two major flavors: Client and Server. The main difference between the two is the purpose they are designed to serve. Client Windows is designed for everyday use and is used on computers, laptops, and tablets. It’s the version of Windows that most people interact with on a daily basis. Server Windows is designed for businesses, large organizations, and other entities that need to manage large networks of computers and provide services to many users.

Both versions of Windows use the same core technologies, but the way they are configured and used can be quite different. Client Windows is focused on providing a basic set of features and services to the end user. This includes things like the Windows UI, system tools, and programs. Server Windows is designed to provide more advanced features and services to businesses and organizations. This includes things like file sharing, user authentication, and centralized management.

Client Windows is also generally easier to use than Server Windows because it is designed to be used by individuals without a lot of technical know-how. Server Windows is designed to be used by IT professionals and requires a lot more technical knowledge to be able to use it.

Overall, the main difference between Client and Server Windows is the purpose each version is designed to serve. Client Windows is designed for everyday use by individuals, while Server Windows is designed to provide advanced features and services to businesses and organizations.   

Client-Side Features

1. Windows Store: The Windows Store is a digital marketplace where users can purchase and download apps, games, music, movies, and TV shows. 

2. Windows Update: Windows Update checks for and downloads updates for Windows, such as security patches and feature updates. 

3. Windows Defender: Windows Defender is a built-in security solution that protects devices against malicious software. 

4. Windows PowerShell: Windows PowerShell is a scripting language that allows users to automate tasks and manage systems. 

5. Windows Remote Desktop: Windows Remote Desktop allows users to access their computers remotely via the internet. 

Server-Side Features

1. Active Directory: Active Directory is a directory service that stores user and computer account information and allows administrators to manage users, computers, and other network resources. 

2. Hyper-V: Hyper-V is a virtualization platform that allows users to create and manage virtual machines. 

3. Windows Server Update Services: Windows Server Update Services (WSUS) is a patch management system that helps administrators keep their systems up-to-date. 

4. Windows Remote Management: Windows Remote Management (WinRM) is a protocol that allows administrators to manage devices remotely. 

5. Windows Server Manager: Windows Server Manager is a graphical user interface that allows administrators to manage servers, roles, and features.

## Practical experiment: Identifying the Functionality Made Available by the Licensing Policy      

As was just said, Windows is capable of supporting more than one hundred distinct features, each of which may be activated through the software licensing process.      

1. Using Windows PowerShell to query the current licensing policy: 

To check the current licensing policy, you can use the `Get-CimInstance` cmdlet. This cmdlet can be used to query information about the licensing policy on the local computer.

For example, the following command can be used to query the licensing policy on the local computer:

```powershell
Get-CimInstance -ClassName Win32_LicenseAuthenticationPolicy
```

2. Using Windows PowerShell to enable or disable license policy functionality: 

To enable or disable license policy functionality, you can use the `Set-CimInstance` cmdlet. This cmdlet can be used to set the properties of the licensing policy on the local computer.

For example, the following command can be used to enable the use of a license key:

```powershell
Set-CimInstance -ClassName Win32_LicenseAuthenticationPolicy -Property @{UseLicenseKey="True"}
```

Similarly, the following command can be used to disable the use of a license key:

```powershell
Set-CimInstance -ClassName Win32_LicenseAuthenticationPolicy -Property @{UseLicenseKey="False"}
```

## Practical experiments. How to use Client and Server features

```cpp
#include <windows.h>
#include <iostream>

using namespace std;

int main()
{
	// Get the handle to the current process
	HANDLE processHandle = GetCurrentProcess();

	// Get the process identifier
	DWORD processId = GetProcessId(processHandle);

	// Get the priority class of the process
	DWORD priorityClass = GetPriorityClass(processHandle);

	// Get the memory usage of the process
	PROCESS_MEMORY_COUNTERS pmc;
	GetProcessMemoryInfo(processHandle, &pmc, sizeof(pmc));

	// Get the processor time for the process
	FILETIME creationTime, exitTime, kernelTime, userTime;
	GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime);
	ULARGE_INTEGER uKernelTime, uUserTime;
	uKernelTime.LowPart = kernelTime.dwLowDateTime;
	uKernelTime.HighPart = kernelTime.dwHighDateTime;
	uUserTime.LowPart = userTime.dwLowDateTime;
	uUserTime.HighPart = userTime.dwHighDateTime;
	DWORD64 processorTime = uKernelTime.QuadPart + uUserTime.QuadPart;

	// Print out the process information
	cout << "Process ID: " << processId << endl;
	cout << "Priority Class: " << priorityClass << endl;
	cout << "Memory Usage (in bytes): " << pmc.WorkingSetSize << endl;
	cout << "Processor Time (in milliseconds): " << processorTime / 10000 << endl;

	// Close the handle to the process
	CloseHandle(processHandle);

	return 0;
}
```

For checking Windows OS version we can also use following code snippet:    

```cpp
#include <windows.h> 
#include <stdio.h> 

int main() { 
    // Local variables 
    OSVERSIONINFO osvi;

    // Get the OS Version Information 
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO)); 
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO); 
    GetVersionEx(&osvi);

    // Check the version of the operating system 
    if (osvi.dwMajorVersion >= 5) 
    { 
        // Windows 2000 or higher 
        printf("This is a Windows 2000 or higher operating system.\n"); 
    } 
    else
    { 
        // Windows 98 or lower 
        printf("This is a Windows 98 or lower operating system.\n"); 
    } 

    return 0;
}
```

## Windows versions vulnerabilities. Eternal Blue

Eternal Blue is a vulnerability in the Server Message Block (SMB) protocol of Microsoft Windows first discovered and made public by the Shadow Brokers hacker group in April 2017. It is an exploit that takes advantage of a buffer overflow within the protocol, allowing an attacker to remotely execute code on vulnerable systems.        

The exploit is particularly dangerous because of its ease of use and its ability to propagate across networks. Once one vulnerable system has been compromised, the attacker can use the same exploit to search for and compromise other vulnerable systems on the same network. This makes Eternal Blue a powerful tool for large-scale malicious attacks.        

The exploit was used in the WannaCry ransomware attack of 2017 and multiple other high-profile cyber-attacks since then. It is believed to have been developed by the United States National Security Agency (NSA) and was leaked by the Shadow Brokers in April 2017.     

Eternal Blue is a serious threat to organizations, both large and small. It is important for organizations to stay up to date on the latest security patches to prevent exploitation of the vulnerability. Additionally, organizations should ensure they have adequate backups and monitoring in place to detect and respond quickly to any potential malicious activity.       

As the threat posed by Eternal Blue continues to grow, security professionals must remain vigilant in their efforts to protect systems and networks from exploitation. By staying up to date on the latest security patches and monitoring networks for suspicious activity, organizations can reduce their risk of becoming victims of malicious attacks.       
 
## BlueKeep

BlueKeep is a critical vulnerability in Microsoft’s Remote Desktop Protocol (RDP) that was discovered in May 2019. The vulnerability affects all versions of Windows from XP to Windows Server 2008 R2, and allows an attacker to gain remote access to a vulnerable system without authentication.

BlueKeep has been categorized as a “wormable” vulnerability, meaning it is capable of spreading from one vulnerable system to another without any user interaction. This means that an attacker who successfully exploits the BlueKeep vulnerability can gain access to a large number of computers in a very short amount of time.

Exploiting BlueKeep is relatively simple. All an attacker needs to do is send a specially crafted packet to the Remote Desktop Protocol (RDP) port of a vulnerable system. This will cause the system to crash, and the attacker can then execute arbitrary code on the system.

Once the attacker has gained access to the system, they can then install malware, steal data, or launch other attacks.

There are a few ways to protect against BlueKeep. The most important thing is to make sure all systems are running the latest version of Windows and have all security patches applied. Additionally, it is important to have a good firewall in place that blocks all incoming traffic to the RDP port. Finally, it is important to use a strong password, as BlueKeep can be exploited even if the system is password protected.

BlueKeep is a serious vulnerability that should not be taken lightly. It is important to take the necessary steps to protect against this vulnerability and to ensure that all systems are running the latest version of Windows and have all security patches applied. Doing so will help to reduce the risk of exploitation and keep your systems secure.

## References 

[Windows Internals (Developer Reference) 7th Edition](https://www.amazon.com/Windows-Internals-Part-architecture-management/dp/0735684189)      
[MSDN documentation](https://learn.microsoft.com/en-us/)     