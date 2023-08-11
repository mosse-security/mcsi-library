:orphan:
(system-hardening)=

# What is System Hardening?

When you take a new system out of the box, are you more concerned with getting it up and running, or ensuring that the security features are configured in the most optimum way? If you’re like most people, you probably picked the first one! One of the major issues the cybersecurity industry faces is the fundamental tension between security and ease of use – put simply, the more secure a system is, the more difficult it often is to use. Take two-factor authentication as an example – setting up two-factor takes a few minutes and some technical know-how and also increases the time it takes to log into an account each time. Overall, it’s slower and more difficult to protect your accounts with two-factor authentication – not much, but a little bit. In return, the additional protection offered is *more* than worth it (in fact, enabling two-factor is probably the single most impactful thing that most average users can do to protect their data) but for some people, it simply feels too complicated or like too much work.

System and software manufacturers know this – they also know that shipping systems which are complex to set up will lead to *tonnes* of support calls and perhaps even a reputation for difficulty of use, which could hurt sales. Therefore, most systems ship with a “good enough” set of security defaults, which provide as much protection as possible without interfering with the user experience to any great extent. 

As you might imagine, this leaves a system in a less than desirable state via-vis security. Hardening then, is simply the process of fixing this. Cybersecurity professionals enable security controls and alter settings to enhance the security of computer systems by reducing vulnerabilities and minimizing potential attack surfaces, often without needing to install any third-party software at all. Many in the industry take the view that these kinds of steps should, in fact, be the default settings – this is often called a “secure by default” configuration. At the moment, however, that isn’t usually the case – so let’s explore some of the most common hardening steps you should be familiar with. 

 

## Open Ports and Services

Closing unnecessary open ports and services is a fundamental step in reducing a system's attack surface. Services like file sharing, remote desktop, and web servers can often introduce vulnerabilities if not essential for operations. By regularly reviewing and closing unused ports and services, organizations can limit potential entry points for attackers. You may be shocked to see just how many ports and unused services are running on your machine! 

Here's an example of listing open ports, stopping and disabling any unused services on Linux:

```
# List open ports
sudo netstat -tuln

# Disable an unnecessary service
sudo systemctl stop <service-name>
sudo sys
```

 

## Registry Hardening

The Windows operating system stores critical system and application settings in a database known as the Registry. Hardening the registry involves configuring access permissions, removing unnecessary entries, and limiting user privileges. This prevents unauthorized modifications, reduces potential attack vectors, and enhances the overall system stability. It should be mentioned that the Windows Registry is not a structure to be casually modified or changed – some expertise is required.  One simple security task you can do, however, is to periodically make a backup of the Registry to a secure location, as this can prove invaluable should you need to recover from an attack or issue with the registry configuration. 

Let's back up the Registry - then Setting the `DisableRegistryTools` value to 1 restricts access to various registry editing tools for non-administrator users. This helps prevent unauthorized modifications to critical registry keys that control system settings and behavior

```
bash
# Backup the registry before making changes
reg export HKEY_LOCAL_MACHINE\Software C:\backup\software.reg

# Restrict access to sensitive registry keys
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d 1 /f
```

 

## Disk Encryption

Disk encryption safeguards data at rest by encrypting the entire disk or specific partitions. In the event of physical theft or unauthorized access, encrypted data remains unreadable without the decryption key. Full disk encryption, such as BitLocker for Windows or FileVault for macOS, is crucial for protecting sensitive information on devices.



## Operating System (OS) Hardening

OS hardening involves configuring the operating system to minimize vulnerabilities. This includes disabling unnecessary features, setting strong password policies, and configuring firewalls. Wherever possible, applying the principle of least privilege ensures that users and processes have only the permissions required for their tasks, limiting potential damage from compromised accounts.

Special care is needed with virtual machines, especially if they have been created from a baseline “golden image” – such images often contain default credentials, or credentials which are common to all clones of the image (for example, a Windows local administrator password). Be sure to change these when creating VMs. 

In this example, we disable root user login via ssh, and use the uncomplicated firewall (UFW) to allow only the needed ports on a Linux server:

```
bash
# Disable root login via SSH
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo service ssh restart

# Implement firewall rules to allow only necessary traffic
sudo ufw enable
sudo ufw allow 22/tcp   # Allow SSH
sudo ufw allow 80/tcp   # Allow HTTP
sudo ufw deny 3306/tcp  # Deny MySQL
```

 *Tip: Don’t forget that the hypervisor running the VMs also needs hardening and patching - In a virtualised environment, none of your machines are secure if your hypervisor has a vulnerability!* 



## Patch Management

Regularly applying security patches and updates is a cornerstone of system hardening. Operating systems and applications can (and often do) have vulnerabilities that are exploited by attackers. Effective patch management ensures these vulnerabilities are promptly addressed, reducing the window of opportunity for attackers.

Remember that availability is also a critical part of security – with this in mind, a critical patch may need to be rolled out right away, but an update carrying a fix for a low impact hard to exploit vulnerability on an important server probably warrants some testing before going live.

Patch management is easy on Linux!:

```
# Update the package list
sudo apt update

# Upgrade all installed packages
sudo apt upgrade -y 
```

 

## Third-Party Updates

Third-party software often introduces vulnerabilities that attackers can exploit. Implementing a robust process for managing third-party software updates is crucial. Using centralized tools to track and update these applications helps maintain a secure environment – there are many third-party solutions for Windows systems which can help with these, whereas in a Linux or Mac environment, it’s more common to be able to manage and update all software packages from a single update tool. 

 

## Automated Updates

Enabling automated updates for operating systems and applications streamlines the patch management process. Automated updates ensure that security patches are applied promptly, reducing the risk of system compromise due to known vulnerabilities. By contrast, it increases the chance of a patch being applied and causing an issue in a production system. For this reason, an in enterprise environment it’s common to test patches on a test system before sending them out to the entire network. 

 Here we enable automated updates using powershell - you can certainly do this from the windows GUI, but powershell scripts are often preferred in a large environment. 

```
powershell
# Check if the Windows Update service is running
$serviceStatus = Get-Service -Name "wuauserv"
if ($serviceStatus.Status -eq "Running") {
    Write-Host "Windows Update service is already running."
} else {
    Write-Host "Starting Windows Update service..."
    Start-Service -Name "wuauserv"
}

# Configure automatic updates
Write-Host "Enabling automatic updates..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4

# Restart Windows Update service to apply changes
Write-Host "Restarting Windows Update service..."
Restart-Service -Name "wuauserv"
Write-Host "Automatic updates are now enabled."
```

# Final words

System hardening is an essential practice in modern cybersecurity - until vendors start to ship software and hardware with a configuration which is secure out of the box (which may never happen!) hardening will always be required. By implementing techniques like closing unnecessary ports, registry hardening, disk encryption, OS hardening, and effective patch management, organizations can significantly reduce the attack surface and enhance their overall security posture. As cyber threats continue to evolve, a proactive approach to system hardening becomes imperative to safeguard sensitive data, maintain operational integrity, and protect against potential breaches.
