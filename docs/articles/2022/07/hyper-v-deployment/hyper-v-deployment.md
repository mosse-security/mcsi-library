:orphan:
(hyper-v-deployment)=
# Hyper V deployment
 
The most crucial element of your virtual environment is unquestionably the Hyper-V host. All of the systems under its purview are immediately at risk if it is compromised. But a computer system is what the Hyper-V host is first and foremost. It must be treated like any other computer system before being treated as a computer that is running a hypervisor. Of course, specific considerations are necessary because it will operate as a hypervisor.

Understanding the architecture of Hyper-V It's crucial to understand the fundamentals of Hyper-V architecture before you can address the security of your Hyper-V host. Without it, it's challenging to comprehend how different security measures will impact the parts of your deployment.

The hypervisor is mostly independent of the management operating system, which is the most crucial concept to grasp. Hyper-V is not an operating system or an application. The hardware that the hypervisor is installed on is directly under its control. It oversees several partitions that house virtual machines. The management operating system is operated on one of these partitions, which is referred to as the parent partition. Only the parent partition is permitted to communicate with the hypervisor directly. The hardware drivers utilized by the hypervisor in Hyper-V are provided by the parent partition. Although the parent partition does have some direct access to the hardware, I/O is ultimately handled by Hyper-V. On very large systems, the gap between the management operating system and the hardware is most obvious.

**Selecting a management operating system**

Prior to starting a project, you must first decide which of these strategies you'll use. Given that each strategy has advantages and disadvantages of its own, this is not an easy decision.

**Hyper-V Server**

The main security advantage of Hyper-V Server is that even the smallest Windows Server deployment has a far larger attack surface than Hyper-V Server. The least number of operating system components that might compete with virtual machines for resources is another result of this. Despite being somewhat less feature-rich than its full-featured version, it nevertheless has all the options required to run a Hyper-V environment, including RemoteFX, the Remote Desktop Virtualization Host, and the ability to join a failover cluster.

However, the same restrictions that make Hyper-V Server more secure also reduce its usability. On Hyper-V Server, there is no built-in GUI. While this boosts the system's protection from direct attacks, it can also weaken the host's security if the administrators in charge are ill-equipped or unable to administer it. Lack of a familiar interface might frustrate users, causing them to take shortcuts that unnecessarily raise the host's risk. For instance, some administrators may want to completely disable a firewall rule using a single line of code because managing firewall rules from the command line might be intimidating.

**Windows Server – full GUI installation**

A full installation of Windows Server with the Hyper-V role enabled is at the other end of the spectrum from Hyper-V Server. The familiarity of the graphical interface is the main factor that influences why most people pick this strategy. Of all feasible deployment techniques, this does, of course, come at the expense of having the largest attack surface. By only activating the responsibilities and functionalities required for the deployment and management of Hyper-V, the risk can be reduced. Microsoft does not support the usage of the majority of the other accessible components when Hyper-V is operational, despite the security advantages of this advice.

**Windows Server – Core installation**

The default installation mode in recent iterations of Windows is Core. This mode lacks its own graphical user interface, just like Hyper-V Server. Applications that do not rely on the Microsoft Management Console or Internet Explorer will typically continue to function regularly because the majority of the Windows Forms components and application interfaces are still available and the most recent versions of the.NET Framework can be installed.

Even though it has the least attack surface imaginable, this Windows Server installation is nonetheless bigger than Hyper-V Server. This mode can be used to establish a balance between the necessity for some supporting technologies, such as Data Deduplication, which are exclusive to Windows Server and the desire for enhanced security. Do keep in mind that, as was stated previously, running many of the other Windows Server components on the host with Hyper-V is not recommended.

**Windows Server – Minimal Server Interface installation**

The Minimal Server Interface installation option sits between full and core installations. Internet Explorer is one of the most often used attack methods on the Windows platform. Some built-in graphical capabilities are preserved while drastically lowering the exposure of the operating system by deleting the majority of Internet Explorer's functions along with related elements like the Start screen and the desktop. It is possible to access a variety of tools, including Hyper-V Manager, using the Microsoft Management Console (MMC) application.

**Switching between Windows Server modes**

Before making a choice, remember that all Windows Server requires is a simple system reboot to switch between any of its three modes. The only GUI-less option offered by Hyper-V Server is the only one. To add the graphical files using either method, you will need to provide the source installation discs since they are not included by default if the operating system was initially installed in Core mode.

**Practical guidance to choose a deployment**

When choosing between your options, there is no one right answer. It's a good idea to confirm that the hardware you'll be installing is supported both with Windows Server and when the server is installed in Core mode before you get started. Anything that functions in Core mode should also operate with Hyper-V Server, but the hardware maker is the only one who can guarantee this with certainty. It may also depend on the third-party applications you plan to install on the machine. Although you should limit the use of such software, backup agents and software are frequently necessary, and in some situations, anti-malware software may also fall into this category. Most software does work even on Core, as the Windows Forms Framework and API are available, but the Windows Presentation Framework is not.

Since the Windows Forms Framework and API are available but the Windows Presentation Framework is not, the majority of apps does operate on Core. The manufacturer may not offer support for the hardware and software you wish to use, even if it does operate on Server Core and Hyper-V Server. Be sure to speak with the tool's manufacturers before choosing a deployment strategy.The general level of technical skill of your Windows Server administrators and the anticipated dependence of your deployment on features are two fundamental indicators to assist you to choose a deployment strategy.

Technical knowledge will inevitably increase via exposure, and your company could be ready to invest time and money in training. Although they are present and must not be overlooked, the increased dangers brought on by the greater attack surface of the more feature-rich options shouldn't be treated as a deciding factor for any institution—aside from those that are already at high risk. Even if an attacker succeeds to compromise files that are never used by the operating system, they are of little use to them. In light of this, you can lower your risk by strictly following two rules. The first rule is to never authorize extra roles and services. Second, instead of performing in-place updates, completely uninstall outdated operating systems and replace them with more recent versions.

**Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**