:orphan:
(securing-virtual-machines-of-hyper-v)=
# Securing Virtual Machines of Hyper V
 
Virtual machines (VMs) are displayed to the outside world in a manner similar to that of a physical machine. They typically run a full operating system and are connected to a network. It is not possible for the hypervisor to make several intercessions on behalf of the virtual machine because of the built-in separation between the guest and its host.

**Recognizing the security environment of virtual machines**

It is important to have a thorough understanding of how virtual machines function in order to comprehend their security requirements. Many administrators find it to be almost entirely mysterious how hypervisors and their guests interact. Many of the explanation materials tackle this topic using complex architectural jargon that many administrators desire or need to know but is frequently unclear.

Isolation is the main characteristic of hypervisor terminology. The main goal of the hypervisor is to create distinct environments that are shielded from interfering with one another, even though management operating systems and all of its guests share a hardware environment. The fact that guests are walled off from one another is typically not surprising to anyone, but it is sometimes hidden that the management operating system also lacks direct access to the visitors.

Administrators frequently have a valid need to transfer data directly between the management operating system and a guest, therefore this can occasionally be a source of aggravation. Any such method, though, is rather simple for an attacker to take advantage of. As a result, solitude is the norm.

The inevitable fact is that the management operating system and all of its guests share a single set of hardware, even though isolation is the intended goal. It is advantageous to have some knowledge of how Hyper-V manages hardware access.

**Process isolation**

At the very least one actual CPU core must be available to every virtual machine. Physical cores are not immediately assigned to guests by Hyper-V. Instead, it makes use of an algorithm that aims to evenly spread the processing load across the hardware that is readily available, allowing any CPU core to be actively running a thread from any given virtual machine at any given time.
Similar to how the Windows operating system manages threads from running processes, Hyper-V manages these threads. Processes are executed by the guest operating systems exactly as they would be in a non-virtualized environment. Hyper-V is able to directly handle all threads from all guests by running on a higher privilege level (referred to as a ring) on the actual CPUs.

The administration of all threads by Hyper-V eliminates the requirement for guest threads to go via the management operating system. Therefore, a break-out attack (i.e., one that overcomes isolation boundaries) from the management operating system is no more likely to happen than one from a guest. Technologies like CPU-based hardware-assisted virtualization and data execution prevention (DEP), both of which are necessary to run Hyper-V, significantly reduce the impact of attacks of this kind.

**Hard disk isolation**

Hard drive access for virtual machines must go through the management operating system, unlike for CPUs. The management operating system and Hyper-V work together to make sure that virtual machines only access data that they are authorized to access. However, the storage of all virtual machines would be immediately in danger if the management operating system were compromised. The same challenges that a memory break-out attack faces will also apply to break-out attacks on storage within a virtual machine; while dangerous, these attacks are much more likely to cause generalized damage than to enable the targeted retrieval of sensitive data.

**Network isolation**

Compared to the technologies mentioned above, networking operates very differently. The virtual switch and the virtual adapter must both be isolated. A virtual adapter can also be para-virtualized, emulated, or completely bypass the hypervisor via single-root I/O virtualization (SR-IOV).

All indications point to the management operating system and guest operating systems as the attackers' preferred targets. Although the complexity of the hypervisor by itself makes it likely to have some security laws, devoting a lot of time to securing the hypervisor's constituent parts is probably not a worthwhile endeavour.

**Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**