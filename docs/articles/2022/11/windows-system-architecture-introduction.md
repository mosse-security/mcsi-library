:orphan:
(windows-system-architecture-introduction)=

# Windows System Architecture: Introduction

We are going to start our investigation of the internal design objectives and structure of the Microsoft Windows operating system now that we have covered the vocabulary, ideas, and tools that you need to be familiar with.      
This post provides an overview of the system's general architecture, including its primary components, the manner in which those components interact with one another, and the environment in which they are executed.        
In order to give a foundation for understanding the inner workings of Windows, let's begin by going through the needs and goals that inspired the initial design and specification of the system. This will allow us to get a better idea of how Windows is put together.    

In 1989, the specification of Windows NT was driven by the need to meet the following requirements:

1. Provide an operating system that is genuine 32 bits, preemptive, reentrant, and virtual memory based.

2. Be able to function on a variety of different platforms and hardware architectures

3. Function properly on symmetric multiprocessing systems and scale up well

4. Function admirably as a distributed computing platform, both as a client and a server for other networks.

5. Support for the majority of 16-bit versions of MS-DOS and Microsoft Windows
3.1 applications

6. Ensure that you are compliant with all POSIX 1003.1 rules set by the government

7. Ensure that your operating system complies with all of the government and industry security standards

8. Support Unicode and make yourself easily adaptable to the international market. 


To guide the thousands of decisions that had to be made to create a system that met these requirements, the Windows NT design team adopted the following design goals at the beginning of the project:     

**Extensibility** means that the code must be developed in such a way that it can easily expand and alter in response to shifting market requirements.

**Portability** is the capacity of a system to function properly on a variety of different hardware architectures and to transition relatively painlessly to new architectures when the needs of the market change.

**Dependability and sturdiness:** The system should be able to defend itself against both internal malfunction and external manipulation.
It is unacceptable for applications to have the capability of causing harm to either the operating system or to other programs.

**Compatibility** Although Windows NT should expand upon previously developed technology, its user interface and application programming interfaces (APIs) should be compatible with previous versions of Windows as well as MS-DOS.
Additionally, it should have a good level of compatibility with other operating systems, such as UNIX, OS/2, and NetWare.

**Performance** - Within the limitations imposed by the other design criteria, the system should be as quick and responsive as is physically possible on each and every hardware platform.     

The operating system kernel code runs in a privileged processor mode (referred to as kernel mode) with access to the system data and to the hardware. Application code runs in a nonprivileged processor mode (called user mode), with a limited set of interfaces available, limited access to system data, and no direct access to hardware. In the majority of multiuser operating systems, applications are kept separate from the operating system itself.
When a user-mode program makes a call to a system service, the processor carries out a specialized instruction that transitions the calling thread into the kernel mode of the operating system.    

The operating system will return the thread context to user mode after the system service has been completed, at which point the caller will be able to proceed with their work.     

Windows is quite similar to the majority of UNIX systems in the sense that it is a monolithic operating system. This refers to the fact that the majority of the operating system code and device driver code share the same kernel-mode protected memory space on Windows computers.
This demonstrates that any component of the operating system or device driver has the ability to corrupt data that is being utilized by other components of the operating system.      

However, Windows does include various kernel protection measures, such as PatchGuard and Kernel Mode Code Signing, which aid in mitigating and preventing issues linked to shared kernel-mode address space. These methods contribute to the mitigation and prevention of vulnerabilities.
Because apps do not have direct access to the source code and data of the privileged part of the operating system, all of these components of the operating system are, of course, entirely protected against programs that behave inappropriately (although they can quickly call other kernel services).      

This protection is one of the reasons why Windows is known for its reputation of being both robust and stable as an application server and as a workstation platform, while at the same time being quick and nimble in terms of the core operating system services, such as virtual memory management, file I/O, networking, and file and print sharing.        

## Overview

Following this quick introduction to the design objectives and packaging of Windows, let's investigate the primary system components that comprise its architecture.
The architecture is depicted in figure in a form that is simplified from the original.
Bear in mind that this is just a rudimentary schematic, and that it does not depict everything.
(For instance, the components that are responsible for networking and the many different kinds of device driver stacking are not represented.) 

![1](windows-system-architecture-introduction/2022-11-21_05-57.png)    

Take note of the line that separates the user-mode components of Windows from the kernel-mode components of the operating system. The components that can be found below the line are user-mode operating system services, whereas the boxes that can be found above the line are user-mode processes.     

User-mode threads run in an area of the process address space that is shielded from interference (although while they are executing in kernel mode, they have access to system space).      

Therefore, the process address space for system support processes, service processes, user applications, and environment subsystems are all separate and distinct from one another.       

The four basic types of user-mode processes are described as follows:      

*Processes* that are not considered to be Windows services but are still essential to the operation of the system include the login procedure and the Session Manager.
(This means that the service control manager is not the one who initiates them.)

*Processes that host Windows services*, such as the Task Scheduler and Print Spooler services, are referred to as service processes. In most cases, the need for services is that they function in a manner that is independent of user logins. Numerous server software for Windows, such as Microsoft SQL Server and Microsoft Exchange Server, also feature components that function in the background as services.

*Applications* used by users, which can be any one of the following categories:
Windows 32-bit or 64-bit, Windows 3.1 16-bit, MS-DOS 16-bit, or POSIX 32-bit or 64-bit, as well as either version of Windows.
Please be aware that only the 32-bit version of Windows can execute 16-bit apps.

*Processes that run on the environment subsystem server* are responsible for implementing a portion of the support for the operating system environment, often known as the "personality," that is displayed to the user and the programmer. Windows NT was first distributed alongside three distinct environment subsystems: POSIX, OS/2, and Windows itself. The POSIX and OS/2 subsystems, on the other hand, were not distributed after Windows 2000.
Support for an upgraded POSIX subsystem known as the Subsystem for Unix-based Applications is included in all of the server editions of Windows, as well as the Ultimate and Enterprise editions of the Windows client operating system (SUA).     

Take note of the "Subsystem DLLs" box, which may be found underneath the boxes labeled "Service processes" and "User applications."   

In Windows, user programs do not use the native Windows operating system services directly; rather, they travel via one or more subsystem dynamic-link libraries in order to do so. This is because using the native Windows services directly would be inefficient (DLLs).
Subsystem DLLs are responsible for translating defined functions into the proper native system service calls, which are typically not documented. This is the job that the subsystem DLLs play.     

This translation may entail sending a message to the environment subsystem process that is serving the user application, or it could not require sending such a message at all.   

The kernel-mode components of Windows include the following:      

The *"Windows executive"* is where the fundamental services of the operating system are stored. These fundamental services include memory management, process and thread management, security, input/output, networking, and interprocess communication.

The *"Windows kernel"* is made up of low-level operating system tasks such as thread scheduling, interrupt and exception handling, and synchronization of several processors.
In addition to this, it gives the rest of the executive a collection of procedures and fundamental objects that they may utilize to develop higher-level constructions.

The term *"device drivers"* refers to both hardware device drivers and nonhardware device drivers such as file system and network drivers. Hardware device drivers are responsible for converting user I/O function calls into specific hardware device I/O requests. Nonhardware device drivers include file system and network drivers.

A layer of code known as *"the hardware abstraction layer"* or "HAL" serves to insulate the kernel, device drivers, and the rest of the Windows executive from the platform-specific hardware incompatibilities (such as differences between motherboards).

The graphical user interface (GUI) functions, more often referred to as the Windows USER and GDI functions, are implemented by *"The Windowing and Graphics System."* These functions include interacting with windows, user interface controls, and drawing.   

