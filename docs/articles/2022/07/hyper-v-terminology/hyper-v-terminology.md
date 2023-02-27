:orphan:
(hyper-v-terminology)=
# Hyper V terminology
 
Before discussing how to secure Hyper-V, below is the terminology of Hyper-V and related technologies. This article will give a comprehensive explanation for these terms.

## Hyper-V

The type 1 hypervisor technology created and offered by Microsoft is denoted by the single word Hyper-V. This phrase does not apply to any specific item. Beginning with Windows Server Version 2008 and Professional and Enterprise Desktop Windows Operating Systems starting with Version 8, it is available as an installable feature.

## Hyper-V Server

A standalone product, Hyper-V Server is readily accessible from Microsoft. A significantly altered version of Windows Server is packed with a free download of the hypervisor.

## Client Hyper-V

Client Hyper-V is the term used to describe Hyper-V as it appears in Windows desktop editions. The differentiation is required since it differs from Hyper-V as it is available in the server editions in terms of needs and restrictions.

## Host

The host is the actual computer system that powers Hyper-V.

## Guest

The words "virtual machine" and "guest" are frequently used interchangeably. It is most frequently used to refer to the virtual machine's operating system.

## Management operating system

As a type 1 hypervisor, Hyper-V has no independent interface and has direct access to the hardware of the host. An exclusive virtual machine called a management operating system can communicate with the hypervisor to regulate both the software and the hardware. This is referred to as the parent partition in other hypervisors.

There is no official definition for the term Hyper-V Core and its variations. The core is a unique setting for Windows Server that excludes a graphical user interface. Given that Hyper-V Server likewise lacks a GUI, it is frequently used to describe that product. Avoid using the core modification when crossing Hyper-V Server as it causes confusion.

Due to the lack of any graphical user interface, Hyper-V Server is frequently (and incorrectly) referred to as core. The command line and PowerShell are the two control methods accessible on the console. Due to the absence of the majority of Windows roles and features, this is not the same as a Windows Core installation. Using Hyper-V in this way has a variety of advantages and cons. Less components in the base installation image and fewer possible weak points for an attacker to breach are the main advantages in terms of security.

## Client Hyper-V

Only Professional and higher desktop versions of Windows support client Hyper-V, but that isn't the only way it differs from its server platform cousin. It needs a CPU with second-level address translation capabilities (SLAT). Additionally, the feature set is smaller. The technologies RemoteFX, Hyper-V Replica, and Live Migration are among those that are excluded. 

Additionally, Client Hyper-V is less likely to use up all of the host memory when running guests.
Application development is one of Client Hyper-most V's popular uses. In-progress software programs should be safeguarded just like any other server-based asset because most software development companies view them as extremely valuable assets.

**Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**