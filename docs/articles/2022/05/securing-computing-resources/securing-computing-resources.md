:orphan:
(securing-computing-resources)=

# Securing Computing Resources

In this blog post, we will deep dive into components of computing resources and their security implications. Before learning how to secure a computer architecture, we need to learn its building blocks. Let's start by understanding the importance and components of compute resources. Cloud computing provides handy, on-request online access to collective customizable and flexible resources.

These are resources such as:

- networking,
- workstations,
- memory,
- database,
- applications,
- and operations.

They can be instantly delivered and destroyed with minimum management activity.

## Components of compute instances

Cloud infrastructures are designed to handle multiple types of resources and efficiently allocate those resources among tasks and programs. One of them is computing instances. You can assign an instance to a single task or perform numerous workloads as needed.

- Compute component encompasses CPU computation time and RAM work area.
- It is implemented by hypervisors, containers, and dedicated hardware resources.
- It segregates the workflows of different users.

## Creating compute instances

There are three fundamental techniques for deploying compute instances:

**hypervisor**

A hypervisor builds virtual computers that include virtual CPUs, RAM, NIC, peripheral connectors, and storage, as well as a virtual BIOS. Each compute instance runs a fully unique and segregated operating system thanks to a hypervisor that virtualizes the compute node's physical hardware. The hypervisor's task is to handle physical resource sharing by allocating CPU, memory, and space among the virtual machines.

**container**

A container virtualizes the operating system, in contrast to a hypervisor. A container separates programs' user areas while enabling them to share a single kernel area. It is more complicated but lighter than a conventional hypervisor.

**bare metal**

Workflows are managed without virtualization by a bare-metal computing component. Each task operates on its own chunk of actual hardware.

## Security considerations of computing resources

The capability of a hypervisor or container virtualization to ensure complete separation between virtualized processes and programs is the most critical responsibility.

A hypervisor may fail to ensure a rigid separation in some situations. For example, it may be susceptible to a breakout attack, in which malware operating in one VM can escape the virtualized environment by having control of the virtualization software itself, thereby controlling all virtual machines handled by the same hypervisor.

As another example, a weak hypervisor may let one emulator access the information memory space utilized by another virtual machine on the same node.

A malicious actor might disable the cloud infrastructure by utilizing the CPU and RAM resources given by compute nodes. He or she may also degrade functionality for other clients. Because CPU and RAM components are not distributed across numerous workloads, this type of vulnerability is mostly applicable to dedicated computing hardware units.

It is critical to plan for this scenario, whether it is the result of malevolent purposes or just an out-of-control task or application.

## Conclusion

In this blog post, we learned that compute instances are at the heart of computational power. We also touched upon security implications related to computational resources.

:::{seealso}
Want to learn practical Cloud Security skills? Enroll in [MCSE - Certified Cloud Security Engineer](https://www.mosse-institute.com/certifications/mcse-certified-cloud-security-engineer.html)
:::
