:orphan:
(a-brief-overview-into-containers-and-the-challenges-they-address)=
# A Brief Overview into Containers and the Challenges they Address
 

This blog article will provide you with an overview of containers and how they affect the overall information technology environment.

## Introduction

Containers tackle the most essential challenge in modern computer systems: executing dependable, decentralized software with high scalability. This introduced a completely new field in software development known as microservices. In addition, they have pioneered a _deploy once_ concept in technology.

## Issues that brought us to containers

Let's start by defining containers in plain terms.

- A piece of software travels through various settings in a typical software development life cycle (SDLC), and different programs may share the same operating system. Because the setup of the systems may change, software that functions in a development environment may not function in another environment such as a test environment.

- Furthermore, when numerous programs are executed on a single system, there will be no segregation between them. One program can consume the computing resources of another, which can cause performance issues. Because repackaging and redesigning apps is necessary throughout every stage of implementation, it requires a significant amount of time and effort and is potentially error-prone. Containers address these issues by isolating application and compute resource management, giving an appropriate solution for these problems.

- The most difficult problem for the software business is to offer application segregation and handle project resources so that they may operate on any system, regardless of the operating system (OS) or the underlying infrastructure.

Software is created in a variety of programming languages and employs a variety of external dependencies and frameworks. That results in a scenario known as the "matrix of hell."

## The matrix of hell

Assume you're putting together a server that will host different applications for various departments. Imagine you don't have a virtualized environment and must operate all these on a single physical system. Because one program utilizes one version of an external dependency while the other uses another, you wind up maintaining two different versions of the same program in a single system. As you grow your infrastructure to handle numerous apps, you will be maintaining a huge number of dependencies and different versions for each application. It will gradually become unsustainable inside a single physical environment. This dilemma is known as the "matrix of hell."

There are several strategies that emerge from the matrix of hell, but two major technological achievements are virtual machines and containers.

Lastly, let’s take a brief look at the two.

### Virtual machines

A virtual machine replicates an operating system by utilizing Hypervisor technology. A hypervisor could operate in two ways:

- either as a program on a host operating system
- or as firmware on a computer.

On the hypervisor, virtual machines operate as virtual guest operating systems. This technology allows you to divide a large physical system into numerous small virtual machines, each tailored to a certain purpose.

### Containers

Containers address the matrix of hell without requiring a large guest OS level. Rather, containers encapsulate the program runtime and external dependencies to form an abstraction known as containers. You can have many containers running on the same operating system.

## Final Words

Upon completion of this blog post, you now know the importance of containers and the challenges they address.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::