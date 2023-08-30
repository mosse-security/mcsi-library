:orphan:
(containers)=

# Containers

Containers are similar to virtual machines, in that they allow an operating system (or application) to be virtualised, allowing it to run on shared platform. Whereas Virtualisation enables multiple OS instances to coexist on a single \*hardware\* platform containerisation allows an application or even OS to run on a shared operating system, with its components separated from the main kernel. This means that in the same way multiple virtual machines can run on a single host, multiple containers can share an OS, yet have separate memory, CPU, and storage threads, guaranteeing that they will not interact with other containers  

 

## What are Containers?

Containers have recently become a go-to solution for flexible deployment off apps and programs without the need to deploy an entire virtual machine. Arguably, containerisation has transformed the way software is developed, deployed, and managed. They are portable, lightweight, and isolated units that package an application along with its dependencies, libraries, runtime, and configurations – allowing users to simply download an install a fully working product with a minimum of configuration. 

Unlike traditional methods where applications are tightly coupled to the host operating system, containers provide a consistent environment that ensures applications run reliably across various stages of development, testing, and production. The isolation of the core processes associated with a container also means that the underlying OS should be unaffected by any instability or crashes within the container itself. 

 

## Containers vs. Virtual Machines

Containers and virtual machines serve distinct purposes – choosing between the two usually means striking a balance between resource efficiency and isolation. VMs simulate an entire operating system on a host machine, consuming more resources and requiring the host to be hardened just as would be the case with a physical machine. Containers, on the other hand, share the host's operating system kernel, making them smaller, faster to launch, and more resource-efficient. Containers also present a smaller attack surface, and, arguably, provide an attacker with a reduced ability to pivot within an environment, not least because they must first escape a compromised container!  Containers are ideal for applications with modular architectures, such as microservices, where individual components can be containerized and scaled independently.



### When to Use Containers

Containers excel in scenarios where agility, scalability, and consistency are of high importance. They are a natural fit for microservices architectures, enabling teams to develop, test, and deploy services independently. Containers also facilitate DevOps practices by ensuring consistency between development, testing, and production environments. They can also be useful for modernizing legacy applications by containerizing them, making them more manageable and portable – although this process itself can be complex which is worth factoring into any conversion decisions. 



### When to Use VMs

Since containers share a common OS, VMs are better suited for scenarios that require full isolation, compatibility with different operating systems, and distinct security boundaries. If legacy software demands a specific operating system version or when applications require separate kernel-level isolation, VMs provide a stronger security boundary. Additionally, VMs are preferable for running applications with varying resource requirements on the same physical hardware.

 

## Security Risks and Best Practices with Containers

Whereas virtual machines are separate instances of an operating system, containers offer logical isolation but share the host OS kernel. This shared kernel does introduce potential security concerns. If one container is compromised, an attacker might exploit vulnerabilities to gain access to other containers or the host system. Implementing container security best practices is essential – the specifics will depend on the container engine, as well as the application it is hosting, however in general points to consider include: 

**Container Images**

- Use official and trusted base images whenever possible.
- Keep images small and optimized by minimizing unnecessary packages and files.
- Regularly update base images and dependencies to include the latest security patches.
- Use version tags for images to ensure reproducibility and avoid relying on "latest."
- Utilize multi-stage builds to create smaller and more secure final images.

**Security** 

- Implement the principle of least privilege for container permissions.
- Run containers with non-root users to limit potential security vulnerabilities.
- Isolate containers using proper network configurations and firewall rules.
- Use container runtime security tools to monitor and protect against vulnerabilities.
- Regularly scan container images for known security vulnerabilities.

**Deployment** 

- Use container orchestration platforms like Kubernetes to manage deployments at scale.
- Design applications with statelessness in mind, allowing easy scaling and recovery.
- Implement rolling updates to minimize downtime during application updates.
- Leverage environment variables and secrets management for sensitive information.
- Implement health checks to ensure applications are running and responsive.

**Monitoring and Logging** 

- Implement centralized logging to gather container logs for analysis and troubleshooting.
- Utilize container monitoring tools to track resource utilization and performance.
- Implement alerts and notifications to proactively respond to anomalies or issues.
- Monitor and manage application metrics to ensure optimal performance.

**Networking and Service Discovery**

- Utilize container networking models to isolate and secure communication between containers.
- Implement service discovery mechanisms to allow containers to locate and communicate with each other.
- Use load balancers to distribute traffic across container instances for high availability.
- Implement network policies to control traffic flow between containers.

**Scalability and Resource Management** 

- Design applications to be horizontally scalable to take advantage of container orchestration platforms.
- Implement auto-scaling based on application demand and resource utilization.
- Configure resource limits and requests to ensure fair resource allocation among containers.
- Monitor resource utilization and performance to optimize container placement and scaling.

**Backup and Disaster Recovery** 

- Regularly back up container data and configuration to prevent data loss.
- Implement a disaster recovery plan that includes application recovery and data restoration.
- Store backups offsite or in a separate location to protect against site failures.

**Development and CI/CD** 

- Implement container-based development environments to ensure consistency across stages.
- Use version control and automate builds to ensure reproducibility.
- Incorporate continuous integration and continuous deployment (CI/CD) pipelines for efficient application delivery.
- Automate testing, including security scans, unit tests, and integration tests, within the CI/CD pipeline.

 

 

## Container Engines

While docker is the container engine most strongly associated with containers – and the organisation behind much of it’s rise to popularity, today there are a variety of container engines to choose from. Some key ones to be aware of include: 

- **Docker -** Docker popularized containerization by providing a platform for creating, distributing, and managing containers. It includes Docker Engine, a runtime for running containers, and Docker Hub, a registry for sharing container images.
- **Kubernetes -** Kubernetes is a powerful container orchestration platform that automates deployment, scaling, and management of containerized applications. It abstracts away the complexity of managing multiple containers across clusters of machines, making it easier to deploy and scale applications.
- **OpenShift -** OpenShift builds on Kubernetes to offer additional developer and operational tools. It provides features like automated application builds, developer-friendly workflows, and integrated security.
- **Amazon ECS -** Amazon Elastic Container Service (ECS) simplifies container management within the AWS ecosystem. It supports Docker containers and integrates with other AWS services for seamless deployment and scaling.
- **Google Kubernetes Engine (GKE) -** GKE is Google Cloud's managed Kubernetes service. It offers automated updates, scaling, and monitoring, making it easy to deploy, manage, and scale containerized applications.

 

## Final words

Containers are an innovative technology which has provided some significant advantages in modern application deployment and management, offering agility, scalability, and consistency. They're particularly suited for microservices architectures and agile development practices. While containers are highly efficient, addressing security risks and selecting the right container orchestration platform are essential steps to ensuring a successful deployment – keep in mind the weaknesses of containers to help identify situations where virtualisation may be a better option.