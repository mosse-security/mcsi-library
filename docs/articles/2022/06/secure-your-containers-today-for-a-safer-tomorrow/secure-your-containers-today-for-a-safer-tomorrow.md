:orphan:
(secure-your-containers-today-for-a-safer-tomorrow)=
# Secure Your Containers Today for a Safer Tomorrow 

There are various ways to attack a containerized operation. In this article we will discuss a few basic vulnerabilities that could be present within a container.

Potential attack vectors can occur at every phase of a container's entire lifespan.

## Application code vulnerability

The life cycle begins with the app code written by a programmer. The code, as well as the 3rd party dependencies on which it relies, may have weaknesses known as vulnerabilities, so there are hundreds of publicly disclosed security flaws that an intruder may abuse.

Scanning the images is the ideal route to prevent running containers with common vulnerabilities.
It's not a one-time event because new threats in current programs are identified constantly.
The scanning process must also detect outdated packets. Certain scanners can also detect malicious code embedded within an image.

## Misconfigured images

After the program is written, it is packaged into a container image. While setting how a container image is produced, there are various alternatives to include vulnerabilities that can subsequently be exploited to target the live container. This can include setting the container to operate as the root user and granting it access to more resources on the host than it requires.

## Machine attacks

An attacker may change or affect the manner in which a container image is generated. In this situation, malicious code can be injected and executed in the test environment. Furthermore, gaining access to the test environment may serve as a basis for breaking into the production environment.

## Distribution chain attacks

After the container image is created, it is saved in a registry and then fetched, or "pulled" from the registry when you want to run it. Make sure the image you're pulling is identical to the one you committed and pushed earlier.

## Misconfigured containers

You may launch containers with privileges that are unnecessary and possibly unintended. If you receive YAML setup files from the internet, make sure they don't include any vulnerable settings before running them.

## Weak hosts

Containers operate on host computers, and you must make sure the users aren't executing susceptible code, such as earlier versions of orchestration elements with common vulnerabilities.

To reduce the attack surface, it's a great way to keep the number of applications running on each host to a minimum, and hosts must also be properly designed in line with efficient security mechanisms.

## Breached data

To interact with other elements of a system, application code frequently requires ids, tokens, or credentials. You must be able to feed these secret values into the containerized code in a container-based delivery. There are various methods for this, each with a distinct level of protection.

## Vulnerable network

Containers must interact with one another and with the public network in order to function.

## Container escape

Container escape is a potential threat in which bad actors can exploit weaknesses in a containerized program to violate its sandboxing environment, gaining access to the guest system's assets.

Most commonly used container runtimes, such as containers and CRI-O, are already quite seasoned. However, it's possible that problems have yet to be discovered that would allow malware executing within a container to jump onto the host.

## Conclusion

A container, despite its isolated environment, is not secure by default. The key considerations for protecting containers are: container host security, network traffic, image integrity, supply chain and machine security, as well as application code and credential security.

There are various things you can do for reducing the attack surface. Some of these include: 

- Scanning the images
- Detecting obsolete packets
- Configuring the container images to operate with the least rights during the packaging process
- Protecting your container from malicious actors both in the test and development environments
- Securing the image supply chain
- Checking `.YAML` files for any susceptible configurations, when downloaded from an untrusted source
- Keeping the apps running on a host machine at minimum
- Using robust sandboxing against container escapes.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**