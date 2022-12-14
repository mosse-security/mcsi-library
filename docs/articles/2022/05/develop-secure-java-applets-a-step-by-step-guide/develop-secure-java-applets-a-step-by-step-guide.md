:orphan:
(develop-secure-java-applets-a-step-by-step-guide)=

# Develop Secure Java Applets: A Step-by-Step Guide

Java applets have been used for a variety of purposes since they were first introduced in the 1990s. While they offer many benefits, they also come with some security risks. In this article, we'll show you how to develop secure Java applets.  By the end of this guide, you'll be able to confidently develop Java applets that are secure and can be run safely by your users.

Let’s start with some basics.

## What is Java?

Java was created by Sun Microsystems. It is a programming language that is used to create tiny apps (applets) for the Internet and independent programs. The goal of Java applets is to reuse code that already exists and enables programmers to design feature-rich apps.

### What are applets?

Applets are inserted into Web pages and are activated when the user's browser loads them into memory. Many operating systems, employ integrated interpreters to detect and parse Java bytecode included within applets.

**The Java Runtime Environment (JRE)**

The Java Runtime Environment (JRE) is a collection of programming tools, including the JVM, that is used to create Java programs.

**Java Bytecode**

Java bytecode is an intermediate binary language. Each operating system has a JVM that acts as an abstraction layer between the operating system and the running Java bytecode, allowing a Java applet to be written once and executed on several platforms.

**The Java Virtual Machine (JVM)**

The Java Virtual Machine is an implementation of the Java Runtime Environment. The Java Virtual Machine is a set of software that runs programs and sequences of instructions (which are denoted as "scripts"). It is a major, abstract component of the JRE that offers a runtime environment for Java bytecode execution.

Apart from providing an abstraction layer, the JVM performs some security actions, such as

- Code validation: JVM loads and checks the code for a predefined list of insecurities,
- Sandboxing: JVM executes the code in a reserved block of memory and isolates it to restrict the damage a malicious program may create on your system, which is called sandboxing.

## How to secure Java applets for developers

**Creating Safe Java Applets**

- You can protect your code by enabling code signing. Code signing entails digitally signing an item to demonstrate to users that it was provided by you and that the code has not been changed since its creation.
- A certified Java applet does not ensure that it is free of security flaws. Sandboxing is used by the JVM to limit the amount of harm a Java applet may do to a user's computer; but, when it is digitally signed, it is permitted to escape the sandbox and get access to client resources.
- The security policies defined on the local client determine the degree of access signed Java applets will have on a user's machine.

The two approaches that a developer may adopt to increase the level of security within their Java applets are as follows:

- Use safe coding methods. Following safe coding techniques reduces the number of vulnerabilities in Java applets.
- Java applets must be signed. Signing Java applets using a certificate issued by a trustworthy CA ensures that they are not tampered with once they are published on the Internet.

**Protecting Java Applet Execution**

The JVM has a built-in Security Manager, which regulates the number of limitations put on processing Java bytecode. A security manager is an item that specifies an application's security policy. This policy defines activities that are dangerous or confidential.
This contains the code that must be executed in a sandbox.

However, developers were not content with the limited functionality of the program. A temporary solution was implemented which let digitally signed Java applets exit the sandbox. From this point on, your local computer could manage these applets via security policies.

You can follow these guidelines to secure the running of Java applets in your local environment:

- Ensure that systems are patched on a regular basis. Java applets are produced by a variety of third-party companies, and you must be vigilant in verifying that the most recent security updates have been implemented to address vulnerabilities.
- You must verify that updates for Java applets generated by third parties are obtained by the originating vendor.
- Make use of Java security policies. Local security policies can be used to limit the degree of access that downloaded Java applets (including signed applets) have on your machine.
- Avoid clicking on tricky links or visiting unfamiliar websites. User attention is a critical component of Java security. Avoiding unfamiliar sites and links can be an effective strategy to avoid the execution of malicious malware.

## Conclusion

It should be clear now why we need to secure our code development process. We are also clear what actions we can take prior to applet execution, and how to safeguard our local environment while focusing on development. How secure is your Java applet?

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::
