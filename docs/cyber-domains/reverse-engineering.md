---
myst:
  html_meta:
    "property=og:image": "https://library.mosse-institute.com/_images/reverse-engineering.png"      
---
(reverse-engineering-landing-page)=

# Reverse Engineering

```{admonition} What is Reverse Engineering?
:class: dropdown

Reverse engineering is the process of taking something apart and figuring out how it works. In the context of cyber security, reverse engineering can be used to figure out how a piece of malware works, or to find vulnerabilities in a piece of software. Reverse engineering is an important tool for security researchers, as it allows them to better understand how systems work and identify potential weaknesses.
```

## Free Video Course

If you're looking to get into reverse engineering, this is the course for you! MCSI's videos will give you the foundation you need to get started in this exciting and important field. You'll learn about the tools and techniques used by reverse engineers, and how to apply them in real-world scenarios.

### Chapter 1: Introduction

Welcome to the world of malware reverse engineering! If you're here, you likely already have a strong interest in understanding how malicious programs work and how to analyze them. In this course, we will explore the fundamentals of malware reverse engineering, including techniques to identify, analyze, and respond to threats. We'll learn common tools and strategies used by security professionals to detect and defeat the latest malicious code. Get ready to expand your knowledge and take your security skills to the next level!

- [Introduction to Reverse Engineering](https://youtu.be/2ivjSOW9i_0)
- [Why do we reverse engineer software?](https://youtu.be/uaLpHA5gvfE)
- [What knowledge do I need to have to be a reverse engineer?](https://youtu.be/RMbq1RVInOU)
- [How does malware work?](https://www.youtube.com/watch?v=l09Y_P2Nd9M)
- [What are the main categories of tools we use for SRE?](https://youtu.be/BV4Su1wcwZM)
- [What is Software Packing and Code Obfuscation?](https://youtu.be/9GrMRXFkIHQ)
- [What is Systematic Approach to Malware Analysis (SAMA)?](https://youtu.be/r2qSO25wJBo)
- [Setting up a lab for Malware Reverse Engineering](https://youtu.be/uuEynyfZxUo)
- [Protocol for safely handling and sharing malware samples](https://youtu.be/G5L-Gdjm8ns)
- [Common IOCs to retrieve from Malware Reverse Engineering](https://youtu.be/vV8q7IvwoHs)

### Chapter 2: File Analysis

File analysis is an important step in malware reverse engineering. It involves the examination of a malicious executable file to determine the purpose of the file and how it works. This analysis typically involves looking at the file's structure, the code and data contained in the file, and any strings that may be present. The analysis may also include looking at the functionality of the file and any other files or processes that it may interact with.

- [Understanding file formats and magic numbers](https://youtu.be/qm33nCV1nkA)
- [Executable File Types in Windows and Linux](https://youtu.be/8Vbw3G1ogCo)
- [Lab Setup for Analyzing Malicious Files and Executables](https://youtu.be/m4f6FERPa2U)
- [How to create a good collection of malware samples](https://youtu.be/OTW2y1GomHE)
- [How to investigate malicious Office documents](https://youtu.be/PSSulYstYzo)
- [How to investigate a malicious disk image file](https://youtu.be/yhiu3DRMqYI)
- [How to investigate a malicious batch script](https://youtu.be/J-gfE0Yt0s4)
- [How to investigate a malicious DLL](https://youtu.be/Im2Tx4hdWWg)
- [Use Resource Hacker to retrieve a malware's resources](https://youtu.be/Bj56T84n2hU)

### Chapter 3: Classification Analysis

Classification analysis is an essential technique used in Malware Reverse Engineering for categorizing malware samples based on their structural and content-related characteristics. This process involves examining the properties and features of the file without executing it or disassembling its code.

- [Use the Linux 'file' utility to recover file types](https://youtu.be/2_HkFx_FpMg)
- [Use PEStudio to analyze malware](https://youtu.be/7yKLn27i72E)
- [Use file hashes to identify and classify malware samples](https://youtu.be/NjSuZJc9tUU)
- [Use YARA to identify and classify malware samples](https://youtu.be/CJSdSd6IAnA)

### Chapter 4: Dynamic Analysis

Dynamic analysis is a crucial technique used in Malware Reverse Engineering for examining the behavior of malware samples in a controlled environment. Unlike static analysis, which involves examining the properties of a file without executing it, dynamic analysis involves executing the sample in a sandboxed environment to observe its behavior and interactions with the system.

- [Introduction to Dynamic Analysis](https://youtu.be/m6L-Cfj8nt4)
- [Automated malware analysis with Cuckoo Sandbox](https://youtu.be/TbB0my32DOE)
- [Analyzing malware samples with ProcMon](https://youtu.be/GpUIcYbOigg)
- [Use Sysmon to analyze a malware sample](https://www.youtube.com/watch?v=tUGtlFqZCUg)

### Chapter 5: Static Analysis

In this section of the video course, you will learn about the various tools and techniques used for static analysis, such as disassemblers, decompilers, and hex editors. We will also discuss how to analyze different aspects of a file, including its file header, strings, and code segments. By the end of this section, you will have a strong understanding of how to perform static analysis on malware samples and identify potential threats to the system.

- [Extracting and analyzing strings from a malware sample](https://youtu.be/Ig-JvkkSQBY)
- [Decompiling .NET code using ILSpy](https://youtu.be/RKfbdIqi0tw)

### Chapter 6: Windows Internals

In this section, we delve into Windows Internals from the perspective of reverse engineering. Gain a deep understanding of the internal mechanisms and structures of the Windows operating system, focusing specifically on how they can be leveraged for reverse engineering purposes. Explore key concepts such as process and thread management, memory allocation, DLL injection, hooking, and more. By uncovering the inner workings of Windows, you'll develop the knowledge and skills necessary to analyze and manipulate software at a low-level, opening up a whole new world of possibilities for reverse engineering and vulnerability research.

- [Kernel mode vs. user mode](https://youtu.be/r440y3cICRA)
- [Windows Processes](https://youtu.be/y35pdF4RgFM)
- [Windows Threads](https://youtu.be/eKJY7ywSMtQ)
- [Windows Services](https://youtu.be/G2v-dEagPxQ)
- [Access Control Lists](https://youtu.be/94hUPK0VzIc)
- [Users and Groups](https://youtu.be/uW8BB7et8AE)
- [Shared Memory](https://youtu.be/tts-LEAHvxY)
- [Drivers](https://youtu.be/qOTyWFWP8F4)
- [Virtual Memory](https://youtu.be/k2eLBIMTYZY)
- [Jobs](https://youtu.be/HDVsCsWHI9A)
- [Objects and Handles](https://youtu.be/Z0KAVdzgXfE)
- [Registry](https://youtu.be/HZP4olITTlc)
- [Elevation](https://youtu.be/YsoTXPSj3kc)
- [Access Tokens](https://youtu.be/uOemcVMhj88)
- [Remote Procedure Calls](https://youtu.be/nw7UCa8ShII)
- [Windows APIs and System Calls](https://youtu.be/FhQR_oMn2NY)

### Chapter 7: Windows Programming

In this section of the course, we'll delve into Low-Level Windows Programming, focusing on Win32 APIs. This will help you understand the basics of how Windows works and how to interact with it using these programming tools. It's a foundational step if you're interested in exploring the intricacies of Windows programming.

- [What are Windows APIs?](https://youtu.be/uJ2rNnpsnqA)
- [Categories of Windows APIs](https://youtu.be/iaPpn8OhA1c)
- [Writing a C program that interacts with Windows APIs](https://youtu.be/186DxHxNxoA)
- [Writing a Python program that interacts with Windows APIs](https://youtu.be/BEJ380ucq94)

## Articles

Reverse engineering techniques can be applied to any system, but are commonly used on software and hardware. There are a variety of reverse engineering techniques, each with its own strengths and weaknesses.

### Analyzing Portable Executable (PE) Files

The Portable Executable Format is a file format used for executables, object code, and DLLs. This format is used for 32-bit and 64-bit versions of Windows. The format is also known as PE32 (for 32-bit) and PE32+ (for 64-bit). The format is designed for use in Windows, and can be used by other operating systems.

* [](reverse-engineering-portable-executables-pe-part-1)
* [](reverse-engineering-portable-executables-pe-part-2)
* [](fuzzy-hashing-import-hashing-and-section-hashing)
* [](don-t-be-fooled-by-malware-in-disguise-identifying-obfuscated-malware)
* [](analyzing-malicious-code-without-reverse-engineering-the-assembly)

### Dynamic Analysis Techniques

Dynamic analysis is the process of reverse engineering a software program by observing its behavior at runtime. This can be done by running the program in a debugger and observing its execution, or by instrumenting the program to log its behavior. Dynamic analysis can be used to understand how a program works, to find bugs, or to perform security analysis.

* [](introduction-to-behavior-analysis-techniques)
* [](fileless-malware-a-new-type-of-malware-that-doesnt-rely-on-executable-files)
* [](identifying-malware-persistance)

### Static Analysis Techniques

Static analysis techniques are used in reverse engineering in order to understand the structure and function of a given system. By analyzing the code and data of a given system, reverse engineers can better understand how the system works and identify potential security vulnerabilities. Static analysis techniques can be used to reverse engineer any type of system, including software, hardware, and firmware.

* [](reverse-engineer-malware-without-the-risk-of-infection)


### Malware Injection Techniques

Malware Injection Techniques are used by attackers to insert malicious code into a legitimate process or file. This allows them to gain control of the system and perform various tasks, such as stealing data, launching denial of service attacks, or creating a backdoor. There are several ways to inject malware, including buffer overflows, process injection, and DLL injection. Attackers often use these techniques to exploit vulnerabilities in software and gain access to systems.

* [](malware-injection-techniques-introduction)
* [](malware-injection-techniques-process-hollowing)
* [](malware-injection-techniques-thread-execution-hijacking-and-setwindowshookex)
* [](malware-injection-techniques-apc-injection)
* [](malware-injection-techniques-atombombing-ewmi-nttestalert)
* [](malware-injection-techniques-api-hooking-techniques)

## Tools

There are a number of different tools that can be used for reverse engineering. These tools can be used to decompile code, to extract information from binaries, and to analyze data. Reverse engineering tools can be used to understand how a system works, to find vulnerabilities, and to create new programs that work with the system.

* [](tools-to-get-you-started-in-malware-analysis)
* [](introduction-to-debuggers-and-disassemblers)
* [](the-working-environment-of-popular-debuggers-and-disassemblers)
* [](know-your-malware-classification-is-key-to-understanding-purpose-and-function)

### YARA

YARA is a powerful tool for reverse engineering malware. It can be used to identify and classify malware, and to find and extract specific features from malware samples. YARA can also be used to create signatures that can be used to detect and block malware. 

* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-1)
* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-2)

## Workflow

```{admonition} What is a workflow?
:class: dropdown

A workflow is a series of steps that are followed in order to complete an engagement. In penetration testing, a workflow is important in order to ensure that all steps are followed in order to complete the testing process. By following a workflow, penetration testers can ensure that they are thorough in their testing and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn malware analysis:

```{thumbnail} ../images/procedures/malware-analysis.svg
:alt: Reverse engineering procedure and workflow
:class: block grey-border mb-5
```