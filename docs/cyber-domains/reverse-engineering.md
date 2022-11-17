---
myst:
  html_meta:
    "property=og:image": "https://library.mosse-institute.com/_images/reverse-engineering.png"      
---
(reverse-engineering-landing-page)=
# Reverse Engineering

Reverse engineering is the process of taking something apart and figuring out how it works. In the context of cyber security, reverse engineering can be used to figure out how a piece of malware works, or to find vulnerabilities in a piece of software. Reverse engineering is an important tool for security researchers, as it allows them to better understand how systems work and identify potential weaknesses.

## Free Video Course

If you're looking to get into reverse engineering, this is the course for you! MCSI's videos will give you the foundation you need to get started in this exciting and important field. You'll learn about the tools and techniques used by reverse engineers, and how to apply them in real-world scenarios.

### Chapter 1: Introduction to Reverse Engineering

- [Understanding file formats and magic numbers](https://youtu.be/qm33nCV1nkA)
- [Executable File Types in Windows and Linux](https://youtu.be/8Vbw3G1ogCo)
- [Lab Setup for Analyzing Malicious Files and Executables](https://youtu.be/m4f6FERPa2U)
- [What is Software Packing and Code Obfuscation?](https://youtu.be/9GrMRXFkIHQ)

### Chapter 2: File Analysis

- [How to investigate malicious Office documents](https://youtu.be/PSSulYstYzo)
- [How to investigate a malicious disk image file](https://youtu.be/yhiu3DRMqYI)
- [How to investigate a malicious batch script](https://youtu.be/J-gfE0Yt0s4)
- [How to investigate a malicious DLL](https://youtu.be/Im2Tx4hdWWg)

## Procedures

```{admonition} What is a workflow and why is it important?
:class: dropdown

A workflow is a series of steps that are followed in order to complete an engagement. In penetration testing, a workflow is important in order to ensure that all steps are followed in order to complete the testing process. By following a workflow, penetration testers can ensure that they are thorough in their testing and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn malware analysis:

```{thumbnail} ../images/procedures/malware-analysis.svg
:alt: Reverse engineering procedure and workflow
:class: block grey-border mb-5
```

## Techniques

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