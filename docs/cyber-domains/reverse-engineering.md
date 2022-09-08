---
myst:
  html_meta:
    "description lang=en": "This is a reverse engineering landing page"
    "type": "article"
    "category": "penetration-testing"
    "property=og:image": "https://6a42-78-174-36-228.eu.ngrok.io/_images/reverse-engineering.png"      
---

(reverse-engineering-landing-page)=
# Reverse Engineering

Reverse engineering is the process of taking something apart and figuring out how it works. In the context of cyber security, reverse engineering can be used to figure out how a piece of malware works, or to find vulnerabilities in a piece of software. Reverse engineering is an important tool for security researchers, as it allows them to better understand how systems work and identify potential weaknesses.

## Procedures

```{admonition} What is a procedure and a workflow and why are they important?
:class: dropdown
A procedure is a set of instructions that detail how to carry out a task. It is important to have procedures in place so that tasks can be carried out efficiently and consistently. Having a procedure ensures that everyone knows what needs to be done and how to do it. This can help to avoid confusion and mistakes.

A workflow is a series of steps that are followed in order to complete an engagement. In reverse engineering, a workflow is important in order to ensure that all steps are followed in order to complete the reverse engineering process. By following a workflow, reverse engineers can ensure that they are thorough in their analysis and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn malware analysis:

<img alt="Reverse engineering procedure and workflow" class="mb-5" src="/images/procedures/malware-analysis.svg">

## Techniques

```{admonition} Why do I need to learn reverse engineering techniques?
:class: dropdown
Techniques are important because they provide a means of achieving a desired outcome. They can be used to improve skills, to develop new ones, or to simply get a job done. There are many different techniques that can be employed, and the right one for any given situation depends on the goal. The most important thing is to select the appropriate technique and to use it correctly.
```

### Analyzing Portable Executable (PE) Files

The Portable Executable Format is a file format used for executables, object code, and DLLs. This format is used for 32-bit and 64-bit versions of Windows. The format is also known as PE32 (for 32-bit) and PE32+ (for 64-bit). The format is designed for use in Windows, and can be used by other operating systems.

* [](reverse-engineering-portable-executables-pe-part-1)
* [](reverse-engineering-portable-executables-pe-part-2)
* [](fuzzy-hashing-import-hashing-and-section-hashing)
* [](don-t-be-fooled-by-malware-in-disguise-identifying-obfuscated-malware)

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

```{admonition} Why do I need to master reverse engineering tools?
:class: dropdown
Reverse engineering tools are critical for malware analysis because they allow analysts to understand how malware works and identify its capabilities. By understanding the internals of malware, analysts can more effectively defend against it and develop countermeasures. Additionally, reverse engineering tools can be used to create signatures for detection purposes.
```

* [](tools-to-get-you-started-in-malware-analysis)
* [](introduction-to-debuggers-and-disassemblers)
* [](the-working-environment-of-popular-debuggers-and-disassemblers)

### YARA

YARA is a powerful tool for reverse engineering malware. It can be used to identify and classify malware, and to find and extract specific features from malware samples. YARA can also be used to create signatures that can be used to detect and block malware. 

* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-1)
* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-2)