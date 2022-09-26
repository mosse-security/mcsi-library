:orphan:
(make-memory-forensics-easier-with-volatility-profiles)=

# Make Memory Forensics Easier With Volatility Profiles

Every DFIR professional must have the ability to perform memory forensics. This includes acquiring _[memory dumps](uncover-crucial-information-within-memory-dumps)_, processing a memory dump for evidence and drawing conclusions for an investigation. Sometimes processing a memory dump is not a straightforward process. The investigator may have to perform some preliminary steps. This blog post discusses one of the preliminary steps which is sometimes performed before processing a memory dump for evidence.

## What is Volatility?

Volatility is an open-source tool that is used to process evidence from a memory dump. In fact, it is a framework that can process memory dumps acquired from Windows, Linux, Mac and Android systems. It cannot acquire memory, it can just process them. What do we mean by ‘processing’?

Volatility can extract information like list of active processes, list of network connections, information about loaded kernel drivers, etc. from the memory dump. Volatility uses _profiles_ for this.

## What are Volatility profiles?

It was mentioned that it is possible to find the list of active processes on the computer from which the memory dump was taken.

On the memory dump, information for a single process would be stored in C-style structures like this one:

```
struct process {
 int process_id;
 int parent_process_id;
 char name[10];
 long int create_time;
}
```

This structure is just a minimal representation. In reality, the structures will hold a lot more data. Structures would exist for every process. Likewise, similar C-style structures exist to hold kernel information, networking information, user information, etc.

These data structures vary across operating system type and version. The structure to hold the information for a process could be different on Windows, Linux-based and Mac computers.

When a memory dump is presented to Volatility for analysis, Volatility says two things:

1. I can find out what operating system type and version this memory dump has been taken from
2. I can interpret the information in the various C-style structures and present them to you in human readable form.

Volatility does this using _profiles_.

Now the entire volatility framework is written in Python. This means whatever information (C-type data structure) is acquired from memory, is processed using Python. Volatility uses profiles to interpret this information in Python. Profiles are simply mapping between the C-style structures to a V-type structure (specific to volatility).

The V-type structure for the C-style process structure introduced in the previous section, will look like this:

```python
'process' : [26, {
 'process_id': [ 0, ['int']],
 'parent_process_id': [ 4, ['int']],
 'name': [ 8, ['array', 10, 'char']]],
 'create_time': [18, ['long int']],
}]
```

Try to understand how the C-style structure is presented as a V-type structure that volatility can interpret. A V-type structure is simply made up of dictionaries and lists in python.

Do you want to look at a real V-type structure? Within the source code of volatility, navigate to the _volatility/plugins/overlays/<os>_ folder. You will find a number of python files. Look within one of those files – you will find large V-type structures specific to each operating system.

## Why should every DFIR professional know how Volatility profiles can be created?

Volatility already has pre-built profiles for most versions of the three major operating systems. The most recent OS versions for which volatility profiles exist, at the time of writing this blog post are:

- Windows 10 (including at least 10.0.19041)
- Windows Server 2016 (including at least 10.0.19041)
- 32-bit and 64-bit Linux kernels (from kernel version 2.6.11 to 5.5)
- 64-bit Mac OS Catalina

In some situations, the investigator may have acquired the memory dump from a computer for which a suitable Volatility profile does not exist. In that case, the investigator will have to manually generate a Volatility profile. Most Linux-based distributions use heavily customized versions of the vanilla Linux kernel. When investigating a memory dump acquired from a Linux-based computer, it is recommended to generate a Volatility profile for it.

## How to create Volatility profiles?

The main idea behind creating custom profiles in volatility is to have a profile that can identify the operating system and version from which the memory dump has been taken, can interpret the C-style data structures present in memory and parse them into human-readable form.

For this:

- The kernel data structures for the target OS must be acquired. This will be C-style structures
- The acquired structures must be converted to V-type structures that can be interpreted by Volatility
- The complete set of V-type structures for an OS constitutes a volatility profile
- Plug the generated profile into Volatility and use it to process the memory dump

There are specific tools to build volatility profiles for Windows, Linux-based and Mac operating systems.

## Project Idea

Here is a project idea for you. You can practice this on a virtual machine, so you will know what to do in case you have to perform this task in the field.

- Open some applications on an Ubuntu machine. Eg: terminal, text editor, web browser
- Acquire the memory dump from this machine
- Create a custom volatility profile for this machine
- Use Volatility to view the list of active processes in the memory dump. See if you can spot entries for the applications you had open, at the time the dump was taken

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MDFIR - Certified DFIR Specialist](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
