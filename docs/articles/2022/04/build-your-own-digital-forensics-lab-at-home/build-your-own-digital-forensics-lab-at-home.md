:orphan:
(build-your-own-digital-forensics-lab-at-home)=

# Build your own Digital Forensics lab at Home!

Have you always dreamed of being a Digital Forensics and Incident Response Professional? You are new to the field, you have been applying for jobs, but companies are demanding some experience in the field. You have decided to learn some skills by setting up your very own DFIR lab at home. This blog post will help you get started!

## How will setting up my own lab benefit me?

An astronaut can consider being selected for a space mission only if they meet the physical fitness requirements. In order to meet those requirements, the astronaut has to train for hours in simulated environments.

In the same way, for a DFIR professional to be assigned to a field mission, they must prove their technical abilities. One way to improve technical skill is to practice in a lab at home.

## Tools Required

This section outlines the most important hardware and software tools required for your lab.

**Desktop or Laptop:** The minimum hardware requirement is a desktop or a laptop with at least 750 GB of hard disk space and having 16 GB RAM. You can even use virtual machines in the free tier offered by cloud providers like AWS, GCP or Azure.

Your hardware can run Windows or Linux-based or Mac operating system.

**Virtualization Software:** Let’s assume you have a laptop running Windows and you require access to a Linux-based machine. You can quickly set up virtual machines using virtualization software like VirtualBox or VMWare. If your system is able to handle at least two virtual machines at a time, that would be great.

**Documentation Tools:** During a forensic investigation, a professional is expected to document every activity performed. At the end of the investigation, all the documented information is presented in a report. You can read more about the importance of DFIR reports _[here](https://blog.mosse-institute.com/digital-forensics/2022/04/20/writing-digital-forensics-reports.html)_.

Since documentation is so important in forensics, while practicing in your home lab, you can also get acquainted with documentation. Be aware of how a good report can be constructed using word processing software. You can even create a DFIR report template that saves time during an actual investigation. Get familiar with how screenshots can be taken and included in your reports.

Documentation is as important as the task performed. Having the ability to write a good report will set you apart as a professional. When you complete any small task, you can type up a report with your findings.

**Other software tools:** Depending on the task you are working on you can download software tools as you progress.

## My DFIR lab is set up. What shall I do next?

Now your lab is all set up! Here’s what you can do next.

Pick a topic to explore. Identify suitable resources on the internet and wonder, ‘How can I perform this task practically in the field?’. Figure out how to do that. Here is an example:

Let’s assume you are investigating a Windows computer affected by malware. The computer is not behaving as expected and you have been tasked with identifying the binaries executed on the system recently. How can this be done? One way is by identifying and processing the prefetch files using special tools.

On Windows machines, Prefetch files indicate which binaries were executed on a system recently. You can read more about prefetch files _[Windows Prefetch Files May be the Answer to your Investigation](windows-prefetch-files-may-be-the-answer-to-your-investigation)_.

How can you practice processing prefetch files?

1. Run an application on your computer. Say `firefox.exe`
2. Perform some activities on it
3. Acquire the prefetch file for Firefox from your computer
4. Identify which tool can be used to process the prefetch file.
5. Use that tool to process Firefox’s prefetch file and see what evidence you can gather about recent activity

This one is just one example! Some other topics that you can explore are:

1. Acquiring evidence from a Windows machine. You can read more about it _[Performing digital forensics on a windows machine – where do I start?](performing-digital-forensics-on-a-windows-machine)_
2. Acquiring evidence of web browser activity from a Linux machine
3. Identifying commands that were typed recently on a Windows or Linux-based or Mac machine
4. Acquiring and analyzing memory from a machine

A good training program guiding you to gain fundamental practical skills would greatly benefit your career. MCSI’s _[DFIR Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)_ guides a student towards gaining practical skills across various important areas in digital forensics.

## Best Practices to maintain your DFIR home lab

Some steps need to be followed to ensure that your lab remains functional for a long time.

**Antivirus:** Ensure that you use verified antivirus software to protect your system and data.

**Backup:** Take regular backups of your important files.

**Maintenance:** Make sure that you sort your files and directories for easy access. Use file names that help you to easily identify what the file contains. Most of the major operating systems allow up to 255 characters in the file name. Use it to your benefit.

All these practices will be useful when you dive into the professional world.

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**
