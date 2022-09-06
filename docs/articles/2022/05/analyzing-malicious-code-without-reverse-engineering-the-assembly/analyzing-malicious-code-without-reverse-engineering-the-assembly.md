:orphan:
(analyzing-malicious-code-without-reverse-engineering-the-assembly)=

# Analyzing malicious code without reverse engineering the assembly

When evaluating malicious code, there are various tools threat hunters can use to aid their investigation. One method to understand the behavior of suspicious files is to disassemble them. However, not everyone has the time or ability to learn assembly to comprehend a suspicious binary's function. By using the Microsoft technical documentation site and knowing the malware's capabilities, a threat hunter can make a more informed decision on the behavior of a suspicious file.

## Microsoft Technical Documentation

The [Microsoft technical documentation](https://docs.microsoft.com/en-us/) (MTD) contains information about the functions that are native to the Windows operating system. The documentation is mainly used by developers when writing windows-based programs. However, it is also an invaluable source of information for threat hunters. The majority of functions used by Windows is well documented on the MTD website. By combining the wealth of information within the MTD and knowing how malware works, a threat hunter can obtain a significant amount of information about a file to help with making an informed decision on whether it is benign or malicious.

A hunter must become familiar with the MTD website and learn to interpret common functions of windows executables. Some may perform activity that seems obvious based on the name, though it may have a different purpose. For example, the [CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) function does create a file. However, it is also used to 'open' an existing file. The distinction and knowing the function's behavior are important so that the hunter doesn't make improper conclusions. That could lead to going down rabbit holes and trying to find what file was created by the malware only to learn it simply opened an existing file.

Other functions may not seem evident with what it does, though it should not be ignored. For example, the function [WTSQuerySessionInformationA](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationa) is used to query a Remote Desktop host for a given RDP session. While the function doesn't seem like it reads an RDP session, the mere fact that it has **Query** in the name provides some insight that it is enumerating or gathering information. _Note: 'WTS' is short for 'Windows Terminal Server'_.

Whenever a threat hunter doubts what a function performs, the MTD site should be consulted to help understand its role with a suspicious file. Also, the threat hunter should not jump to conclusions based on the name of a function. They must be confident they understand what the function does before making assumptions and leading to incorrect conclusions.

## Using Yara

Yara is a tool that can be used to read the functions of a suspicious file, unless it was packed. Packing an executable cause the functions to be hidden due to the compression packers use. A good task for threat hunters is to learn the various behaviors of malware and search the MSDN documentation to know what functions are used to perform that behavior. For example, a Yara rule could be created to search for the _WTSQuerySessionInformationA_ function. If that function is found, it provides information about the file's capabilities. However, other questions must be answered to give context to the file's use of the function. Is it under _C:\Users\Public_ or located in a user's profile's _temp_ directory? Those would be suspicious. Is the file located within the _C:\Program Files_ directory in a subdirectory of the organization's known programs? It may or may not be suspicious, so further questions need to be answered. Is the program under _C:\Program Files_ legit? Is one of its features to use Remote Desktop or other Windows remote access features? While one function like _WTSQuerySessionInformationA_ shouldn't be used to draw conclusions by itself, it is a strong indicator of the behavior of the suspicious file. Along with _WTSQuerySessionInformationA_, other functions will help the threat hunter make an informed decision.

There are dozens of Windows functions that can be used to create a ruleset with Yara and scan files to help determine its behavior. The functions a hunter chooses to search on will be based on what their organization deems as suspicious behavior, come from known threat actor IOCs, or reports from malware analysts and threat intelligence sources. Some may want to scan for all files that have the ability to run as an administrator or perform specific functions such as enumerating the host or using network sockets, potentially to exfiltrate data.

## Automated analysis

Keeping up with the thousands of functions in Windows is not feasible. Well-written Yara rules with thorough documentation can provide information about what the function performs so the threat hunter doesn't have to keep searching for functions, especially ones they may not see often.

Mandiant has a tool called [capa](https://github.com/mandiant/capa) to aid a threat hunter. The capa tool searches through an executable and prints out information that helps explain the file's behavior. The GitHub repo for capa explains how it works in-depth and provides a sample report. One of the more impressive screenshots on the capa GitHub page is a side-by-side screenshot of IDA Pro and a capa report to show the level of detail it provides in context to a well-known disassembler. Capa can be used as a good starting point for a threat hunter to provide a fast analysis of files. The report created could be used to help the threat hunter generate more hypotheses on where and what to search for within the organization.

Similarly, a threat hunter could use capa to determine if a deeper analysis of the file is necessary. Whether it is performed by the hunter or passed on to malware analyst, capa can provide a detailed insight into a file without having to search for each function. Mandiant is a leading malware research organization and have created a program that can read the libraries a file imports and aid in the process of determining the behavior of a file.

## Conclusion

As a threat hunter, it is important to understand the various techniques that can be used to analyze malicious code. While assembly and reverse engineering are important skills, they are not always necessary. The Microsoft documentation for their API is extensive and can undoubtedly provide details that a hunter needs to make an informed decision on a suspicious file. Utilizing tools like capa and Yara can help provide information about the behavior of a file to help support a hypothesis or used to create further hypotheses.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**
