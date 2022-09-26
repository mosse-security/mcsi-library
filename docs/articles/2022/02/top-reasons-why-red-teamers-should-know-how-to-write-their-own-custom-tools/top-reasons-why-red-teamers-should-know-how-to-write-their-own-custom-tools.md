:orphan:
(top-reasons-why-red-teamers-should-know-how-to-write-their-own-custom-tools)=

# Top reasons why Red Teamers should know how to write their own custom tools

Red teamers should be able to write their own custom tools for a number of reasons. Custom tools can be more stealthy and harder to detect than off-the-shelf tools. They can also be tailored to meet the specific needs of the red team, such as specific protocol dissectors or payloads. Finally, custom tools can be used to build attack frameworks that make it easier to launch attacks against a target that requires original requirements.

## Stealthy and hard to detect

Malware authors have discovered a number of methods for hiding software from detection, one of which is to create custom tools.

Anti-virus businesses with complete knowledge of the code base are familiar with off-the-shelf products. Say goodbye to all those detections if you use custom tools with your own unique code.

## Harder to analyze and respond to

Most incident responders are well-versed in commercially available tools like Metasploit, PowerShell Empire, and Cobalt Strike. When you utilise custom tools, you force them to begin their analysis from scratch, with no existing knowledge to draw on.

They'll ask themselves key questions such as:

- What are the capabilities of this malware?
- Who is the author of this malware? What group use this malware sample?
- How do we remove this malware from the network?
- What is the severity of finding this malware on our network? Can we afford to ignore the threat?

If you used specific approaches to obfuscate your malware's code, the Blue Team will have to manually reverse engineer your samples and build deobfuscation scripts in order to retrieve the malware's logic. If they are capable of completing it, all of this might easily amount to hundreds of hours of work. That time advantage could mean the difference between the Red Team completing the operation or being thrown off the network before it is completed.

## The number one risk with writing custom tools

The major risk with writing custom tools is having all those tools eventually burnt. This happened to the NSA with Danderspritz and Mandiant's Red Team Tools (as well as other groups).

The Red Team should expect their tools to be discovered by security researchers or, in the worst-case scenario, exposed to the Internet by a real threat actor.

## The cost and effort of writing custom tools

It's trivial to create simple offensive security tools (assuming you know what you're doing!). The majority of the ones created by Red Teaming are between 50 and 1000 lines of code in length. They can perform highly specific tasks that off-the-shelf products can't deliver.

Writing a whole C2 framework from start and maintaining it, on the other hand, takes a lot of time and effort. The majority of commercial Red Teams do not try this feat. Nonetheless, we recommend that you develop a modest C2 framework at least once in your career for learning purposes in order to gain a thorough understanding of how this capability works.

## The right operational approach when relying on custom tools

The best Red Teamers have understood that the best approach is to combine off-the-shelf tools and custom tools.

Also, it is possible to augment off-the-shelf tools with custom capabilities, such as adding layers of obfuscation or implementing a unique code injection technique.

In high-risk phases of the operation, such as the first compromise, where security defences are primarily deployed, the technique consists of using off-the-shelf tools. If the Blue Team finds the tools, they won't be able to attribute them on the Red Team, and they won't be able to design new detection rules to prevent the tools from ever operating again.

In many cases, using various off-the-shelf technologies is the best solution. For example, let's use Metasploit to compromise a system, then Cobalt Strike to roam across the network, and finally PowerShell Empire as a backup link into the network! We can then use specialized tools to avoid detection or execute operations that would otherwise be impossible.

## Conclusion

There are numerous reasons why Red Team members should be able to create their own specialised tools. These include the capacity to carry out assaults fast and easily, modify attacks for certain circumstances, and conceal exploits and attacks from the Blue Team. Red Teamers can considerably improve their ability to carry out successful attacks against their targets by learning how to create bespoke tools.

Remember that combining off-the-shelf products with custom tools is the best strategy! This is how it's done by the pros!

:::{seealso}
Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html)
::: In this course, you'll learn about the different aspects of red teaming and how to put them into practice.**
