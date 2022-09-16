:orphan:
(don-t-be-the-next-victim-understand-the-attack-lifecycle)=
# Don't be the Next Victim Understand the Attack Lifecycle
 
There are seven steps in the attack lifecycle that are present in most breaches. Although not every attack includes all seven steps, this lifecycle can be modified to meet any incidence. Additionally, an attack's phases don't necessarily occur in the sequence that is indicated by the attack lifecycle. This chapter introduces the idea of the attack lifecycle since it is crucial to consider occurrences in relation to the various stages of the lifecycle. You'll be able to comprehend the context of every newly uncovered action in relation to the overall compromise more clearly by thinking in terms of the different phases. Additionally, you should consider attacker activity in each phase of your repair planning. 

Below there is a brief explanation of each of the seven attack lifecycle stages.

- **Initial compromise**
  
It happens when the attacker successfully runs malicious code in the computer system. Initial compromises frequently happen as a result of social engineering, such spear phishing, or by taking advantage of a flaw in a system that can be accessed via the Internet. Attacks using social engineering frequently take advantage of a third-party program running on an end-user machine that is weak.

- **Establish foothold**
  
A recently compromised machine has remote access thanks to the attacker. This happens right after the initial compromise. Installing a permanent backdoor or downloading further binaries or shellcodes to the victim system are two common ways the attacker gains access.

- **Escalate privileges**
  
The attacker gains access to more systems and data than was previously available. Privilege escalation is often achieved through password hash or token dumping, which are followed by password, nonprivileged user access, extracting the currently logged-on user’s password, or using privileges held by an application, such as executing commands via Microsoft SQL’s xp_cmdshell extended stored procedure. This step also includes gaining access to non-administrative user accounts that have access to data or resources that the attacker requires.

- **Internal reconnaissance**
  
The attacker analyzes the victim's surroundings to gain a better understanding of the environment, crucial people's roles and responsibilities, and where critical information is kept.

- **Move laterally**

The attacker moves from system to system inside the compromised environment using the established foothold. Accessing network shares, using the Windows Task Scheduler to execute programs, using remote access tools such as PsExec and radmin, or using remote desktop clients such as RDP, Dameware, and virtual network computing (VNC) to access the systems' graphical user interface are all common lateral movement methods.

- **Maintain presence**

The attacker maintains access to the victim's surroundings. Installing many unrelated backdoors (including reverse backdoors and normal backdoors, such as webshells on Internet-facing computers), acquiring access to a VPN, and putting backdoor code in legal programs are common techniques of sustaining persistence.

- **Complete mission**

The attackers achieve their aim, which frequently involves data theft or change of existing data. Most targeted and persistent attackers do not depart the area after completing the goal, but instead keep access in case they are ordered to execute a new mission in the target environment. Throughout an incident, it is not unusual for an attacker to repeat many steps of the attack lifecycle. For example, an attacker committing credit/debit card fraud must steal and change data in real time.


## Conclusion 

Cyber-attacks are not going away. They have become the new normal. If you can be compromised, it is likely that you or your organization will be compromised over time. It is best to be prepared and armed in order to cope with any crisis as successfully as possible.

**Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**