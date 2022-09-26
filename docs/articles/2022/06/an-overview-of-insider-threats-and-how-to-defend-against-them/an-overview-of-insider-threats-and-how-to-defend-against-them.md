:orphan:
(an-overview-of-insider-threats-and-how-to-defend-against-them)=
# An Overview of Insider Threats and how to Defend Against them
 
An organization's own personnel pose one of the biggest threats to its security. Human error or negligence tends to be the leading cause of data breaches in an organization. A threat that can be particularly severe for the organization, aside from those brought on by gross negligence, is that posed by a malicious insider. Compared to external threats like hackers, internal threats to the company can have much more catastrophic repercussions. The basics of insider threats, their types, their impact on the organization, and the tactics for detection and prevention are covered in this article.

## What is an Insider Threat?

An insider threat is someone who has authorized access to an organization's assets or resources and utilizes that access to perform acts that potentially compromise the confidentiality, integrity, or availability of those assets, whether intentionally or accidentally. The term "insider threat" refers to a variety of threats that an organization may face from individuals who have legitimate access to its facilities or resources, including third-party suppliers, business partners, vendors, former employees, and many more. When compared to harm from external threats, the loss potential due to threats that originate from within the organization is significantly greater. As a result, it is crucial for the business to take these threats into account and lower the risk due to them. 

Although it may seem that all insider threats are malicious but that is not the case. Insider threats have different types depending upon the intent, motivation, awareness, and level of access that they have to the organization's critical assets or sensitive information. The following section describes different types of insider threats.

## Types of Insider Threats:

The different types of insider threats classified according to their intent are as follows:

### Turncloaks:

Turncloaks, also known as malicious insiders, are those who act with the aim of bringing harm to an organization for personal or financial gain. An example of a turncloak is a disgruntled employee who wants to exact revenge on the company because they feel they have been wronged by the employer or treated unfairly. This employee takes advantage of his access privileges to cause harm to the organization in a number of ways, including by stealing money, damaging infrastructure, stealing confidential data, and many other things.

### Collaborators:

Another type of malicious insider is a collaborator, who works with third parties such as a company's competitors to steal sensitive information such as intellectual property, trade secrets, or information regarding critical business functions. The goal of these attackers or threats is to obtain information that is very important to the business and the loss or exposure of such information could severely harm the company. These insider threats have the greatest loss potential and are the hardest to identify.

### Pawns:

Pawns are careless insiders who don't act with the intention to cause harm to the organization. These insiders are the ones whose mistakes or negligence can result in serious consequences for the organization such as heavy financial and reputational losses due to a data breach. One of the most common ways that an attacker can target such employees is through social engineering or phishing attacks. This usually occurs by sending malicious links to the employees through email and the user clicking on the link in the email leading to the compromise of user credentials or his workstation. Some other examples of employee negligence are failing to protect a device with sensitive information which makes it easy for the attackers to steal the device or using very weak account passwords that can be easily compromised.

## The Impact of Insider threats:

Through their effects on several areas of the organization, insider threats can have severe consequences for the business. These threats are most difficult to identify for a number of different reasons. One of the causes is that these insiders have legitimate access to the resources of the company. In other instances, malicious insiders are aware of the location of critical/sensitive data and how the organization's detective or preventative security mechanisms function. They can develop a successful strategy for the exfiltration of sensitive information with the help of this in-depth understanding of the organization.

Insider attacks become particularly dangerous if the users have access to the company's sensitive data or information regarding critical business functions. If a malicious insider has access to those assets or if an attacker can compromise the credentials of a privileged user then it becomes very hard for the company to recover from such incidents in a timely manner. The biggest downside of such attacks is the operational downtime losses suffered by the company due to the interruption in key business processes. The company may even go out of business if its incident response strategy is not strong.

According to the Ponemon institute's research titled ["2022 Cost of Insider threat Global Report"](https://static.poder360.com.br/2022/01/pfpt-us-tr-the-cost-of-insider-threats-ponemon-report.pdf), 56% of the security incidents experienced by the organization were due to human negligence, 23% were due to malicious insiders and 18% were those due to theft of credentials of a legitimate user. It also states that the average time to receive from a security incident due to an insider attack is 85 days. There has been a 7% increase in security incidents due to insider threats from the year 2020 to 2022. The annualized average cost to recover from an insider attack is $15.4 million. The increasing frequency and cost of insider attacks warrant a strong defense strategy leveraging a variety of security controls.

## How to detect Insider threats:

As previously stated, it is particularly challenging to identify insider attacks that are already underway, but with the correct set of controls, an organization may identify these incidents in a timely manner, contain them, and reduce the damage caused by them. The ideal mitigation technique for insider threats uses multiple layers of security controls as part of a defense in-depth approach. The methods listed in this section can be used to identify unusual or suspicious user behavior, which may be a warning indicator. The following are these methods:

### UEBA(User and Entity Behavior Analytics):

User and Entity Behavior Analytics commonly referred to as User Behavior Analytics is a data analytics technique that collects user-related network events over time and uses them to establish a baseline of normal user behavior. To create a profile of normal user behavior, these tools employ a variety of techniques like artificial intelligence and machine learning. The signs of unusual or suspicious user activity are then recognized using this collected data, and alerts are generated when a deviation from typical user behavior is detected.

When compared to other detection tools, UEBA solutions are better at detecting insider attacks because they put more emphasis on malicious user behavior rather than searching for indicators of compromise for a particular kind of attack. With the help of this detection capability, the company can identify the attack as it is unfolding and stop it from propagating throughout your network. The usage of these tools is therefore essential for businesses that keep a record of sensitive user information, such as those in the health or financial sectors. Here are some examples of anomalous user behavior that UEBA technologies can identify:

* Downloading and copying files containing sensitive information
* Accessing data that users are not required to access based on their job duties
* Attaching sensitive data in email 
*  Moving, copying, or, modifying a large number of files in a short period of time
* Searching the network for files containing sensitive information and much more.

### SIEM(Security Information and Event Management):

Security Information and Event Management tools are also very helpful in identifying suspicious user behavior. These systems can detect insider threats using a variety of indicators, including the ones listed below:

* By observing suspicious user behavior like multiple login attempts, logins made at odd hours, and other indications, SIEM can determine if the user credentials have been compromised.

* SIEM can detect abnormal privilege escalation attempts by monitoring systems holding critical information. SIEM can monitor the activities of the users who have access privileges on those systems and detect signs of privilege escalation attempts.

* By keeping an eye on user network activity and comparing it to indicators of compromise or attack for various types of malware, SIEM can spot the telltale signals of a compromised user account. SIEM can therefore determine whether a compromised user account is being utilized by a hacker to establish a command and control channel.

* By observing unusual user behavior, such as the attachment of sensitive information to user emails, the unauthorized attachment of external storage devices to workstations, such as USB drives, the moving or copying of sensitive files to unauthorized cloud storage, and many other actions, SIEM can spot signs of data exfiltration.

* SIEM can also detect the symptoms of ransomware attacks, which are typically conducted through a compromised user account. SIEM can spot anomalous user behavior like the simultaneous encryption of numerous files or an entire drive in a computer.

### PAM(Privileged Access Management):

Accounts with high-level or privileged access to an organization's resources exist in every organization. These accounts may be associated with system administrators or service accounts. A threat actor will only be able to access the data of that specific user if they manage to compromise a normal user account. However, they will have much more access and, depending on the account, might even be able to damage systems if they are able to compromise a privileged user account. Because they can exploit their access rights to steal or alter critical information, accounts belonging to privileged users are always a special target for attackers.

Privileged Access Management refers to the set of security policies and procedures that protect and monitor the use of privileged accounts within an organization. PAM tools can be set up to apply the policies and rules of the organization related to privileged user accounts. This gives the security administrators a platform to monitor and control the user activities related to these privileged accounts. As a result, any efforts to compromise the credentials associated with these accounts or any privilege escalation attempts can be quickly and effectively detected.

## How to prevent Insider threats:

Besides employing detective controls to detect suspicious user activity, it is very important to employ such controls that prevent insider attacks from occurring in the first place. Thus employing preventive controls along with the detective controls can effectively defend against these attacks. Some of the preventive strategies to stop insider attacks from taking place or minimize the damage due to them are as follows:

### Conduct Security Awareness and Training programs:

It is critical to develop and implement security awareness and training programs on a regular basis in order to prevent insider threats due to negligent or careless users. Security is about more than just using cutting-edge technology to combat attacks; it is also about addressing human behavior and educating an organization's employees about the consequences of their actions.

The organization's staff members need to be informed of the various strategies and methods employed by the malicious adversaries. For instance, if they get a suspicious email that asks them to click on a link, they need to know how to spot the telltale indications of a phishing attempt. They should also be urged to contact the appropriate authorities if they detect anything suspicious, such as an employee acting suspiciously or expressing resentment at the company's higher management. Finally, users should be trained on how to carry out their duties in a way that doesn't jeopardize the security of the organization's assets.

### Enforce Strict security policies:

Users' duties and responsibilities must be specified in detail in the organization's security policies, which must also impose severe penalties for breaking them or acting in a way that is against the organization's rules. This will go a long way toward ensuring that users behave in a way that doesn't put the organization's security in jeopardy. It will, to a certain extent, assist in discouraging fraudulent user activity as well.

### Implement the principle of least privilege:

Implementing appropriate access controls is one of the most efficient ways to stop or reduce the harm caused by an insider threat. The organization must accurately identify sensitive or critical assets, define different user roles, and specify the access privileges assigned to each role. These access permissions must be designed with the idea of least privilege in mind. According to the principle of least privilege, users should only be granted the minimum number of privileges required to carry out their job responsibilities. This makes it extremely difficult for attackers to gain access to sensitive/critical data even after they have compromised a user account.

### Enforce the Separation of Duties principle:

Enforce the separation of duties principle for critical business functions. The separation of duties principle ensures no single user has enough rights or permissions to complete a critical task. This principle is used to deter employee fraud or malicious activities and requires collusion to occur between two or more people to harm the organization.

### Implement the Zero Trust Architecture:

Implement the zero trust architecture in your organization to mitigate the risk due to insider threats. Zero trust is a security framework that requires all users to be authenticated, authorized, and assessed for compliance with specific security configurations before granting them access to the organization's resources. Enforcing the zero trust architecture is critical as more and more organizations are shifting towards remote work and hybrid could environments. It enables the organizations to prevent the compromise of a user account, loss of sensitive information, and much more through the use of controls such as multifactor authentication.

### Employ DLP(Data Loss Prevention) Solutions:

Employ Data Loss Prevention solutions to prevent the exposure or loss of sensitive information in the organization. DLP solutions ensure that users cannot intentionally exfiltrate or unintentionally send sensitive or critical information outside the corporate network. DLP products use an organization's security policies to assign labels to critical or sensitive company information. Thus these solutions protect the confidential data by preventing the users from transferring it outside the company's network.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::