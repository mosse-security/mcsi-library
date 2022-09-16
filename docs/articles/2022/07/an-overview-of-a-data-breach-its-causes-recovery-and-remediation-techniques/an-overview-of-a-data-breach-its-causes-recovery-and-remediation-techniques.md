:orphan:
(an-overview-of-a-data-breach-its-causes-recovery-and-remediation-techniques)=
# An Overview of a Data Breach, its Causes, Recovery, and Remediation Techniques
 
Data is the major driving factor behind businesses worldwide. This data is stored in digital form by the organizations. Data is the most valuable asset of an organization as well as the prime target for attackers. This data is continuously being transferred over the internet which makes it possible for the attackers to compromise its security. The organization may suffer serious repercussions if the security of this data is compromised. 

Data breach costs increased from USD 3.86 million to USD 4.24 million in 2021, according to the Ponemon Institute's study on the statistics for data breaches. This represents the highest average overall cost in the survey's 17-year history. These figures highlight the need for a responsible and proactive strategy to lower the risk of data breaches in an organization. This article goes over the fundamental concepts related to the data breach, factors that contribute to a data breach as well as recovery and mitigation techniques. 

# What is a data breach?

A data breach can be defined as the loss, theft, or unauthorized exposure of the sensitive, confidential, or protected information/data owned by the organization. The stolen or exposed data may consist of financial information such as customers' credit/debit information, PII(Personally Identifiable Information) such as social security numbers, PHI(Protected Health Information) such as patient records, intellectual property such as a company's trade secrets and much more. A data breach can occur accidentally or intentionally. It can be the result of negligence on the part of the organization's employee or some cyber criminal hacking the organization's database. Either way, the loss or disclosure of such sensitive information can have serious consequences for the organization and affected individuals.

Organizations of all sizes are susceptible to data breaches. Organizations all over the world are becoming more and more dependent on digitally stored data, as well as the move toward cloud computing and remote work, rendering them open to many attack vectors. It is therefore imperative for the organizations to understand numerous ways through which this data can be leaked as well as take appropriate security measures to prevent data breaches. Over the years, several privacy rules and regulations have evolved, including GLBA, PCI DSS, HIPAA, and GDPR. These laws are intended to clearly outline the security and protection standards for the confidential customer information maintained by the company. Depending upon the sector in which the organization operates, it is required to adhere or comply with the relevant privacy laws and regulations.

## What is the impact of a data breach?

A data breach can have a significant impact on an organization that varies from financial to long-term losses. This section describes the major consequences of a data breach on an organization. 

### Financial Impact

Financial impact or financial losses are the most profound impact of the data breach. The magnitude of financial losses depends on the nature of the information that was leaked. These losses can include increased security measures, investigation of the breach, reactive steps to contain the breach, compensating those affected, such as customers, decreased share value, and legal or regulatory penalties. Although it is very difficult to predict exactly how much money will be lost due to a data breach, these losses can put a lot of burden on the company. As was already established, the average cost of a data breach worldwide is 4.24 million US dollars for the year 2021.

### Reputational Losses or Loss in the brand value

The reputation or brand value of an organization may suffer significantly as a result of a data breach. This can have a negative impact on client retention owing to a lack of faith in the business, poor media coverage, diminished employee loyalty, and other issues. The organization may have a difficult time repairing its damaged reputation as a result. The organization must proceed with each step after a data breach with extreme caution. Quickly notifying consumers, giving them satisfactory answers, advising them on the required actions they may take to stop additional damage, and ensuring them that steps are being done to contain the damage brought on by the data breach are some of the steps that can help the companies restore their reputation.

### Operational downtime losses

The critical business functions of the organization can be disrupted as a result of the data breach. This can result in major operational downtime losses for the company or even result in the company going bankrupt if appropriate security controls are not in place to recover from the data breach. According to the Ponemon institute's data breach statistics report for the year 2021, it took an organization an average of 287 days to discover and contain the damages due to data breaches. The average cost of a network outage is 5600 US dollars per minute according to the study conducted by Gartner in 2014. Depending on the company and sector in which it operates, this translates to average operational downtime losses between 140000 and 54000 US dollars per hour.

### Legal and Non-Compliance penalties

As mentioned previously, organizations are legally bound to comply with the different laws and regulations. The organization can incur losses in the form of regulatory fines post data breach. These losses can vary depending upon the type of data leaked, the sector and the geographical location of the company, and the incident response activities post data breach. If the organization operates in a highly regulated industry such as the healthcare industry, the losses suffered due to non-compliance will be significantly higher. The Ponemon Institute's report states that the healthcare industry suffered from the highest data breach losses for the 11th consecutive year. These high losses are due to strict privacy policies in the healthcare industry.

### Ransomware losses

Sometimes a ransomware component is present in a data breach, adding to the expenditures incurred as a result of the data breach. Companies are strongly discouraged in these circumstances from paying the ransom. However, since paying the ransom appears to be the simpler and safer choice, the majority of businesses choose to do so in exchange for the recovery of lost data and the avoidance of operational downtime losses, reputational damages, and legal penalties. The Ponemon Institute reported that the average cost of a data breach involving ransomware was USD 4.62 million.

## How can a data breach occur?

This section lists some of the most common ways in which a data breach can take place. 

### Compromise of user credentials

The theft of the user credentials of an authorized user is one of the most frequent ways that data breach takes place. The compromise of user credentials was the cause of 20% of data breaches that happened in 2021. Different methods might be used by the attacker to get hold of valid user passwords. Some of these methods entail either utilizing social engineering attacks or dictionary/brute-forcing attacks to decrypt user passwords that are too simple. An attacker will find it relatively simple to compromise user credentials by employing a variety of password cracking tools if the organization has lax password policies and permits users to use plain or weak passwords. An attacker can access confidential data within the firm by utilizing these stolen credentials. The attacker can then use a variety of exfiltration techniques to steal the data or encrypt it in order to launch a ransomware attack. Attacks through social engineering will be covered next.

### Social Engineering attacks

Attackers commonly employ social engineering attacks by taking advantage of human behavior and trust instincts in order to trick them into divulging sensitive information. One of the most common forms of these attacks is a phishing attack. An example of a phishing attack is a malicious link planted in an email to the victim user that aims to steal important user information such as his credentials. As soon as the user clicks on the link and enters his credentials on the attacker's website, these credentials are stolen by the attacker. While emails are the most common form of phishing attack, SMS text messages, and social media messaging systems are also popular with hackers. Once the attackers get a hold of these credentials, they can exploit them in different ways to cause further damage as mentioned previously.

### Broken or Misconfigured Access Controls

Broken or Misconfigured access controls can lead to the attacker getting hold of the company information in an unauthorized manner. This happens when the access control restrictions in the company's network, web application, or target system allow the attacker to access sensitive information in an unauthorized manner. For example, if a web application's underlying web server is not configured properly, then it may allow the attacker access to private files stored on the web server.

### SQL Injection Vulnerability

A SQL injection vulnerability allows an attacker to manipulate the inputs to a web application in order to send malformed queries to the underlying database server to elicit sensitive information. This vulnerability in some cases allows the attacker access to an organization's sensitive information. For example, an attacker can send malformed queries to the database server to retrieve private customer records stored in the database.

### Insider threats

An insider threat is a threat to the organization's assets that originates from the individuals that have authorized access to the organization's sensitive information such as third-party suppliers, the organization's employees, disgruntled former employees, rogue employees, and much more. Some of the examples of data breaches caused due to insider threats are as follows:

* An negligent employee divulging sensitive information such as his password falling victim to a phishing attack. This information can be exploited by the attacker to gain access to sensitive information about the organization.

* An attacker gaining access to an organization's data due to a compromised third-party application

* Organization's sensitive data stolen by a former employee as a form of seeking revenge on the organization.

* A rogue employee collaborating with the organization's competitor to steal the company's trade secrets.

### Malware infection

If an attacker is able to install malware on the organization's workstation or network then he can gain access to sensitive data being exchanged between nodes on a network and exfiltrate this information through a C&C(command and control network) server.

## What can you do to recover from a data breach?

Some of the steps that an organization can take to recover from a data breach are as follows:

* As soon as the company discovers that it has suffered from a data breach, it is necessary to identify what data has been compromised, how the data was compromised, and who was behind the attack. The company's incident response team must take the necessary steps in order to assess, contain, and mitigate the damage due to the breach. 

* The company should communicate with its legal team or seek external legal assistance. The legal team will advise the business on the federal and state laws that could be violated in the event of a breach.

* The business must engage forensic investigators to take forensic images of the affected systems, gather and examine the evidence, and specify corrective actions. By doing so, the organization will be able to identify the root cause of the data breach and produce proof in the event that the business faces legal issues.

* In case of a data breach the company may be required to notify the law enforcement agencies and the affected individuals. Depending on the type and the sensitivity of the information leaked, the company may be required to notify appropriate authorities. For instance, the GDPR privacy rule requires the organization to report the breach to relevant authorities 72 hours after its discovery. The notifications sent to the affected individuals must clearly state what happened(information that the company has gathered so far about the incident), the steps that the company is taking to remediate the issue, and what the customers can do to protect themselves from further harm.

* Last but not least, the organization must take the required steps to learn from the incident and make a sincere commitment to enhancing its security. By creating a sound security management system and using various strategies to deal with security issues in a proactive manner, the company must make sure that similar situations don't happen in the future.

## How can you prevent data breaches in your organization?

Some of the recommended strategies to prevent data breaches in your organization are as follows:

### Enforce the principle of least privilege

Organizations must ensure that their employees have access to only those resources that they need to perform their jobs. This will help reduce some of the damage in case the attacker is able to compromise an authorized user's credentials.

### Conduct Security awareness and training programs

Most data breaches occur due to the negligence of the organization's employees. Therefore it is necessary that the organization regularly conducts security awareness and training programs to educate their employees about different techniques employed by the adversaries and what they can do if they notice anything suspicious.

### Employ Multifactor Authentication

In order to prevent user credentials from getting compromised, organizations must employ multi-factor authentication techniques. In addition to this, the organization must enforce strict password policies and regularly audit the strength of the passwords used.

### Proper Configuration of your network firewalls

The organization's firewalls must be properly configured in order to accurately apply access control lists and perform deep packet inspection to identify and block various attacks, malware, or threats.

### Implement DLP solutions to prevent data exfiltration

The organization must install several data loss prevention solutions in their network environment to stop intruders from stealing sensitive data from the company's network.

### Employ Data Back up and Recovery techniques

In order for the organization to protect itself from becoming a victim of a ransomware attack, it is necessary to implement different data backup and recovery techniques so that the organization can recover its data in a timely manner without paying the ransom.

### Design and implement a strong cyber security management program

Finally, the company needs to give careful consideration to allocating its resources in order to build a solid security management program. As a result, the business will be able to assess the various risks to its valuable assets and implement cost-effective security controls to reduce those risks..

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MDFIR - Certified DFIR Specialist](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**