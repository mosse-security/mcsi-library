:orphan:
(model-your-threats-to-protect-your-assets)=

# Model Your Threats to Protect Your Assets

Every organization has several valuable assets that must be safeguarded. The assets can be tangible, such as computers, laptops, and network equipment, or intangible, such as information, data, programs, and so on. As the number of cyber-attacks increases around the world, the focus on cyber security is shifting from reactive to proactive methods. A proactive cybersecurity strategy is a preventative strategy that seeks to discover any vulnerabilities and threats surrounding our assets before they have an opportunity to compromise the security of our assets. Threat modeling is one of the most widely utilized proactive methodologies in the creation of secure systems and applications. This article will explain what threat modeling is and how you can leverage it to improve your organization's security posture.

## What is Threat Modeling?

Threat modeling is a proactive strategy for detecting and enumerating all potential vulnerabilities and threats to our assets in order to develop effective mitigation strategies. Threat modeling aids developers in identifying the many threats that can affect systems/applications, enumerating those threats, and implementing suitable security controls. Threat modeling can be utilized in the development of secure IT infrastructure such as software, applications, systems, network devices, and so on.

## Why should you use Threat modeling?

Threat modeling begins with identifying the weaknesses in our assets and allows us to analyze potential adversaries, their capabilities, their motivations, and the techniques they might use to exploit those flaws. Threat modeling allows developers to concentrate their mitigation efforts on threats that are likely to occur. This aids in the implementation of cost-effective security controls to reduce the risk posed by these threats.

Threat modeling is useful for creating cyber-resilient systems and applications. By using threat modeling throughout the product design phase, you may can reduce the overall attack surface and deliver a well-rounded secure product.

Threat modeling can also aid in the discovery of single points of failure in a system or application. A single point of failure is when a critical component of a system fails, causing the entire system to become unavailable or dysfunctional. As a result, developers can use this technique to discover all of the scenarios that could cause the system to go down, and then use defense-in-depth strategies to minimize downtime.

## When should you use Threat Modeling?

Threat modeling should be employed early in the development of a system and refined throughout its lifecycle. This helps us handle threats that arise during the development of a system/application as well as validate our security measures.

Threat models can also be utilized when a system receives a new feature, undergoes a change in its functionality or architecture, or when a security incident occurs.

## The Process of Threat modeling:

The threat modeling process is broken down into a four-question framework by the OWASP (Open Web Application Security Project). These questions can assist security professionals in determining the possibility of a threat exploiting a vulnerability, the risk posed by this threat, and the appropriate security controls to implement. Answering these questions will help the threat modeling process to become more structured and effective. The following are the questions:

1. What are we working on?
2. What can go wrong?
3. What can we do about it?
4. Did we do a good job?

When it comes to threat modeling, different organizations use different techniques and models. All of these tools have the same basic essence, which consists of the following major steps:

<u>1. Identify the scope and the objectives:</u>
This stage begins by identifying the boundaries of our scope for the system under examination. A scope might be anything from the complete system/application to a single component. After defining the scope, you continue on to identifying the assets, defining the use cases, data flows, and stakeholders involved.

This phase will assist you in answering the first of the four questions in the framework. It enables you to comprehend why the system is being designed and how it functions to achieve that goal.

<u>2. Identify and analyze the threats:</u>
This step requires you to examine your system holistically and discover various weaknesses and threats. It assists you in analyzing the various attack vectors by focusing on security weaknesses, identifying who/what can harm the system, and the possible techniques that can be used for exploitation.

This step helps you in answering the second question, which is what could go wrong. This stage must be carried out in great detail, taking into account all possible situations for exploitation or failure. This stage will equip security experts with sufficient information to implement appropriate security measures in order to address the security issues.

<u>3. Determine the security safeguards:</u>
In this step, you decide how you will deal with each threat. This phase assists you in answering the threat modeling framework's third question. Depending on the risk posed by each threat, you can choose to accept, transfer, decrease, or avoid the risk. This stage helps to choose from different sets of security controls (physical, administrative, or technical) to mitigate the risk posed by each threat.

<u>4. Validation of security controls:</u>
This phase allows you to see if the security controls you've chosen are actually reducing the risk posed by a specific threat. This stage aids you in answering the threat modeling framework's last question. This aids in evaluating the efficacy of security countermeasures and determining how to improve your security approach. This process should be continued throughout the system's development lifecycle. This is because different threats emerge as the system progresses through its developmental stages.

## Threat Modeling Frameworks:

There are numerous frameworks available that can be utilized to simplify the effort of threat modeling in your organization. The threat model you choose is determined by a variety of criteria, including your business goals, the assets you want to protect, available resources, the kind of threats your systems face, the goal of threat modeling, and so on. These considerations will aid you in determining the framework to use to model threats in your environment. The following are some of these frameworks.

### STRIDE:

Microsoft created the STRIDE threat modeling framework. Developers primarily utilize STRIDE to assess the security of applications. This model is used to identify threats that could jeopardize the system's confidentiality, integrity, or availability, as well as its authentication, authorization, and non-repudiation mechanisms. STRIDE stands for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. Each of these elements is described below:

<u>1. Spoofing:</u> Spoofing occurs when an entity (user/program) masquerades as another entity trusted by the system. Spoofing is a technique used by attackers to get around a system's authentication procedures.

<u>2. Tampering:</u> Tampering is the unauthorized alteration of a system or its components in order to change its behavior or data. A tampering attack compromises the system's integrity.

<u>3. Repudiation:</u> A Repudiation attack occurs when a system's logging, tracking, and monitoring mechanisms are inadequate, allowing an adversary to undertake harmful activities on the system. This technique is used to bypass a system's non-repudiation measures.

<u>4. Information Disclosure:</u> When a system provides sensitive information to unauthorized users, this is referred to as information disclosure. Adversaries can utilize this information for malicious purposes like designing a successful attack on the system. The system's confidentiality is endangered by the Information Disclosure attacks. The most typical way for information to be disclosed is through an application's error response, which can reveal vital information about its internal structure, operation, or user details.

<u>5. Denial of Service:</u> A Denial of Service attack happens when an attacker overwhelms a system or program, rendering it unavailable to legitimate users. A Denial of Service Attack compromises a system's availability. Buffer overflow and flood attacks are the two most popular types of Denial of Service attacks.

A buffer overflow attack happens when an attacker exhausts all of an application's processing capacity or memory, causing it to crash.

A flood attack happens when an attacker sends a system unsolicited connection requests or packets, causing it to crash.

Smurf attacks, ping flood attacks, and ping of death attacks are examples of DOS attacks.

<u>5. Elevation of Privilege:</u>
An Elevation of Privilege attack happens when an attacker exploits a vulnerability, such as faulty access controls or security misconfigurations, to achieve greater or elevated privileges on the machine. An Elevation of Privilege attack undermines a system's authorization mechanisms. An attacker can gain elevated rights via compromising an administrator account, injecting a malicious payload into a process with higher privileges, or injecting a malicious payload into a system that can give an attacker elevated access.

### PASTA:

The PASTA threat model examines a system from the perspective of an attacker, identifies threats and risks, and recommends appropriate security safeguards. PASTA stands for Process for Attack Simulation and Threat Analysis and is based on a seven-step process. These are the steps:

<u>1. Define objectives:</u>
This step establishes the reason for which the system or application in question was created. This step aims to determine which business objectives are met by our system.

<u>2. Define the technical scope:</u>
In this step, you describe the system's attack surface and determine what it is you're protecting. This stage aids in the identification of the underlying technologies/components that support the business goals established in the previous step.

<u>3. Decompose the application:</u>
This stage decomposes the application, even more, to better understand the data flow between the many components of the system that were discovered in the previous step.

<u>4. Analyze the threats:</u>
This stage identifies and analyzes the threats that have an impact on the attack surface you established in the previous step. To identify the most common risks to your organization and assets, you can use credible threat intelligence resources as well as your system/application logs.

<u>5. Analyze the vulnerabilities:</u>
This stage identifies and analyzes the flaws in your system/application that the threats from the previous step can exploit. These can be in the form of code flaws or design flaws.

<u>6. Analyze the attacks:</u>
This step involves simulating attacks based on identified threats and vulnerabilities in order to demonstrate how a threat can exploit a vulnerability. You can utilize attack trees to create the whole attack scenario.

<u>7. Analyze the Risk and its impact:</u>
In this stage, you assess the risk posed by the threats you have identified, as well as their potential impact. This stage assists you in implementing cost-effective security controls based on the risk level.

### TRIKE:

The TRIKE model is an open-source framework for threat modeling. To enumerate threats, TRIKE employs a risk-centric methodology, ensuring that the degree of residual risk is acceptable to the stakeholders. Two models for analyzing threats and selecting security solutions are combined in the trike model. The following are the models:

<u>1. The Requirements Model:</u>
The security requirements of the system or application in question, as well as the acceptable amount of risk to each asset, are established using this model.

<u>2. The Implementation Model:</u>
Data flow diagrams are used in this step to understand the flow of data between different components of the system and to build use cases. Afterward, the threats are enumerated and a value is assigned to the risk posed by them. Using these diagrams, appropriate security measures are chosen to meet security requirements and reduce risk to an acceptable level, as stated in the requirements model.

### DREAD:

The DREAD threat model analyzes the impact and probability of the risk due to a threat using a qualitative risk analysis approach. These values are used to determine the threat's severity. DREAD stands for Damage, Reproducibility, Exploitability, Affected Users, and Discoverability. Each of these factors is given a score ranging from 1 to 3, and the severity is determined by combining all of the scores. Each of the elements are described below:

<u>1. Damage:</u> How much damage can the threat cause if it exploits a vulnerability?

<u>2. Reproducibility:</u> How easily can this attack be replicated by different adversaries?

<u>3. Exploitability:</u> The resources that are required to launch an attack successfully against the system.

<u>4. Affected Users:</u> The number of people that will be impacted as a result of this attack.

<u>5. Discoverability:</u> How easy is it to locate the vulnerability?

### VAST:

VAST(Visual Agile and Simple Threat) model is based on an automated threat model developed by ThreatModeler. The three main components of this model are Automation, Integration, and Collaboration. The benefits of using VAST model :

- VAST can be easily scaled to cover any part of the enterprise or the whole enterprise
- VAST can be easily Integrated into Agile environment and DevOps lifecycle
- VAST allows for collaboration between developers, security engineers, and various stakeholders to provide effective solutions to deal with threats

VAST develops two models for threat reduction: Application and Operational threat model. The purpose of these models is described below:

<u>1. Application Threat Model:</u>
The purpose of an application threat model is to discover threats and vulnerabilities in an application. The creation of this model aids the developers in mitigating the risk due to these threats.

<u>2. Operational Threat Model:</u>
An Operational Threat Model is created with the goal of visualizing the IT infrastructure at a higher level and reducing the operational environment's risks. Web servers, proxy servers, firewalls, and database servers are examples of IT infrastructure. This model is intended to assess the attack surface and identify potential threats by including the viewpoints of multiple stakeholders. Following that, the risk posed by each threat is assessed in order to determine the right security controls.

### hTMM:

hTMM stands for Hybrid Thread Modeling Method. It was developed by SEI(Security Equipment Inc.) in 2018. This model is used to analyze threats and the risk due to these threats using security techniques such as SQUARE(Security Quality Requirements Engineering Method), Security Cards, and PnG(Persona Non-Grata).

The SQUARE method is used to gather, categorize and prioritize security requirements for a system or application under consideration. This method is used to integrate security into the product during the initial phases of its development.

The Security Cards is a brainstorming technique that is used to analyze threats by taking into account these factors:

- Human Impact
- Adversary's Motivations
- Adversary's Resources
- Adversary's Methods

The PnG method is used to create a threat actor's profile by focusing on all the ways that an attacker can exploit the vulnerability in the system to launch an attack successfully.

The main steps of the hTMM model are:

1. Identify the system to be threat-modeled
2. Apply the security cards based on the developers' suggestions
3. Eliminate the unlikely PnGs
4. Summarize the results using tool support
5. Continue with a formal risk assessment method

> **Want to learn practical Secure Software Development skills? Enrol in [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).**
