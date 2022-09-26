:orphan:
(designing-threat-emulation-scenarios)=

# Designing Threat Emulation Scenarios

The cyber red team is a key part of defending an organization's networks and systems. Red team members simulate cyber-attacks against an organization to help identify and fix vulnerabilities. But how do you design effective cyber red team scenarios?

One method is to use real-world data to create realistic threats. This can include data from past attacks, leaked information from hackers, and information from intelligence agencies. You can also use modelling and simulation tools to create realistic scenarios.

## Use the Insider, Outsider, Nearsider Models

The Insider, Outsider, Nearsider Models offer a way to design threat emulation scenarios. An Insider is a current employee with authorized access to the organization's systems and data. An Outsider is an individual or organization not authorized to access the organization's systems and data. The Nearsider is a threat that has some limited access and knowledge.

### The Insider: Whitebox Testing

An entity with legitimate access to specific software, systems, networks, and physical access is referred to as an "insider".

When designing Red Team scenarios, we should consider "insider" knowledge and access:

- Access to legitimate credentials
- Access to network architecture diagrams
- Access to organizational charts
- Understanding of network segmentation controls
- Knowledge of security controls deployed on the network
- Ability to exploit trust relationships between employees and business divisions

Providing the Red Team with too much inside information can come seen as unfair and unreasonable. In reality, advanced threat actors blackmail or otherwise compel internal employees into giving privileged information before ever launching a cyber attack.

### The Nearsider: Greybox Testing

The Nearsider is a threat that has some limited access and knowledge, for example a cleaning crew or an IT contractor. We decide on key scenario parameters:

- Do they have a regular AD account?
- Can they access the network with VPN credentials?
- Maybe they just have an email account that they are accessing remotely?
- Do they have a pass to get into the building?
- Maybe they received some privileged information because they bidden on a tender?
- Maybe they landed a meeting with the CISO and some restricted information was shared in good faith?

When it comes to cyber threats, organizations often underestimate how much information a threat can legitimately capture on them. Whether it is via open-source intelligence (OSINT) or spying, we should never believe that they are starting from zero.

If you're still not convinced, consider how much information legitimate salespeople can gather in order to try to close a deal with your organization... you'll soon learn that all it takes is a few email exchanges, browsing through your websites, a phone call or two, and possibly an onsite visit... They can map your organizational hierarchy, extract your IT plan, uncover HR issues, and identify capability gaps with minimal effort.

### The Outsider: Blackbox Testing

The outsider, on the other hand, has no prior understanding about the target organization. They are starting from the beginning. This is the most popular sort of Red Team operation, and it's also the one most CISOs believe will provide the most benefit.

## Use common Red Team scenarios

There also are 3 types of common Red Team scenarios:

## Option 1: Assumed Breach

The Assumed Breach scenario assumes that a threat has already entered the network and gained unauthorized access to one or more devices and credentials at the start of the engagement. Because it starts with network connectivity, this scenario is without a doubt the most helpful and cost-effective (saving many weeks of effort).

Less mature businesses believe that a threat must first demonstrate that they can obtain it before they can begin. In this circumstance, we recommend supplementing this scenario with a spear-phishing campaign, possibly as a separate engagement.

## Option 2: Restricted Network or Physical Access

We'll presume that the Red Team has gained logical or physical access to a public location in this scenario. For example:

- Access to the guest wireless
- Access to the reception area
- Access to a public meeting room
- Access to a public printer
- Access to a floor (not not all floors)
- Access to the underground car park
- Access to a "stolen" mobile device

This type of engagement commences on-premise rather than over the internet. As a result, the Red Team will not conduct spear-phishing assaults or attack ICT systems that are exposed to the Internet.

## Option 3: Full Engagement

The scenario is a complete end-to-end threat simulation that begins and ends with stated operational effects. This scenario is the most popular choice among very mature organizations.

- Obtain remote access to the target network via the Internet
- Escalate privileges on machines and the networks
- Move across the network and bypass network segmentation controls
- Obtain unauthorized access to sensitive materials
- Deploy off-the-shelf and custom tools
- Operate entirely remotely, like a real cyber threat actor

## Final Words

There is no one-size-fits-all answer for how to design cyber red team threat emulation scenarios. Every organization is different, and will have different needs and priorities. However, there are some general guidelines that can be followed to create effective scenarios.

First, make sure that the scenarios are realistic and challenging. They should be designed to test the organization's defences against a wide range of possible attacks.

Second, ensure that the scenarios are constantly evolving. The defenders should never know what to expect, so they are constantly forced to adapt.

Third, use open source intelligence (OSINT) to gather information about the organization and its networks. This will help to ensure that the scenarios are accurate and realistic.

Finally, involve the defenders in the creation of the scenarios. This will help to build mutual trust and cooperation, and will also help to identify any potential weaknesses in the organisation's defences.

:::{seealso}
Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html) In this course, you'll learn about the different aspects of red teaming and how to put them into practice.
:::
