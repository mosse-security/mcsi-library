:orphan:
(introduction-to-stride-as-a-threat-modelling-framework)=
# Introduction to STRIDE as a Threat Modelling Framework
 

Threat modelling is the process of identifying potential threats to a system and figuring out how to mitigate or eliminate those threats. The goal is to make the system more secure and resilient against attacks. Threat modelling can be done at different levels, from high-level overviews down to very detailed analysis. A vital phase of the threat modeling strategy is specifying the potential dangers that an application or system may encounter and its weaknesses.

An efficient threat model includes the following components:

- Threat intelligence
- Mitigation capabilities
- Asset identification
- Risk assessment

Before we dive into STRIDE, let’s begin with Microsoft SDL.

## What is Microsoft Security Development Lifecycle

Microsoft Security Development Lifecycle (SDL) was developed in 2008 to guarantee security and privacy factors are taken into account throughout the development process. The aim was to help developers to create:

- secure software,
- meet security compliance needs,
- and lower development costs.

Threat modeling is at the heart of Microsoft SDL.

## Why do we need guidelines in threat modeling?

It is generally beneficial to utilize a guide or reference when trying to catalog and classify risks to an organization's valued assets. To address this issue we can utilize guidelines such as STRIDE, PASTA, VAST, and STRIKE.

Today we are going to make an introduction to the STRIDE framework methodology.

## What is STRIDE?

STRIDE is a threat classification technique designed by Microsoft as part of their Security Development Lifecycle. STRIDE is frequently used to evaluate threats to applications or operating systems. It can, however, be used in other domains as well.

STRIDE is an abbreviation for the following six main principles:

**Spoofing**: Spoofing is the use of a fake persona to gain access to a victim's machine.IP addresses, MAC addresses, ids, machine names, wireless network SSIDs, email addresses, and several different logical authenticators may all be spoofed. When an adversary masquerades as a legitimate or approved entity, they are typically able to bypass filtering and barriers that prevent unauthorized entry.

**Tampering** : Tampering is any activity that causes illegal alterations or data exploitation, whether in transit or at rest Tampering is used to change static information or mislead information. Such attacks violate both integrity and availability.

**Repudiation**: Repudiation is an attacker's capability to reject performing an action or activity. Repudiation assaults are frequently used by attackers to preserve reasonable refusal. They also avoid responsibility for their activities.

**Information exposure**: Information exposure refers to the disclosure or distribution of private information to unauthorized authorities. Revealed data may contain information about the customer's credentials, ID, finances, or confidential company operations.

Information disclosure can be exploited with these aspects:

- system design
- and implementation flaws.

Examples of such defects are:

- forgetting to remove debugging code,
- not sterilizing end-user programming notes,
- using secret form areas,
- showing end-users too much information about errors

**Denial of service**: It is an attempt to restrict the allowed consumption of a service. This can be accomplished by exploiting flaws, overloading connections, or flooding traffic. A DoS attack may not always result in a complete disruption of a resource; it may instead lower bandwidth or add delay, impeding productive use of a resource. While most DoS attempts are transient and endure just as long as the attacker keeps the attack going, some are lasting.

A continuous DoS attack might entail destroying a database, replacing software with evil alternatives, or pushing a hardware flash procedure that can be halted or set up with inaccurate firmware.

Some of these DoS assaults would result in a constantly impaired system that could not be recovered to operational status by restarting.

To recover from a persistent DoS attack, a thorough system repair and backup restoration would be necessary.

**Elevation of privilege**: In this type of attack, you can turn a restricted user account into one with more rights, capabilities, and access. You can do this by stealing or exploiting the credentials of a higher-level account, such as an administrator or root. You can also accomplish this level of escalation through a system or application hack that offers greater privileges to an otherwise restricted account, either temporarily or permanently.

## Summary

STRIDE is most commonly associated with software threats. However, this framework can also be applied to network and host risks.

STRIDE's six threat ideas, however, are quite general.
STRIDE and similar threat modeling tools analyze a wide variety of compromising issues and their scope. They also focus on the:

- intent
- or effects of an assault

In this article, we explain how you can utilize the STRIDE framework for assessing and mitigating risk.

The first step in creating defenses is to identify risks. A secure design is essential for every software program or system. Although STRIDE was used primarily for classifying application risks, its six main threats are quite broadly applicable to diverse domains in threat modeling.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**