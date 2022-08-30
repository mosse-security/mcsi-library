:orphan:
(securing-confidentiality-of-data-using-the-bell-lapadula-model)=
# Securing Confidentiality of Data using the Bell-LaPadula Model
 

In an organization, you can secure information in many ways. In this article, we are going to give a general overview of the importance of security models and discuss the rules for securing data using the Bell La Padula Model and its benefits and disadvantages.

Let’s start by describing a security policy.

## What is a security policy

A security policy provides a precise set of mathematical instructions that a computer may use to apply the critical security processes, procedures, and ideas contained in a security program.
A policy is formed based on 2 models:

- Informal
- and formal security models

## What exactly is a security model?

A security model describes the critical features of security and their correlation to operational system performance.
Models might be either intuitive or abstract, which means they are validated mathematically through time.

Security models define these 2 areas to implement a given policy:

- access control policies
- emphasize the objects

## What is Bell-LaPadula?

- Bell-LaPadula is a formal security model used to maintain the _confidentiality_ component of the CIA triad (especially for the US Department of Defense).

- In contrast to the Biba Integrity Model, which defines criteria for protecting data integrity, the Bell–LaPadula model concentrates on data secrecy and regulated entry to classified information.

### Bell-LaPadula mechanism

The entities in an information system are split into subjects and objects in this formal paradigm. This model defines a primary method of access in terms of reading and writing, as well as how subjects get access to objects. Only approved access options, subject to restriction, are available in the secure state, in line with a defined security policy.

### Access Rules:

First of all, let’s describe an entity. In this conventional method, the organisms in an information system are split into two categories:

- subjects
- and objects

**no read up**

An object cannot read material that is graded higher than the subject. It is referred to as "simple confidentiality."
The subject can only read files:

- on the same classification level
- and the lower level of classification
  It can’t read the upper-level information (no-read-up).

**no-write-down**

The second attribute is named the star attribute, or *-property, and relates to defining the scope and rules of *writing access\*.
The subject can only write data to an object that is of the:

- same level of classification
- or higher classification.
  The subject can’t write at the lower level of classification (no write-down).

**strong star**

It is a highly secure and strong rule. It simply says that the subject can both read and write.

### General attributes of the Bell-LaPadula model

offers a precise transition procedure for transferring the information from one safeguarding state to another.

- Allows access to data components (called objects) on a strictly need-to-know basis.
- Follows the "no write-down, no read up" guideline.
- Specifies entry to an object based on the subject's and object's classification tier.
- The Bell LaPadula Model is widely used in government and military organizations.

## Advantages and disadvantages

This model's policies can be applied to real-world organizational structures. It is simple to apply and comprehend, and it has been shown to be effective.
However, even if a user does not have access to an item, they will be aware of its existence, hence it is not confidential in that sense.
The concept is heavily reliant on trust inside the organization.

## Summary

Bell LaPadula is a confidentiality-based formal security model which has defined reading and writing access control rules. Regarding its simple appliance and drawbacks, it can be adopted for different organizational needs.

After all, we implement security models in order to maintain the confidentiality and integrity of information. With a strong and efficient security model, it is easier to safeguard your critical information or data in a company.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**