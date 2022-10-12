:orphan:
(a-brief-introduction-to-aws-key-management-service)=
# A Brief Introduction to AWS Key Management Service 

AWS Key Management Service (KMS) is a managed service that makes it easy for you to create and control the encryption keys used to encrypt your data. AWS KMS is integrated with other AWS services, making it easy for you to encrypt your data with a few simple clicks. In this blog post, we'll cover some of the key security considerations for using KMS, and how you can keep your keys safe.

## What is a Key Management Service?

AWS KMS offers a straightforward platform for generating and managing cryptographic keys, as well as acting as a cryptographic service supplier for data security. AWS KMS combines standard key control services with AWS Cloud services solutions to give a unified view of clients' keys throughout AWS, as well as central control and monitoring.

### Hardened Security Appliance(HSA)

Using your master keys, you can create your unique HSA-based cryptographic environment. The keys are exclusively available on HSAs and may be used to execute cryptographic HSA-based actions such as the generation of application data keys. Various master keys can be generated, each indicated by a Customer Master Key (CMK). You can distinguish them by their key ID.

By setting a policy that is associated with the key, you may use the AWS KMS dashboard to set access control policies as to who can control and/or access master keys. This helps you to create proper settings for key usage that are particular to that app.

You must make all KMS requests using the TLS protocol and complete them on an AWS KMS host. AWS KMS hosts will only permit TLS using a cipher suite that achieves full forward secrecy. AWS KMS verifies and approves client requests by utilizing the very same identification and policy methods as all other AWS APIs and IAM.

### Domains

The AWS KMS service is comprised of a group of AWS KMS operators that manage "domains." A domain is a region-specific collection of Key Management Service servers, operators, and hardware security modules.

To verify its activities, each unit has a hardware token that includes a private and public key combination. In order to secure HSA-to-HSA connections, the HSAs have an extra private and public key pair.

KMS includes a number of hardware security components. These modules meet the Federal Information Processing Standard 140-2 (FIPS 140-2).

## Benefits of AWS KMS service

The AWS KMS is intended to satisfy the basic guidelines as follows.

**Durability**

A given cryptographic key can encrypt a vast amount of customer data that has been gathered over time. If a key is lost, data encrypted with it becomes unrecoverable.

**Quorum system**

CMKs is not accessible to any Amazon personnel. Also, there is no method for extracting raw CMKs.

**Access control**

Access control policies that you establish and administer are secured by keys.

**High bandwidth and reduced delay**

AWS KMS will enable cryptographic functions with acceptable latency and throughput for utilization by other AWS resources.

**Regional autonomy**

AWS delivers user data with geographical autonomy. Key use is restricted to an AWS region.

**Reliable random number generation**

AWS offers a superior supply of random numbers since powerful cryptography relies on really unexpected random number production.

**Integration with auditing**

AWS CloudTrail Logs includes information about the usage of cryptographic keys by AWS. Clients can investigate the usage of their cryptographic keys using AWS CloudTrail Logs.

CloudTrail can also inspect the utilization of keys by AWS Cloud services in their customer's place.

### Summary

To review, we have learned that the AWS Key Management Service is a critical secure platform to protect your cryptographic keys. It has many strong features as above. It also incorporates with AWS CloudTrail. This makes it easy to see who used the keys as well as when.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::