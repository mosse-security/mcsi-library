:orphan:
(zero-trust-the-foundation-of-modern-network-security)=
# Zero-Trust: The Foundation of Modern Network Security
 

Zero Trust is a security model that aims to eliminate vulnerabilities by reducing unnecessary access points. In other words, zero trust means no single point of failure. In this blog post, we are going to define certain methods to achieve this in our cloud-based business to improve security.

## Zero-trust security architecture elements

With a solid knowledge of the idea of zero trust, we may develop architectures that adhere to its principles.

### Access Control

NIST established a body of rules for zero trust systems, many of which address how organizations manage IAM.

- The most important idea is to have a central point of identification. Most businesses will utilize Active Directory (AD) for this purpose. Active Directory must be informed of any user or identity.
- Examine and evaluate all access controls.
- Strong IAM policies must be in operation. And those policies must include the least amount of privilege.

### Authentication

Secondly, robust authentication is required to prove that a user, let's say Alice is actually who she says she is.

- You must employ MFA (multi-factor authentication).
- Furthermore, NIST emphasizes the importance of validating and verifying the environment in which people are authorized and verified. Many programmers have their own computers loaded with their favorite applications. These applications must be evaluated to decide if they comply with the security policies.

### Access policies

Application access policies must also be specified and managed. For example, any programmer working on a human resources web page is unlikely to require access to a company's supply chain application. Access to the application should be limited in that scenario. As a result, zero trust implies that each program has its own group of policies, such as who is authorized to access it, at which degree, and also what privileges are granted in that app.

### Information security

The next building elements for zero-trust infrastructure are data categorization and information security. In cloud-based information technology, data may exist everywhere and is accessible throughout portals, apps, and services.

- Companies must understand where the data is located, the sort of it, and also who is permitted to access it under specific restrictions.
- The information must be defined and categorized: is it confidential, or can it be accessible by the public? Strong privacy requirements, like the General Data Protection Regulation (GDPR), are recommendations for data classification; it is the company's job to follow these criteria.

## Summary

In essence, zero trust is primarily concerned with segregating network layers, programs, information, and resources as much as feasible. Zero-trust is also limiting access to all these multiple elements to verified and authorized users with the principle of least privilege.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::