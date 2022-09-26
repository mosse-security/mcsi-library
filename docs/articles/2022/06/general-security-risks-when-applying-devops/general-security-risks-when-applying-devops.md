:orphan:
(general-security-risks-when-applying-devops)=
# General Security Risks when Applying DevOps
 

Applying DevOps without considering security would undoubtedly lead to an increased risk of cyberattacks by growing the attack surface of organizations. This blog post will give you a strong understanding of general security risks in DevOps and how to address them.

There are many issues that should be considered, some examples of these are:

- Access control
- Lack of guardrails and rules
- Prioritizing development methodology and speed above security

## Access control

### Privileged access management (PAM)

Development and Operation teams are likely to utilize code repositories that are accessible manually by developers or by tools. Even while functioning as open-source, code must be secured, and code must be distributed so other developers may contribute to the program. Even in that instance, corporations would want to restrict access to code so that it does not leak or, is injected with malicious code.

You'll want to employ a role-based access model for source repositories such as who has read and write permissions, and who has complete access and why? GitHub organizations, as an example, can establish internal repositories to which only authorized personnel or tools of that firm have access. The administrator assigns the roles inside that internal repo. Credentials are assigned in accordance with the organization's security policy. Applying privileged access management (PAM) is a suggested method for maintaining access control .

DevOps requires teams to generate accounts with additional privileges which are distributed across programmers and devices. The following accounts are stored in repositories.

- Service accounts,
- Application Programming Interface (API) certificates,
- The Secure Shell Protocol (SSH) keys,
- Cryptographic key pairs,

Consider a person who does not have the authority to access these repositories gaining access to these accounts. It would have devastating consequences.

A PAM tool enables you to approve and monitor any DevOps operation.

### key vaults 

The majority of these systems employ key vaults to secure credentials and to verify and approve users before they can access code resources.

## Lack of guardrails and rules

The ability to access code is one thing; what we do with that code is another. Companies are unlikely to enable DevOps teams to simply push a new code to development. First and foremost, the company must consider the desired toolset. It is critical that each DevOps team adopts those tools. However, DevOps toolkits lack a uniform set of rules for security controls like access management. That is something that the organization must formulate and maintain, which is made easier if you use a single toolbox.

The same is true for working style: it must be uniform throughout the organization. Everything must be stated in a favored technology checklist, as well as DevOps guardrails and standards.

### A simple cloud operation

First there is usually a master branch. New code will initially be pushed to a different branch, known as the feature branch, and it will be tested there. The code is integrated into the master when the verified, and positive testing results are received. The repository now contains the main branch. When code is fetched from the repository, how it is pushed to feature branches, and how it is reviewed and finally published for joining to the master are all governed by the guardrails.

## Prioritizing development methodology and speed above security

DevOps is all about increasing development pace. That should not be used as a justification to ignore security.

## Conclusion

To recap, DevOps security is concerned with many issues, these issues are are commonly related to:

_Track and trace_: Monitor every step of the DevOps process and pipelines.

_Audit_: Confirm that technologies produced under DevOps are compatible with the organization's security requirements and the industry standards to which the business is subjected.

_Monitor_: Deploy reliable monitoring systems.

You now have a solid grasp of the security issues associated with DevOps.

:::{seealso}
Want to learn practical DevSecOps skills? Enroll in [MDSO - Certified DevSecOps Engineer](https://www.mosse-institute.com/certifications/mdso-certified-devsecops-engineer.html)
:::