:orphan:
(compliance-challenges-in-the-cloud)=
# Compliance Challenges in the Cloud
 
Each cloud service provides a different amount of environmental control in IaaS, PaaS, and SaaS models thus creating compliance issues for business operating in the cloud. This blog post will give you an insight into compliance challenges in the cloud.

## Introduction

Since each cloud model is different than the other, in some circumstances, you are accountable for safeguarding your data in the cloud in others, you will be responsible for keeping the services you use securely.

**IaaS**: The risks associated with the networks and servers on which the virtual infrastructure is built are handled by the cloud service provider in IaaS architectures. However, you have still a great deal of control over the infrastructure which makes you responsible for the actions you perform on it. You need to protect your infrastructure, keep the OS patched and updated, and manage storage and backup solutions.

**PaaS**: In PaaS setups, the cloud provider takes on the infrastructural responsibility from you(such as maintaining the security of the OS and the physical architecture).

**SaaS**: Lastly in the SaaS model, you don’t have much control over the infrastructure. The cloud provider is accountable for it. What these three models have in common is that you are always accountable for the data you keep on the platform.

## Audit and Assessment Restrictions

When you make an agreement with a cloud service provider, your capabilities of auditing and analyzing the security posture of the cloud environment are defined by this contract.

In many circumstances, the cloud provider enables you as a client to audit and evaluate the environment. However, a cloud provider may specify how and when you can request an audit. A cloud provider can also determine by whom these audits can be conducted such as internal audit teams or third-party agencies.

The cloud provider may also deny the audit demands in some cases. Let’s say you want to analyze a cloud provider's security. Many providers refuse pentest requests or allow them under highly rigorous circumstances.

As you can see, auditing capabilities in the cloud are limited. Furthermore, active security tests may have an impact on the infrastructure, the platform itself, or the application being tested. These security tests may also interrupt the services and decrease the uptime.

## Conclusion

Cloud services are distributed services shared by the clients. They may provide compliance issues because of the shared tenancy model. The security status of the organizations sharing the same servers may affect each other potentially harming them. Multitenancy brings growing risks to the cloud. As you might already guess, these risks grow bigger in SaaS models where the cloud service provider has the most control. Sometimes You may have data in the same database as other customers, with just the application logic keeping your data separate from theirs. When we look at the IaaS model, the smaller portion of sharing some of the same system resources with other host tenants reduces the compliance risks associated with multi-tenancy.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::