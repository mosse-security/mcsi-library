:orphan:
(securing-data-in-iaas-paas-and-saas)=
# Securing Data in IaaS, PaaS and SaaS
 
In this blog post, we will take a look at the best practices for securing your 3 states of data in the cloud which are data at rest, data in transit, and data in use.

## How to secure data at rest?

Data at rest refers to all of the information saved in your cloud or cloud systems. Encryption is the greatest technique to safeguard data at rest; however, the implementation of encryption differs depending on the kind of cloud.

**Data at rest security in PaaS and SaaS**

In the case of PaaS and SaaS, the provider is primarily in charge of data encryption at rest. As a result, before choosing a cloud service, you should question if they support data encryption at rest. You should also keep in mind that this covers also backups.

## How to secure data in transit?

Data in transit is the exchange of data between endpoints. Securing this data is more difficult since it frequently necessitates collaboration between the cloud provider and the user.
SaaS data in transit security

**SaaS data in transit security**

You can safeguard data in transit for SaaS solutions by employing a secure transmission protocol such as SSL. HTTPS prevents person-in-the-middle attacks by encrypting data in transit.

**PaaS data in transit security**

Securing data in transit for PaaS typically necessitates some setup on the cloud provider side, as well as certain security settings on your endpoint device. As an example, you can use a secure API to transfer data between your device and the cloud. API key provides end-to-end encryption between endpoint devices and the PaaS solutions.

**IaaS data in transit security**

Securing data in transit for IaaS is generally done by the user by configuring secure ways to connect to their cloud systems and infrastructure, such as SSH. You can also benefit from PUTTY to verify that communication with your cloud server is safe.

## How to secure data in use?

Data in use is essential information stored in random access memory (which is abbreviated as RAM). Previously, data in use was not regarded as susceptible; however, attackers developed techniques to access data from memory. Therefore it is essential to ensure that you have taken measures to secure data in use.

The key strategy to preserve data in use is to ensure that the server and applications are patched with the latest security patches to prevent memory leaks.

**SaaS data in use security**

If you are a SaaS user, you can adopt the following techniques to limit the risks of these attacks:

- If you are not currently using a cloud session, terminate it.

- When you’re done with a web tool, make sure to sign out before closing the web browser.

**PaaS data in use security**

If you are a PaaS user, you can follow the same best practices as SaaS users, but you must additionally utilize the most recent version of the platforms you use and avoid using applications with known vulnerabilities that could result in a memory leak.

**IaaS data in use security**

You should take it a step further by adhering to the following best practices if you are an IaaS customer. You should update the OS to the most recent version and patch on a regular basis. Ensure that all software is up to date.
Remove any potentially susceptible software from your servers.

## Conclusion

Regardless of the state, you must guarantee that your data is always safe. In this blog post we have leared how to achieve this as SaaS, Paas and IaaS customers.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::