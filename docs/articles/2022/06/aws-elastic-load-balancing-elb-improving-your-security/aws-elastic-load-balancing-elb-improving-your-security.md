:orphan:
(aws-elastic-load-balancing-elb-improving-your-security)=
# AWS Elastic Load Balancing (ELB) - Improving Your Security
 

This blog post will provide you with the security perks of an Elastic Load Balancing (ELB) service.

## What are benefits on an ELB?

Elastic Load Balancing keeps control of an Amazon EC2 farm by disseminating requests to instances through all Availability Zones within a region.

Elastic Load Balancing offers all of the benefits of an on-premises load balancer, as well as some protection advantages:

- ELB takes over the cryptographic appliance work from Ec2 Instances and controls primary on the load balancer.
- ELB provides customers with a single egress point of contact and can also function as the frontline of security against network threats.
- Supports the setup and maintenance of security groups linked with your Elastic Load Balancing when utilized in an Amazon VPC to give extra networking and security alternatives.

### ELB and TLS

ELB also supports TLS (formerly SSL) end-to-end traffic encryption on networks that employ secure HTTP (HTTPS) communications.

If TLS is utilized, the TLS server certificate utilized for end-host communication on the load balancer may be handled centrally rather than on each isolated instance.
HTTPS/TLS generates a short-term session key from a long-term secret key that is utilized between the browser and the server to construct secure communications.

### ELB and cipher suites

When a connection is created between a user and your load balancer, Elastic Load Balancing fine-tunes your load balancer with prespecified encryption keys that are used for TLS communication. The pre-defined encryption keys are compatible with a wide range of customers and employ powerful cryptographic algorithms.
To guarantee that standards are fulfilled, certain clients may have specifications for accepting only specified ciphers and protocols (for example, Payment Card Industry Data Security Standard [PCI DSS], Sarbanes-Oxley Act [SOX]).

Elastic Load Balancing gives choices for comparing various settings for TLS protocols and ciphers in these circumstances. Depending on your unique needs, you can activate or deactivate the ciphers.

You may set the load balancer to have the last word in the cipher suite selection during the host-web server communication.

If the Server Order Preference alternative is chosen, the load balancer will choose an encryption key based on the server's priority preference rather than the client's. This allows you better flexibility over the degree of security used by customers to link to your load balancer.

### Perfect Forward Secrecy

Elastic Load Balancing supports Perfect Forward Secrecy, which employs session keys that are temporary and not kept anywhere, for even more communication privacy. Even if the private long-term key is exposed, this prohibits the decryption of collected data.

Whether you're utilizing HTTPS or TCP load balancing, Elastic Load Balancing makes it possible to determine the source IP address of a consumer connected to your services.

While queries are proxied through a load balancer, host communication details like port numbers and IP addresses are often discarded. Because the load balancer makes queries to the server in the consumer's place, your load balancer seems to be the querying host. If you require additional information about your viewers for your apps, like connectivity metrics, network logs, or managing allowed IP addresses, knowing the source IP address is important.

### ELB and auditing

The access logs for Elastic Load Balancing provide details about each HTTP and TCP query performed by your load balancer.
Every request issued to the load balancer is recorded, even those that cannot reach the back-end instances.

## Summary

In summary, AWS Elastic Load Balancing improves the overall networking security of your business with a range of benefits we covered above.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::