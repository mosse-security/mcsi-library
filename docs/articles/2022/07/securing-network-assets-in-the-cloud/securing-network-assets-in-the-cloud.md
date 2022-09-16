:orphan:
(securing-network-assets-in-the-cloud)=
# Securing Network Assets in the Cloud
 
We have switches, routers, subnets, load balancers, and so on on-premises. In the cloud, their counterparts are called network assets and they perform similar tasks such as facilitating interaction between our resources and the rest of the world and protecting resources. Let's take a look at each of them individually. In this blog page, we will take a look at how to manage network assets securely

## Subnets, VPCs, and CDN

Virtual private clouds (which can be abbreviated as VPCs) and subnets define the rules and parties of communication. You should scan your network regularly and keep track of your Subnets and VPCs because you can forget them easily. Content distribution networks (which can also be abbreviated as CDNs) are low-latency content delivery solutions that disseminate your content internationally.

You should keep in mind that, if an attacker has access to the content distribution network, he or she may contaminate your content with malicious code.

## DNS records

Keeping a good inventory of DNS records and as well as registrars is part of a good network asset management strategy. You should also keep in mind that many browsers don’t support Transport Layer Security (which can be abbreviated as TLS). Spoofing a DNS record can direct your user/visitor to an attacker's specified site. We can see that DNS spoofing can lead the way for an attacker to steal your visitor's credentials. The attacker may also read any data passing through to your site, and even intercept it while in transit. Furthermore, keeping a good track of DNS records prevents a possible service outage.

## Certificates

The strongest line of defense against an attacker impersonating your website is X.509 certificates. When a certain cryptographic technique is revealed to be weak or when a certificate authority has a security concern, a whole class of certificates must be reissued.

You must also keep track of who has access to the private keys. Private key holders may also spoof your resources.

When a certificate expires, there occurs a service outage unless you renew it. So, you should keep in mind that if you forget to renew a certificate, connections will fail. You can benefit from certificate storage services to keep an inventory.

## Reverse proxies, LBs, and WAFs

Load balancers, reverse proxies, and web application firewalls process and route traffic to your resources/contents. You need to keep a good inventory of these resources to manage them effectively.

## Conclusion

Upon completion of this blog post, you have learned the importance of renewing your certificates. You have also understood the importance of keeping a good inventory of your network resources in the cloud such as

- Subnets
- VPCs
- Content distribution networks
- DNS records
- Reverse proxies,
- Load balancers
- Web application firewalls
- Private key holders

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**