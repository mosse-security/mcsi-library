:orphan:
(additional-security-with-amazon-emr)=
# Additional Security with Amazon EMR
 

AWS offers web-based analytical services to assist you in processing and analyzing large quantities of data, regardless of whether you require controlled Hadoop clusters, live streaming, massive data warehousing, or orchestrating. In this blog article, we will introduce Amazon EMR which is formerly known as Elastic MapReduce, and examine its security benefits.

## What is AWS EMR?

Amazon Elastic MapReduce (Amazon EMR) is a controlled online tool that allows you to create Hadoop clusters that handle big quantities of data by dividing tasks and content across multiple servers. It involves an improved version of the Apache Hadoop technology that runs on Amazon EC2 and Amazon S3 infrastructure.

## An overview of a job flow

In a typical job flow, you just need to import your raw data as well as an information processing program to your AWS S3. As a next step, AWS EMR deploys a certain range of EC2 machines. The service begins task workflow processing by gathering information from S3 into the EC2 machines.

When the job flow is completed, Amazon EMR sends the output information to Amazon S3, from which you can download it or use it as a source in a different job flow.

### Amazon EMR and security groups

When Amazon EMR launches task flows on your part, it creates two Amazon Web Services security groups:

- one EC2 for the master endpoints
- second EC2 for the slaves.

The master security group has a connection channel available with this resource. It also includes an open SSH port, allowing you to SSH into the VMS with the password given at launch.

These security groups are configured in default to deny access from outside resources, such as Amazon EC2 machines pertaining to other clients. You can modify the security groups inside your account utilizing the usual EC2 features or interface.

## Additional security benefits of Amazon EMR

### SSL

Amazon EMR uses SSL to exchange files to and from Amazon S3 to secure client entry and exit information.

### IAM

Amazon EMR offers numerous methods for controlling ingress points to your bundle resources. AWS IAM may be used to establish user accounts and roles, as well as define privileges that govern specific AWS functionalities these users and roles have access.

You may also provide clients besides the default Hadoop user permission to introduce tasks to your cluster. By default, when an IAM user starts a cluster, the cluster is invisible to other AWS IAM clients. The filtration operates across all Amazon EMR endpoints, preventing IAM users from accessing and mistakenly modifying clusters formed by the other IAM accounts.

### Encryption/SSH

When you initiate a cluster, you may connect it with an AWS EC2 secret key suite, which you can then use to log in to the bundle through SSH.

You may use any standard strong encryption application to secure the data input prior to uploading it to Amazon S3. If you secure the information by encrypting it before uploading it, you must include a decoding procedure at the start of your task flow once Amazon EMR retrieves the information from S3.

### VPC

You may add an extra degree of security by starting your EMR cluster's EC2 machines within an Amazon VPC, which is equivalent to putting it into a private subnet. That gives you power over the whole domain. You may alternatively run the cluster in an Amazon VPC and allow it to access assets on your local network through a VPN service.

## Conclusion

One of the reasons consumers use Amazon EMR is because of its security features. Amazon EMR is used by clients in legislated industries such as financial services and healthcare in connection with their strategic plan. Amazon EMR security parameters additionally make it simple to encrypt data in motion and at rest. As previously said, Amazon EMR might be an excellent fully-ledged choice for administering your organization's big data frameworks.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**