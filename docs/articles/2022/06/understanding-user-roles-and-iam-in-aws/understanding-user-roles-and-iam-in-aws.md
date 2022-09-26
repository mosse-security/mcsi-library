:orphan:
(understanding-user-roles-and-iam-in-aws)=
# Understanding User Roles and IAM in AWS
 

IAM stands for "Identity and Access Management", it allows you to restrict who and what applications may access the AWS environment which is also referred to as entities or principals. Today, in this article we will explore fundamental principals in IAM.

## What is a Principal?

A principal is an IAM unit that has access to AWS services. A principal can be either constant or transitory, and it can represent either a person or a program. Let's start with exploring the first principal which is Root.

## Root User

When you register an AWS account, you only have a single log-in principal with unrestricted access to all Amazon Web services in the profile. The root account is the name given to this authority. The root user for that association will continue for as long as you have an active account with Amazon. The root user may access the Cloud environment through GUI as well as programmatically. The root in AWS is comparable to the UNIX root or Windows Administrator account in that it has complete access to the account, as well as the ability to terminate it. It is highly suggested that you should not utilize the root user for any everyday tasks, including operational ones. Rather, follow best practices by creating your initial IAM user with the root user and afterward safely put away the root login information.

## IAM Users

Users are durable entities created by the IAM service to identify specific individuals or apps. You may establish individual IAM users for every participant of your operations department so that they can communicate with the terminal and utilize the CLI. You may also establish development, test, and production users for apps that need AWS Cloud services. Principals with IAM operational capabilities can establish IAM users at any moment. Users are resilient in the sense that they have no expiry date; they are continuous units that remain until an IAM admin deletes them.

## Transient Security Tokens and Roles

Roles and temporary security tokens are critical for sophisticated IAM utilization, but many AWS customers are perplexed by them. Roles are used to provide individuals with specific privileges for a fixed period of time. AWS or another trustworthy third party can verify these users.
If one of these players takes on a role, AWS issues the user a transient security token that allows the agent to access AWS Cloud-based services. When acquiring a temporary security token, you must specify how long the token will be valid until it expires (16 minutes-36 hours).

A variety of use cases are enabled by roles and temporary security tokens:

- Amazon EC2 Roles: Allowing access to apps operating on an EC2 instance.
- Cross-Account Access: Providing rights to users in other AWS accounts, regardless of whether you manage these profiles.
- Federation: Assigning privileges to users who have been confirmed by a dependable third party.

## Summary

This blog article discussed the several principals that can engage with Amazon web services: Roles/Temporary Security Tokens, Root, and IAM Users.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::