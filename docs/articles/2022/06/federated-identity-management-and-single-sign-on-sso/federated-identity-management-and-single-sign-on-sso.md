:orphan:
(federated-identity-management-and-single-sign-on-sso)=
# Federated Identity Management and Single-Sign-On (SSO)
 

Employees in an organization are provided access to various resources and applications in order to perform their day-to-day responsibilities. Instead of requiring the user to create a different set of credentials to access each application or different resources, the organization employs SSO (Single-Sign-On) and federated identity management technologies which results in smoother access to these resources/applications. These technologies when implemented correctly, increase functionality and protect organization's valuable assets. This article covers the federated identity management concepts, different frameworks used for its implementation, and the security challenges related to it.

## What is SSO(Single-Sign-On)?

SSO is a technology/function that allows a user to authenticate once and then continue to access multiple resources in the network environment without having to re-authenticate. Some of the most significant advantages of using SSO technology are as follows:

* User experience is enhanced because the user does not need to remember several passwords to access various resources. It also lowers the risk of password compromise by removing the need to save numerous passwords in an insecure manner. (for example, scribbling passwords on a piece of paper)
* SSO reduces administrative overhead for IT support department by reducing the time and effort necessary to reset forgotten user credentials. It also eliminates the need of creating and managing several accounts for a single user.
* SSO allows the centralized and efficient management of user credentials as well as the access privileges that are provisioned to the authenticated user.

## What are Identity Federation and Federated Identity?

Identity Federation, also known as Federated Identity Management, is the act of linking a user's many identities across multiple locations without the need for synchronization or consolidation. Identity federation enables the development of trust between two parties for user authentication, as well as the transmission of this information to relying parties for resource authorization.

A federated identity is a portable identity with associated rights that can be utilized across organizational boundaries. It enables a person to be authenticated once in order to gain access to multiple IT systems and services. Federated Identity provides a convenient way for businesses and customers to access resources, and it is widely utilized in e-commerce platforms. The following are the main components of federated identity management system:

### Identity Provider

The identity provider is a service or a system that is responsible for end user authentication. It is also responsible for issuing of assertions related to the user identity and profile information to the relying parties within a federated or distributed environment. Identity provider is used to store and manage user credentials and allows for the central management of user access rights across different systems or applications.

### Service Provider

A Service Provider is an application or a service that trusts and relies on the Identity Provider for user authentication. A service provider receives the information about the user's identity, his particular attributes, and his associated rights in form of assertions. The service provider then creates a user session based on these assertions and allows the user access to the resources depending upon his rights as established by the Identity Provider. The service provider is not responsible for user authentication; instead, it is merely interested in knowing if the user was properly authenticated in order to provide the user access to its resources.

### Principal

A principal is typically an end user that is requesting access to the system or application.

Federated Identity Management and SSO allows for the central management of federated access to multiple applications and makes it easy for the users to access their accounts and different business applications/service from one place. It also allows for multiple enterprises to exchange user authentication information so that users can use the same identity to access resources across different platforms. For example, a user can access Instagram by using his Facebook credentials to login into Instagram.

## Frameworks used for Identity Federation:

There are different standards and frameworks that are used to manage the federated identity across different enterprises. These frameworks are developed to maintain the security of the user information while providing the user seamless access to resources. This section reviews these frameworks in greater detail.

## SAML(Security Assertion Markup Language):

Security Assertion Markup Language is an XML-based standard that allows for the exchange of authentication and authorization information between different security domains. XML(Extensible Markup Language) is a universal and foundational standard that defines the structure for the development of various markup languages which are interoperable among different web technologies and provide various functionalities. SAML is also an interoperable standard that is used to communicate a user's identity to various on-premises and cloud service providers. The latest version of SAML is SAML 2.0 and it has been in use since 2005.

SAML allows for the management of federated identity in business-to-business(B2B) and business-to-consumer(B2C) transactions. SAML enables the organization to create only one login for the user so he can use that identity for access to different services available on the company's premises or in the cloud. SAML standardizes the communication between the identity provider and the service provider that ensures the protection of the federated identity.

### How does SAML work?

By delegating the federated identity, SAML allows users to effortlessly access various applications and services such as customer relationship management system, Active Directory, corporate email, and so on. By entering his credentials, a user logs into the enterprise's SSO authentication system. The SAML protocol is then used by the organization's identity provider to deliver the user's login name and associated characteristics to the service provider. The service provider then interprets this data in order to grant the user access to protected resources. Consider the following scenario to better understand how SAML works:

Suppose your organization uses Gmail as the email service provider for the employees. However, the company employs SSO authentication services on premises in order to maintain control over user credentials and protect them from security compromise. Now whenever a user wants to access his Gmail account, his authentication request is redirected to the organization's SSO authentication system that authenticates the user and forwards the response to the Gmail which then allows him to access his email account.

It is very important to note that two communicating systems using SAML must be configured to use the same type of authentication data. Thus before the communication using SAML can take place, identity provider and service provider must agree upon configuration parameters so that the authentication and authorization can be carried out properly.

### SAML Assertions

SAML assertions are XML documents that contains important user information in the form of statements that are sent by the identity provider to the service provider. There are three types of SAML assertion statements which are described as follows:

- *Authentication statements:* Authentication assertions are used to verify the identity of the user as well as provide important information regarding the method/mode and time of the authentication.
  
- *Attribute statements:* Attribute statements are used to relay important information regarding the attributes of the authenticating user such as the user's role in the organization, the department for which they work, contact information such as email address, and much more.
  
- *Authorization decision statements:* Authorization decision statements are used to relay important information regarding permissions being granted to users to access the service. They are also used to specify if the user has been denied access to the service due to authentication failure or lack of user permissions.

## OAuth(Open Authorization):
OAuth is an open standard of authorization (not authentication) for third-party services or applications. OAuth enables your information that is present on different websites to be used by third parties. OAuth enables users' account information to be shared in such a way that doesn't expose sensitive information such as user account credentials. This delegated authorization occurs in the form of access tokens being granted to third parties to access specific information. The latest version of OAuth is OAuth2.0 which has been currently adopted by a large number of service providers across the world. (e.g. Apple, Google, Facebook, LinkedIn, etc.)

Consider an example to understand authorization process in OAuth. For example if you made an account on LinkedIn and after making the account the system requests access to your Google contacts so it can import contacts that are already present on LinkedIn. If you agree, then you see a window that asks you if allow LinkedIn access to your accounts. If you click yes then an authorization/access token is granted to LinkedIn to access only the information(i.e. your contacts) that you authorize for a limited time period.

### OAuth Roles:

The essential roles in the OAuth2.0 framework are as follows:

**Resource Owner**

The Resource Owner is the entity or the user that grants the third-party service access to the protected resource.

**Resource Server**

The Resource Server is the server that is hosting the resource. This server is responsible for verifying the access token and provides access to the resources to the third party.

**Client**

The Client is the third-party service that is requesting access to the protected resource on the behalf of the resource owner.

**Authorization Server**

The Authorization Server is responsible for authenticating the Resource Owner(i.e. user) and issues access tokens to the third party service after receiving the consent for access to the protected resource from the Resource Owner.

### How does OAuth work?:

The basic steps of how different roles interact with each other in an OAuth2.0 framework are as follows:

1. The client(third party service) requests access to protected resources from the Resource Owner(user).
2. If the Resource Owner grants consent to access the required resource to the client, it receives the authorization grant.
3. The client presents the authorization grant to the authorization server and requests an access token.
4. After the successful client authentication and validation of the authorization grant, the authorization server grants the client the requested access token.
5. The client then presents the access token to the resource server that contains the protected resource.
6. After the successful verification, the resource server allows the client access to the requested resource.

## OIDC(OpenID Connect):

OpenID Connect is an open authentication protocol that sits on the top of the OAuth2.0 framework. OIDC uses the same architecture and components as OAuth. OIDC is developed for performing user authentication whereas OAuth is an authorization protocol that provides clients(third party services or applications) delegated access to the resources owned by the end user. 

This protocol was developed by the OpenID foundation and allows the clients(third-party services) to verify the identity of the user based on the authentication performed by the authorization server. It allows for the collection of basic user profile information to be used by third-party applications. OpenID connect encodes user identity information in the form of JSON web tokens that are also called ID tokens. These  ID tokens are separate from the access tokens that are generated to grant access to the resources owned by the end user. The ID tokens match the standard flow of OAuth2.0 and can be used with a variety of web or mobile applications.

### OIDC Roles:

There are two main roles involved in the OpenId Connect framework:

**OpenID Provider** 

OpenID Provider or the Identity provider (same as an authorization server in OAuth framework) is a server that is responsible for end user authentication, getting user consent, and issues the access tokens to the requesting application or service.

**Relying Party** 

The client or the application that is requesting for the user identity is called the relying party. The relying party relies or trusts the Open ID provider for user authentication.

### How does OpenID Connect work:
The basic steps involved in the OIDC framework are as follows:

1. The client or relying party requests OpenID Provider for user authentication.
2. The OpenID Provider authenticates the end user and obtains the user's consent for access to the protected resource.
3. After successful authentication, the OpenID provider provides the relying party with an ID token containing the user identity information and an access token with authorization to access the resource.
4. The relying party then requests additional information about the user by contacting the userinfo endpoint in the OpenID using the access token.
5. The OpenID provider returns the additional user information requested by the relying party or the client application.

## Security Challenges of Federated Identity management:
Federated Identity Management offers a lot of advantages for organizations, however, there are some major security and implementation challenges that the organizations must overcome in order to secure their valuable assets:

* There should be a strong sense of mutual trust between the two parties exchanging information especially if it involves sensitive information such as private customer data. The unauthorized disclosure of sensitive data can have severe implications on the company that is responsible for safeguarding the data. Thus organizations must ensure that their sensitive information is protected by performing regular penetration testing, vendor risk management, and ensuring that third parties have completed security compliance audits such as SOC2, SOX, or HITRUST, among others, to reduce the risk introduced due to third parties.

* There should be adequate security safeguards in place to protect the authentication information shared with the identity providers. These measures should provide appropriate protection against attacks such as person-in-the-middle, phishing, and replay attacks, all of which can result in the compromise of user credentials. As a result, security mechanisms such as multi-factor authentication must be implemented to prevent user credentials from being hacked. Furthermore, any identification information transferred between parties must be encrypted in order to prevent it from being intercepted by malicious adversaries.

* Organizations must take appropriate precautions to protect themselves from threats posed by human factors such as insider threats and human errors. The breach of a single user account can lead to the exploitation of several valuable resources. As a result, to track user activities, adequate security monitoring and logging mechanisms must be in place. Security awareness and training sessions must be held on a regular basis to reduce security threats caused by human errors.

* Organizations must guard against unnecessary privileges being granted to a user to prevent authorization creep. If the user's privileges are not properly provisioned then it can lead to severe security consequences for the company such as loss/theft of sensitive data. Thus organizations must ensure that a federated identity must be allowed only the level of access required for the user's job responsibilities, and any temporary access necessary for short-term projects should be revoked as soon as it is no longer required.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::