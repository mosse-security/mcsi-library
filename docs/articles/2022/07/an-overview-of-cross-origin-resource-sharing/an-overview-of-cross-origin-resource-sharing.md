:orphan:
(an-overview-of-cross-origin-resource-sharing)=
# An Overview of Cross-Origin Resource Sharing
 
The Same-Origin Policy is a security mechanism that prevents the resources belonging to a web application from being shared with another website. The major goal of this policy is to safeguard your web application against many attack methods, including malicious code execution, compromised user passwords, unauthorized disclosure of sensitive information, and much more. However, in today's world, websites exchange a large number of resources with one another in order to provide numerous capabilities and a more seamless user experience. 

One such example is of CDNs(Content Delivery Networks). Content Delivery Networks are geographically distributed servers that distribute content from an origin server by caching the content close to the user's internet access point. Cross-Origin Resource Sharing(CORS) is one such method that permits resources to be accessed without interruption across several domains and offers relaxation of the same-origin policy. The article covers the fundamentals of CORS, the vulnerabilities that arise from security misconfigurations, their effects, and the preventive measures to reduce the likelihood of these vulnerabilities being exploited.

## What is Cross-Origin Resource Sharing?

Cross-origin resource sharing is a process that enables a web application from one origin to request resources from another website having a different origin. The protocol, such as http:// or https://, the domain name, such as www.example.com, and the port number, such as 8080, make up the origin of a web application. The CORS policy is set up on the target web server using HTTP headers, which tell the browser of the requesting web application or the origin if it is permitted to access the web server's resources. Cross-Origin resource sharing enables the transfer of various resources, including media files, images, and much more, between several domains. It's crucial to go over the various CORS HTTP request and response headers in order to comprehend how CORS functions.

### CORS HTTP Headers:

Some of the important headers that are used for CORS implementation are as follows:

**Origin:** This HTTP CORS request header is used by the web browser to send an HTTP request in order to get access to the required resource on the destination web server. This header is used to identify the origin (scheme, hostname, and port) of the web application that is making the resource request.

**Access-Control-Allow-Origin:** This HTTP CORS response header is used in response to the request for access to the target web server's resources. This header in the HTTP response is used to include the origin of the web application from where the request was received by the target web server.

**Access-Control-Allow-Credentials:** This HTTP CORS response header tells browsers whether to expose the response to the frontend JavaScript code when the request's credentials mode (Request. credentials) is set to include. As a result, the browser will only expose the response to the frontend JavaScript code if the Access-Control-Allow-Credentials header is set to true by the target web server.

**Access-Control-Allow-Headers:** This HTTP CORS header is used in response to a pre-flight request and uses the Access-Control-Request-Headers to indicate which headers are to be used in the actual HTTP CORS request to the target web server.

**Access-Control-Request-Methods:** This HTTP CORS header is used to specify the methods that can be used to access the resources on the web server in response to a preflight request. 

### How does Cross-Origin Resource Sharing work?

The underlying web server should be configured to build a whitelist of authorized origins that can access the resources of a web application. As a result, the web server will compare the origin of requesting web application to this whitelist in order to grant access to those resources from origins other than the same origin. Whenever a web application requests access to a resource belonging to the target web server, the web browser of the requesting web application makes an HTTP request to the target web server along with the Origin header. The information about the requesting web application's origin is contained in this header. The Origin header in an HTTP request will look something like this if, for example, a web application with the origin https://example-site.com wants access to some web server's resources:

`Origin: https://example.com`

The Origin of a request for access to a resource will now be checked against a whitelist of authorized locations when it is received by the target server. The Access-Control-Allow-Origin header is only set to the origin of the web application making the request if the requesting web application is permitted to access its resources. This origin is then included in the HTTP response sent to the web application. Therefore, in the case of our example, the Access-Control-Allow-Origin header will be set as follows if it is permitted to access the requested resource:

`Access-Control-Allow-Origin: https://example.com`

### CORS Preflight Requests:

Modern Web browsers include a mechanism called "pre-flight requests" that they utilize to ask the destination web server for permission before sending it an actual HTTP CORS request. This enables the web server to determine whether it trusts and authorizes the requesting web application to access the required resources as well as the methods that can be performed on them. The web server denies all subsequent access requests made by the web application if it is not allowed to access its resources or perform specific methods on them.

The preflight request is in the form of an HTTP OPTIONS request and contains specific request headers in order to describe the future HTTP CORS requests. Specific CORS response headers that explicitly accept the incoming request must be included in the HTTP response by the web server.

### CORS Requests with Credentials:

Sometimes the cross-origin HTTP requests are made that include an Authorization header enabled. Thus the target web server in that case responds by seeking approval for the use of credentials. An HTTP request's credentials are a read-only property that contains the credentials of that request. In order for the credentials to be passed to another origin, the client and the server should be configured to enable their use. This allows the web browser to send cookies, client-side certificates, and basic authentication information along with the request to the web server. 

On the client-side, it is achieved by setting the Request. credentials to include or by setting the req.withCredentials property of the HTTP request equal to true. On the server-side the Access-Control-Allow-Credentials header must be set to true as follows:

`Access-Control-Allow-Credentials: true`

The purpose of this HTTP response header is to inform the web browser of the requesting web application that it is allowed to send authenticated requests to the target web server. You can send credentials to a different domain on cross-origin requests by using the Access-Control-Allow-Credentials header in conjunction with the Request. credentials property. If the web server allows for the use of credentials, it will respond with a true value for the Access-Control-Allow-Credentials HTTP header and will set the Access-Control-Allow-Origin header to the origin of the requesting web application. As a result, the application will be granted access to the user's credentials when a request is sent to the server with the client-side configured to allow the use of credentials. The web browser of the requesting application will send the user's credentials to the requesting web application.

## Cross-Origin Resource Sharing Vulnerabilities:

The underlying web server's security misconfigurations are the primary cause of CORS vulnerabilities in any web application. This gives the attackers the ability to compromise crucial information by using multiple techniques to exploit these vulnerable settings. This section examines several CORS configuration errors and illustrates how they might give a malicious adversary unauthorized access to a web application's resources.

### Using * character to allow access to any origin: 

This is the worst-case situation for CORS misconfiguration. The web application's resources can be accessed by any domain because of the use of the wildcard '*' character. By enabling malicious adversaries to access its resources without any restriction, this configuration invalidates the fundamental tenet of the Same-origin policy. The Access-Control-Allow-Origin header in this instance looks like this:

`Access-Control-Allow-Origin: *`

Now if any attacker that is hosting a malicious website can easily gain access to this web server's resources by sending the web server an HTTP CORS request. 

### Using * character to match names to a domain:

To grant users access to its resources, many web applications tend to construct a whitelist of different origins. The underlying web server verifies the value in the request's Origin header against this whitelist when it receives access requests and decides whether to give access to its resources based on the results. An alternative approach is to use the * character. This wildcard character is quite often used by web applications to grant access to a domain's whole subdomain structure. In other situations, the web application may be set up to permit access to an origin if it has a specific domain name as a prefix or postfix. A web application's resources can thus be easily accessed by any clever attacker by circumventing or bypassing these access limitations.

Let's say, for instance, that a web application permits access to a domain and its subdomains by employing the * character, as in `*.example-site.com`. If an attacker now hosts a malicious website under the domain name `evilsite.example-site.com`, this is a security risk. When the web server receives a CORS request from this origin, it provides the attacker access to its resources by setting the Access-Control-Allow-Origin header to the following:

`Access-Control-Allow-Origin: http://evilsite.example-site.com`

In other cases if a website grants permission to domains beginning with `example-site.com*`, then an attacker can use any domain like this to gain access to the web server's resources:

`Origin: http://example-site.com.evilsite.com`

Thus the web server allows this harmful web application access to its resources by setting the Access-Control-Allow-Origin to the following:

`Access-Control-Allow-Origin: http://example-site.com.evilsite.com`

### Allowing the use of null in the Origin header:

In some situations, a web application may allow the use of a null value in the Origin header. The Origin can be null in one of the following situations:
* Requests coming from a source that doesn't use the typical protocol, domain, and port number scheme such as data: or file: protocol
* Cross-origin redirects (If a cross-origin request redirects to another resource at a new origin, the browser will set the value of the Origin header to null after redirecting)
* Sandboxed Documents (iframes that use sandbox attribute and are typically used by developers of the application to test their code without affecting the application)

As a result, allowing the usage of a null value in the Origin header can enable an attacker to produce cross-origin requests for malicious purposes, such as creating malicious documents using sandboxed iframes to access a web application's resources.

### Blind Reflection of the Origin Header:

The usage of the '*' character to construct a whitelist of domains is not supported by the web browser when working with CORS requests involving credentials. This is a security feature in web browsers that don't allow web developers to assign arbitrary origin in case of CORS requests containing sensitive data. As a result, sometimes developers create the web application in such a way that it reads the value supplied in the Origin field of the HTTP request and simply reflects or duplicates that value in the Access-Control-Allow-Origin header. An attacker can thus leverage this security flaw to launch attacks that can steal private user data, including user cookies, CSRF tokens, and API keys. Let's have a look at the following scenario to help us comprehend this attack:

Our victim has already been authenticated on a web application. A malicious link is included in a phishing email that the attacker delivers to the victim user. When the user clicks this link, it causes an HTTP CORS request to be automatically sent to the target web server on the behalf of the authenticated user. The attacker's malicious script causes the origin of the attacker's website to be specified in the Origin field along with the request to include credentials.

The Access-Control-Allow-Origin header will now use the origin of the attacker's website and the Access-Control-Allow-Credentials header will be set to true as follows if the web application reflects the value of the Origin header without any validation:

`Access-Control-Allow-Origin: http://malicious-website.com`

`Access-Control-Allow-Credentials: true`

The above scenario will cause the victim's web browser to send the user's credentials to the attacker's website. 

## Impact of CORS misconfiguration vulnerabilities:

The confidentiality or integrity of the data in a web application may be compromised by security weaknesses resulting from improperly configured Cross-Origin Resource Sharing settings. This may lead to the modification or deletion of the user-related information or possibly the disclosure of sensitive user data. The effect of these flaws depends on the importance and sensitivity of the information that is compromised and how the attacker might utilize it to their advantage to inflict more harm.

## Remediation Techniques:

The appropriate implementation and setup of CORS settings are critical to preventing the associated vulnerabilities. It is therefore very important for the web developer to gather the security and functionality requirements prior to the deployment of the web application. The web application needs to be rigorously tested for vulnerabilities caused by misconfigured settings after they have been integrated into the web application. The following are some of the methods that can be employed to mitigate CORS-related vulnerabilities:

* The least privilege and need-to-know security principles should be used when designing the web application. Sensitive information should be given appropriate security labels, and access to such information should only be granted to trusted websites following strict security checks. Similar to this, when using Access-Control-Allow-Methods, you should be very specific about which methods are acceptable for use by permitted websites. Some websites may merely require the ability to view resources, while others may require the ability to read and update them, and so on.

* Do not use wildcards for the Access-Control-Allow-Origin header. Instead, create and maintain a proper whitelist of trusted sites for accessing resources. With whitelisting, the scope of your Access-Control-Allow-Origin will be limited to only the sites that deal directly with your primary site or API and exclude any of your sites that do not. When a website requires access to a web server's resources, it should be validated against the access control lists before being granted access to its resources. 

* Do not include null in the whitelist for the Access-Control-Allow-Origin header. An attacker can create a malicious HTTP CORS request using null as its Origin and utilize it to get around the web application's access controls.

* Extensive testing should be done to identify any CORS setup errors and remediate any identified security flaws. Make sure that no access is permitted to arbitrary domains. When access to sensitive information is required, ensure that the Access-Control-Allow-Origin header value is specified correctly.

> **Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).**