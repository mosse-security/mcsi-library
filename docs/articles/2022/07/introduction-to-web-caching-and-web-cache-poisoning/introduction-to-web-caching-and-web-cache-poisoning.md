:orphan:
(introduction-to-web-caching-and-web-cache-poisoning)=
# Introduction to Web Caching and Web Cache Poisoning
 
Web applications such as e-commerce websites or websites that use Content delivery networks receive a large number of user requests from around the world. In order to deal with growing user requests and balance the load of the main server, web applications use different caching techniques. Caches are typically employed by the use of proxy servers or web browsers to store files such as images, videos, or audio files and different frequently accessed files in the local storage. Web caching is an effective technique that is used to handle growing user requests, improve network capacity, and provide a seamless user experience. This article covers the basics of web caching, how the attackers perform web cache poisoning attacks, the impact of web cache poisoning, and the recommended mitigation techniques.

## What is a Web Cache?

Web Cache is a system used by web applications that is made up of both hardware and software components. A web cache's primary function is to reduce the load on the primary web server by storing or caching the frequently visited content in various locations. The process of saving data for later use, such as a copy of a web page delivered by a web server, is known as web caching. When a user views a web page for the first time, the cache/proxy server, which sits between the user and the main server, stores it or caches it. In order to keep the remote server from getting overloaded, the cache server will intercept each incoming HTTP request. If the user requests for the same page again, the cache server will provide the stored copy of the same web page that was previously cached by the server. To guarantee that only the most recent content is delivered to users of the web application, cache servers are set up to update their content at predetermined intervals or in reaction to specified events. 

## How does web caching work?

Web caching works by utilizing a cache key for the HTTP requests that are assigned by the cache servers. The cache key usually consists of specific components of the HTTP requests such as the request line and the Host header of the HTTP request. For example, consider the following HTTP GET request on the website:

`GET / HTTP/1.1`

`Host: example-site.com`

`X-Forwarded-Host: example.com`

Now if the cache key on this web application consists of the request line and the Host header, then only this part of the request forms the cache key:

`GET / HTTP/1.1`

`Host: example.com`

The inputs of the HTTP request that is included in the cache key are called keyed inputs whereas the inputs that are not included in the key are called unkeyed inputs. This cache key is used by the proxy server to determine whether the request is already cached in the memory or it needs to be forwarded to the main server. The cache server reacts by presenting the user with that copy of the web page if the cache key of an incoming HTTP request matches a request that is already saved on the cache server. This procedure is performed for each subsequent request to the web application.

Web caching provides numerous advantages to the web application. Some of these benefits are listed below:

* Web caching provides the end-user with the required content more quickly, resulting in a better and more seamless user experience.

* By reducing network traffic and congestion, web caching lowers the amount of bandwidth used by the network.

* Web caching employs load balancing through the use of proxy servers to reduce the workload of the main server and prevent it from being overwhelmed or unavailable.

## Types of Web Caching

There are two typical forms of web caching i.e. server-side and client-side web caching. Each of these forms is explained below.

### Server-side caching

Server-side caching, as discussed above, is employed through the use of proxy/caching servers that stores the web server's static content. Each request to the web application is intercepted by these proxy/cache servers to deliver the content quickly and efficiently to the end-user thereby reducing the load of the remote server.

### Client-side caching

Client-side caching, commonly referred to as browser caching, involves the user's browser temporarily storing the web page's resources. In this type of caching, a user's web browser downloads several web resources, including photos, HTML or JavaScript files, and much more, and stores them on the local storage of the user's device. This makes it possible for the web page to load rapidly and greatly enhances the performance of the website.

## What is Web Cache Poisoning?

An attacker conducts a web cache poisoning attack by sending the web server an HTTP request that has been specially designed for malicious purposes. This leads to a malicious response being stored as a cached entry in the web cache and served to the web application's legitimate users. As a result of web cache poisoning, attackers can distribute malicious payloads by exploiting an underlying cross-site scripting or HTTP response splitting vulnerability. An attacker can use the CR (carriage return) and LF (line feed) characters to fill the HTTP header field with several headers due to the HTTP Response Splitting Vulnerability. These headers are consequently included in the response by the server. Web cache poisoning can be difficult to perform correctly for the attackers, but once they are able to conduct it successfully it can be quite difficult to detect. 

## How does Web cache poisoning take place?

The three significant phases of a web cache poisoning attack are as follows. These two phases are covered in more detail in this section.

### 1. Determining and testing the unkeyed inputs

It takes a lot of work on the part of the attacker to carry out this phase of the attack. The ability to accurately identify the unkeyed inputs of the HTTP request is essential to the attack's success. As previously mentioned, whenever the cache server receives a request, it analyses the cache key (certain HTTP headers and request line) and determines whether any HTTP requests already cached in the server are equivalent. When selecting whether to provide the end-user with a cached response, the cache server only looks for the keyed inputs and ignores the unkeyed inputs. Identification of these unkeyed inputs is the first step in this attack.

The attacker manipulates the inputs by injecting random values in the HTTP request headers and observing the changes in the HTTP response from the server in order to discover the unkeyed inputs manually. Inputs that are not keyed can be found by the attacker using cache busting methodology. A cache-busting technique is used by the developers to force the cache server to download another copy of the file in order to replace the cached file on the cache server. Attackers or security testers can use the cache-busting techniques to make sure that a special identifier is appended to the request during testing so that only the tester/attacker can see the outcomes of the web server's caching behavior and that the real-time application users are unaffected.

However, performing this step manually can be difficult as the changes in the response can be subtle and difficult to detect clearly. This step can also be performed by using automated tools such as ParamMiner or BurpComparer extensions in Burp Suite.

### 2. Generate a harmful response from the web server

After identifying the unkeyed inputs, the next step is to cause the main server to respond in a harmful manner. It may be possible for the attacker to inject the malicious payload into these inputs so that it is successfully mirrored back by the server. If the attacker can obtain the input from the HTTP request to reflect back into the response from the web server or dynamically produce some data, then it can be used further to carry out a web cache poisoning attack. 

### 3. Caching the malicious response

After successfully determining the unkeyed inputs and getting the server to reflect the required response, the last step is to finally cache the malicious response so that it can be served to the users of the website. The success of the final step depends upon a variety of factors such as file extension, content type, route, status code, and response headers. At this stage, the attacker carefully examines the caching behavior of the web server through trial and error in order to successfully store or cache the response on the proxy server.

## Web Cache Poisoning Example 1

In order to understand the web cache poisoning attack, let us consider the following scenario. Let us suppose that the HTTP request to a target web application looks like this:

`GET http://example-site.com HTTP/1.1`

`Host: www.example.com`

`X-Forwarded-Host: home`

The response sent by the server as a result of this HTTP request is as follows:

`HTTP/1.1 200 OK`

`Cache-Control: Public`

`...`

`<meta property="og:image" content="https://home/cms/social.png" />`

Suppose that the keyed inputs of this request consist of the first two lines i.e. request line `GET http://example-site.com HTTP/1.1` and the host header i.e. `Host: www.example.com`. The attacker discovers the X-Forwarded-Host header to be an unkeyed input. Thus the attacker decides to manipulate the X-Forwarded-Host header to cache the harmful response on the proxy/cache server.

After some trial and error, the attacker determines that the web server uses the X-Forwarded-Host header to dynamically generate the URL in the meta tag of the web page. This header is normally used while using proxy servers on the web application where the origin of the web application is different from the proxy server's hostname. Therefore this header is used to identify the correct host for which the client request was made. Now let us suppose the attacker injects a simple XSS(Cross-site Scripting) payload in this header to observe if the payload gets reflected back to the attacker without any sanitization or validation. 

`GET http://example-site.com HTTP/1.1`

`Host: www.example.com`

`X-Fowarded-Host: a."><script>alert(1)</script>`

As a result of this request the attacker observes that the payload gets injected in the response as follows:

`HTTP/1.1 200 OK`

`Cache-Control: Public`

`<meta property="og:image" content="https://a."><script>alert(1)</script>"/>` 

Now after successfully generating the harmful response, the attacker decides to send the request once again to the web application. This time the attacker sends the request from a different machine and without the malicious payload while keeping the same cache key as follows:

`GET http://example-site.com HTTP/1.1`

`Host: www.example.com`

Thus the attacker observes that his payload gets reflected and cached into the proxy server successfully. Thus this payload will be served to users who visit the web application and make a similar HTTP request.

## Web Cache Poisoning Example 2

Let us consider another example to understand this attack further. Suppose that the HTTP request to a target web application looks like this:

`GET / HTTP/1.1`

`Host: vulnerable-site.com`

`X-Forwarded-Host: example.com`

The X-Forwarded-Host header in this case is used to import the script from a different source. As a result, the HTTP response looks like this:

`HTTP/1.1 200 OK`

`Cache-Control: Public`

`<script src="https://example.com/resources/js/tracking.js"></script>`

The attacker after a lot of trial and error discovers that the X-Forwarded-Host to be an unkeyed input and that its value is used to form the URL for script import. Let us suppose the attacker creates a malicious script and this script has the following link:

`https://malicious-site.com/resources/js/tracking.js`

The attacker exploits the X-Forwarded-Host header to inject this malicious script and cache this response in the cache server as follows:

`GET / HTTP/1.1`

`Host: vulnerable-site.com`

`X-Forwarded-Host: malicious-site.com`

The HTTP response now uses the X-Forwarded-Host header value as the script source on the web page as follows:

`HTTP/1.1 200 OK`

`Cache-Control: Public`

`<script src="https://malicious-site.com/resources/js/tracking.js"></script>`

Now when the attacker visits vulnerable-site.com, the response is cached and the attacker's malicious script gets executed successfully.

## Impact of Web cache poisoning

The impact of a web cache poisoning attack depends on the damage inflicted by the malicious cached response and the users who are impacted by this response. The injected payload can have an extremely wide user base of impact if the attacker is able to cache a response for a web page of the application that is very often visited. As a result, this attack may be highly damaging if the attacker is successful in using it to obtain sensitive data of the web application.

## Remediation techniques for web cache poisoning

Some of the remediation strategies to prevent web cache poisoning for your web application are as follows:

* The ideal solution would be to completely eliminate web caching altogether. However, since certain online applications rely on caching to provide content to users more quickly, this solution is not practical. As a result, the developers must make sure that caching is limited to web application responses that are strictly static, such as *.js, *.css, or *.png files, or to web pages that are consistently the same.

* Web application developers must thoroughly examine the caching configuration of the cache server. It is because web cache poisoning attacks largely rely on client-side flaws like Cross-Site Scripting to cause more harm. It is the responsibility of the developers to make sure that this configuration does not trust HTTP header values that are not a part of the cache key. Ensure that the HTTP headers are not returned to users in the cached content by the server.

* If your web application incorporates third-party technologies for carrying out certain functions, then the web developers must carefully review the associated security flaws and remediate them by using an extra layer of security controls. In the context of web caching, while using third-party technologies, developers must review the HTTP headers that are supported by them and disable all the unkeyed inputs.

* Last but not least, web developers must patch various flaws including HTTP response splitting and Cross-Site Scripting flaws that can be used by attackers to perform web cache poisoning attacks.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::