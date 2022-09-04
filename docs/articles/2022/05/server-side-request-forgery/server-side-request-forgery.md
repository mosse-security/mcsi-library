:orphan:
(server-side-request-forgery)=
# Server-side request forgery
 

Server-side request forgery (SSRF) attacks are a type of attack in which the attacker tricks the server into making a request to a third-party resource on behalf of the attacker. This can be done by specifying a malicious URL in the request parameters, which the server then attempts to resolve. This can lead to sensitive data being leaked, or the attacker gaining access to internal systems that are not normally accessible from the public Internet.

## How does an SSRF attack work?

In this blog, we will look at some of the common Server-side request forgery attacks attackers use. 

### SSRF against its own server

In this type of attack, the attacker tricks an application to make an HTTP request to the server hosting the application. This type of attack usually involves sending a URL with the hostname similar to that of the `localhost i.e 127.0.0.1.`

For instance, let's consider an e-commerce website that allows a user to check which shop is near to the user's location for a product he is looking for, to do this the application has to make an HTTP request to the backend system and send the data such as location and the product type to the server. The request looks like the one below.

```
POST /location/stores/products HTTP/1.0
<Request Headers>

Product_store_info=http://shoppingapp.com:80/location/stores/products/check?locationid=12947&productid=986
```

The above request makes an HTTP request to the server and gets the details of all the shops near the user's location which has the product the user is looking for. 

The attack captures the request using tools like Burp Suite and edits the request to get info from the same local server, for instance, the attacker can try to get access to admin details which are only meant to open in the organization's internal network, or if the IP address in that of `localhost i.e 127.0.0.1 `

```
POST /location/stores/products HTTP/1.0
<Request Headers>

Product_store_info = http://localhost/administrator
```

Here the server is tricked to retrieve information from the directory /admin, usually, if a normal user tried to access the admin account he will be blocked, but in this case, the server is making the request so the request is validated by default and the attacker gets access to admin account. 

### SSRF in Open redirect

Sometimes an attacker uses an open redirect vulnerability and performs a successful SSRF attack.

For instance, if the website has an open redirect vulnerability the attacker can manipulate the server and request the malicious backend server. The URL looks like the below

```
POST /location/stores/products HTTP/1.0
<Request Headers>

http://shoppingapp.com:80/location/stores/products/check?locationid=12947&productid=986&Path=http://example.com
```

In this case, the server first checks the location of the stores after which it requests the attacker-controlled `example.com`.

## SSRF prevention measures

There are a few different ways to prevent server-side request forgery (SSRF), but the most common is to simply check the URL that is being requested. This can be done by looking at the hostname and/or the IP address to see if it matches the expected values.

Additionally, any parameters that are being passed in the URL should be checked to see if they are valid before making the request.

Another common way to prevent SSRF is to use a whitelist of approved URLs. This can be done by maintaining a list of known good URLs and only allowing requests to those URLs. Any requests to other URLs would be automatically rejected. 

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**