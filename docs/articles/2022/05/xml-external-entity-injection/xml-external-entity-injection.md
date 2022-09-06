:orphan:
(xml-external-entity-injection)=

# XML External Entity Injection

XXE (XML External Entity Injection) is a common web-based security vulnerability that allows an attacker to interfere with a web application's processing of XML data. XXE is a common security flaw because XML is an extremely popular format used by developers to transfer data between the web browser and the server.

XML necessitates the use of a parser, which is where most vulnerabilities occur. The content of a file path or URL can be used to define an entity in XXE. When the server reads the XML attack payload, the external entity is parsed, merged into the final document, and returned to the user with the sensitive data inside.

XXE attacks can result in internal network port scanning, server-side request forgery (SSRF), data exfiltration, and the use of an organization's servers to perform denial of service (DoS), among other things. As a result, XXE prevention strategies must be implemented.

XXE attacks are a powerful method of exploiting applications due to the numerous ways in which they can be exploited, including:

- Implementing an SSRF (Server-Side Request Forgery) attack
- Obtaining file contents by requesting the application's response
- Forcing error messages through blind XXE, possibly displaying sensitive data in those parsing error messages

## XXE Prevention in common programming languages

Smart coding practices can prevent XXE, and we'll go over some of the most popular programming languages where this vulnerability occurs.

**XXE Prevention in Python:**

Python's popularity brings with it a plethora of amazing things, as it allows for the creation of an infinite number of modules. However, because many of these modules aren't built with safety in mind, this luxury frequently comes at the expense of security. In Python, the following are some of the most popular XML parsers: `Pulldom`, `Lxlm\sSax\sEtree`, `Genshi\sXmlrpc`, `Minidom`.

Etree, Minidom, Xmlrpc, and Genshi are all secure by default and do not require any additional action to protect against XXE injection. However, there is a way to secure each of these parsers, and that is with defusedxml. It is fully compatible with any of the above packages and provides complete protection against potential XXE attacks.

When an attempt is made to access local or remote resources in an external entity, Defusedxml throws an exception.

**XXE Prevention in C/C++:**

XXE appears frequently in C/C++. This problem arises as a result of the use of Libxml2, an XML parser. However, the problem is that libxml2 allows external entities by default.
Fortunately, there is a way to avoid this from happening.

You can install your own entity loader using `xmlSetExternalEntityLoader`, which allows you to control which URLs are loaded, preventing unwanted behavior in your application.

**XXE Prevention in Java:**

Hackers who use XXE attacks love Java because most Java XML parsers are vulnerable to XXE, making your life difficult.
For example, one of the most popular Java parsers, dom4j, used to be vulnerable to the XXE vulnerability, and it's very likely that most Java applications still are. To avoid this behavior and prevent XXE attacks, you should update dom4js to at least version 2.1.3.

**XEE Prevention in .NET:**

Since version 4.5.2 of .net, preventing XXE attacks is no longer an issue. While .net applications built with this framework were vulnerable until 4.5.1, this issue has now been resolved, and you can rest assured that your applications are secure.

In an ideal world, we'd all be using the most recent versions, but that's not always possible. But don't worry, there is still hope for you! The simplest way to keep your code safe is to simply disable any external resources using XmlResolver.

**XXE Prevention in iOS:**

iOS developers will mostly face the same issues with XXE attacks that C/C++ developers do. iOS, like C/C++, makes use of the libxml2 parsing library. Despite the fact that libxml2 version 2.9 automatically protects against XXE, iOS6 and older use the old libxml version, resulting in vulnerable code.

This is where NSXMLDocument enters the picture. It's an iOS feature built on top of libxml2, and you can easily protect yourself against XXE by using the following command when creating a new NSXMLDocument:
`NSXMLNodeLoadExternalEntitiesNever`.

**XXE Prevention in PHP:**

As you are probably aware, PHP is one of the most popular server-side languages available. It's widely used in web applications, making it an ideal target for malicious attacks.

This is especially true for XML parsing, which is frequently used with PHP. The good news is that XXE attack prevention is relatively simple to implement. All you have to do when using PHP's default XML Parser is add the following line to your code:

`libxml_disable_entity_loader(true);`

This prevents external entities from being loaded, keeping your application safe.

## Final Words

As we can see, the XEE attack is a serious vulnerability that attackers can use to gain access to sensitive data. Because of the way XML parsers handle external entities, this type of attack is possible. It is critical to use a less vulnerable XML parser, such as the one provided by the Apache XML project, to protect against this type of attack. It is also critical to set your XML parser to reject external entities.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
