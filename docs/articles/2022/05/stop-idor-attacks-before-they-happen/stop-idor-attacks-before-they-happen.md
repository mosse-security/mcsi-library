:orphan:
(stop-idor-attacks-before-they-happen)=
# Stop IDOR Attacks Before They Happen
 

Insecure Direct Object References (IDOR) are a type of vulnerability that occurs when an application references an object such as a database and files using an insecure method. This can allow an attacker to gain access to sensitive data or perform unauthorized actions. IDORs can occur when an application uses user input to reference an object without properly validating or sanitizing the input. 

## How does an IDOR attack work?

To begin with, the malicious actor identifies an application that is using direct object reference to give access to data and information. For instance, let us consider an e-commerce website that is using direct object reference to give the user access to their information. The URL looks like the one below.

`https://shoppingsite.com/accounts/user?id=9876`

After sending a valid request using the above mention URL the user is given access to the data, But this URL can be used by malicious actors to gain access to a different user account by changing the id parameter, the malicious URL looks like the one below.

`https://shoppingsite.com/accounts/user?id=9900`

After sending the above mention URL to the server as a valid request, the server sends the user data for the user `id=9900` as a response, which can be viewed by the attacker. 

IDOR can also be leveraged to gain sensitive data when the user data is stored in static files. For instance, the e-commerce company might save the user data in a numerical file name and for every new data, the file number gets incremented. The URL looks like the one below.

`https://shoppingsite.com/accounts/user/123.txt`

Now the attacker can simply modify the file name to get the data created by other users. For instance, the URL looks like the one below. 

`https://shoppingsite.com/accounts/user/567.txt`

## IDOR preventive measures and best practices

Several preventive measures can be taken to avoid insecure direct object references. 

First, it is important to ensure that all data is properly validated before being used. This means validating user input and ensuring that only the expected data is being accessed.

Second, data should be properly sanitized before being used. This means ensuring that any potentially dangerous characters are removed or escaped. 

Finally, it is important to implement proper access control measures.This means ensuring that only the appropriate users have access to the data they need. By taking these measures, it is possible to greatly reduce the risk of insecure direct object references.

*Best practices include:*

- Object references should not be guessable
- Object references should not be accessed without proper authentication
- Use digital signatures or message authentication codes to verify the integrity of direct object references
- Do not expose direct object references in URLs
- Do not store direct object references in cookies

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**