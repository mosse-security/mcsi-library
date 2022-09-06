:orphan:
(common-code-injection-vulnerabilities)=

# Common Code Injection Vulnerabilities

Injection attacks are a type of attack that allows attackers to execute malicious code on a server by injecting it into a web application. This can be done through user input, such as via a form field or URL parameter. Once the code is injected, it can be executed by the server, resulting in the attacker gaining access to sensitive data or damaging the server. Injection attacks are a serious threat to web applications and can be difficult to prevent.

## SQL injection:

SQL injection is a type of attack in which malicious code is inserted into user controlled input fields that are later passed to an instance of SQL for parsing and execution. This can allow attackers to gain access to sensitive data, or even execute malicious code on the server. SQL injection attacks are possible when user input is not properly sanitized before being passed to the SQL interpreter. For example, consider a login form that takes a username and password, and then generates a SQL query to check if the provided credentials are valid. An attacker can use this data and craft a malicious text which terminates the SQL command and runs the malicious code.

Check out this blog to know more about [SQL Injection](keep-your-web-application-safe-by-preventing-sql-injections).

## OS command injection:

An OS command injection attack occurs when an attacker can execute system commands on a server by manipulating the parameters that are passed to an operating system command-line interface. This can be done in several ways, but the most common is to inject the malicious command into an input field that is used to execute OS commands. One way to execute a malicious command is to use a special character that is used to delimit commands. For example, in Windows the semicolon `(;)` is used to delimit commands, so an attacker could inject a malicious command after a legitimate command that is delimited by a semicolon.

## Cross-site scripting (XSS):

Cross-site scripting (XSS) is a type of injection attack typically found in web applications. When a user views a page, the malicious code is executed by the web browser, resulting in the execution of the attacker's code. For example, a web application may allow users to post comments on a blog. If the application does not properly sanitize user input, an attacker could post a comment that contains malicious code. When other users view the comment, the code would be executed by their web browser, resulting in the execution of the attacker's code.

Check out this blog to know more about [XSS](secure-your-web-application-against-cross-site-scripting-xss).

## Template injection:

Template injection is a type of attack where a malicious user inserts code into a template, resulting in the execution of the code when the template is rendered. Template injection can be used to attack any system that uses templates, such as web applications, word processors, and even some desktop applications. The most common type of template injection is done through the use of server-side scripting languages, such as PHP, ASP, and JSP. These languages allow the template to be dynamically generated based on input from the user.

## XPath injection:

XPath Injection is a type of code injection attack that exploits how some web applications use XML data. An attacker can use XPath Injection to target specific information stored in the XML database. The attacker first identifies a target web page that makes use of XML data. The attacker then crafts a malicious input that is designed to exploit how the target page processes XML data. When the attacker's input is processed by the target page, it can allow the attacker to access information that would normally be inaccessible. The best way to prevent XPath injection vulnerabilities is to use a whitelist approach when validating XPath expressions.

## Prevention methods:

Several effective measures can be taken to prevent injection attacks. First, input validation should be used to ensure that all data entered into a system is clean and free of malicious code. Second, data sanitization should be performed to remove any potentially dangerous characters or strings that could be used to exploit a system. Finally, access control measures should be put in place to restrict access to sensitive data and systems. By following these simple steps, organizations can greatly reduce their risk of becoming the victim of an injection attack.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
