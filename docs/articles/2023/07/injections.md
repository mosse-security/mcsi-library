:orphan:
(injections)=

# Injection Attacks

User input in applications serves as a means for users to provide data and instructions to the application, enabling interactivity and personalization. When users interact with the application, they input information through various UI elements such as text fields, checkboxes, and buttons. If the user input is not properly validated and sanitized, it can lead to the exploitation of security vulnerabilities like injection attacks. Injection attacks occur when malicious data, often in the form of code or commands, is inserted into the application's input fields. Injection attacks allow attackers to manipulate, extract, or even delete data, compromise user accounts, or gain unauthorized access to the system. This article provides an overview of various types of injection attacks, their execution methods, and prevention techniques.

## Types of Injection Attacks

### Structured Query Language (SQL) Injection Attack

A SQL database is a type of relational database that uses Structured Query Language (SQL) to manage and manipulate data. It organizes information into tables with predefined columns and rows, allowing for efficient storage, retrieval, and modification of data. 

A SQL injection is an attack that is directed at SQL databases. In this type of attack, hackers manipulate input fields to trick the application into executing unintended SQL commands. This can lead the hacker to gain unauthorized access to the sensitive information stored in the database.

**How does the SQL Injection Attack work?**

Let us consider the following example to understand how this attack works.

Suppose we have a web application that takes user input (e.g., a username and password) and uses it in a SQL query to retrieve data from a database. The SQL query might look like this:

`SELECT * FROM users WHERE username = 'input_username' AND password = 'input_password';`

Here the user is prompted to enter their username and password in the login form. The values input by the user are then matched against the database. However, a malicious user can exploit the SQL injection vulnerability by entering a specially crafted input in the username field:

`' OR '1'='1`

Now after entering this input, the resulting SQL query will look like this:

`SELECT * FROM users WHERE username = ' ' OR '1'='1' AND password = 'any_random_password';`

Here the condition ('1'='1') always evaluates to true in the WHERE clause, causing the query to retrieve all rows from the "users" table, regardless of the provided username or password. This demonstrates how SQL injection can be used to bypass authentication and gaining unauthrorized access to the database. 

**Testing for SQL injection vulnerability**

To check for SQL injection vulnerability, testers need to verify whether the application is susceptible to this form of attack. This involves inputting various forms of malicious data into identified input fields and observing the application's responses. Commonly used payloads to test for SQL injection include the following examples:

* ` ' or 1=1--`
* `" or 1=1--`
* `or 1=1--`
* `' or 'abc'='abc'–-`
* `' or ' '=' '–-`

If the application behaves differently after injecting different payloads, returns more results than expected, or displays any unexpected errors, then it could be vulnerable to SQL injection.

**Preventing SQL injection**

The use of stored procedures is a primary defense mechanism against SQL injection attacks and is supported by the majority of database engines. Stored procedures are precompiled and stored database objects that contain one or more SQL statements. They are typically used to encapsulate and manage complex SQL operations within the database. Stored procedures offer several advantages, including improved performance, code reusability, and enhanced security.

When using stored procedures, input values are passed as parameters rather than being directly inserted into the SQL statement. This means that the values are treated as data and not executable code. As a result, even if an attacker tries to inject malicious SQL code through input fields, the database will treat the input as data and not execute it as SQL commands.

### DLL Injection Attack

A dynamic-link library (DLL) is a collection of reusable code and data that can enhance the capabilities of a program by providing additional functionality. This is achieved by including library routines from the DLL at runtime, allowing the program to access and utilize the DLL's features as needed. 

DLL injection is a technique to insert external code into a running process or program by forcibly loading a dynamic link library into its memory space. This injected DLL then becomes part of the program and can modify its behavior, access its data, or extend its functionality. This type of attack can be used by malicious adversaries to execute unauthorized code, bypass security measures, or steal sensitive data. 

**Preventing DLL Injection Attack**

In order to prevent DLL injection attacks, developers should specify the full path for the DLLs to be used for the application. This ensures that only the intended DLLs are loaded, reducing the risk of a malicious DLL being injected into the program.

### Lightweight Directory Access Protocol (LDAP) Injection Attack

Lightweight Directory Access Protocol or LDAP, is an open and platform-independent protocol used to access and manage directory services over a network. LDAP-based systems utilize this protocol to store and retrieve information from a directory server that stores data entries, such as user accounts, organizational units, and network resources. User input is used to build or modify LDAP queries by incorporating user-supplied data into the query's filter or search criteria.

LDAP Injection is a type of attack that works by injecting malicious input to modify the LDAP query. This can lead to an attacker gaining unauthorized access to sensitive data or even executing unauthorized LDAP operations on the directory system.

**Preventing LDAP Injection**

Preventing LDAP injection involves proper input validation, sanitization, and using parameterized queries or prepared statements to separate user input from the LDAP query construction.

### Extensible Markup Language (XML) Injection Attack

Extensible Markup Language (XML) is a flexible and human-readable format used to store and share structured data. It uses tags to define different types of information, making it easy to organize and understand data. An XML-based system refers to any application or technology that utilizes XML for data representation and communication. In web applications, XML is used to exchange data between different systems, such as a web server and a database, or to communicate between various components of the application.

An XML injection attack is carried out by exploiting vulnerabilities in an XML-based system that does not properly validate or sanitize user-supplied XML input. The attacker inserts malicious XML code into the input fields or data sent to the system, which is then processed by the application. This injected XML can disrupt the intended XML structure, manipulate data, or trigger unintended actions. XML injection attacks are similar to other injection attacks (e.g., SQL injection) and can lead to various consequences, such as unauthorized access, data manipulation, denial of service, or the extraction of sensitive information

**Preventing XML Injection Attacks**

In order to prevent XML injection, developers must validate and sanitize user input before processing it, ensuring that XML data is properly formed and safe for use in the application.

## Conclusion

In conclusion, understanding and mitigating various injection attacks is critical for ensuring application security. To safeguard against injection attacks, it is important to adopt secure coding practices while developing applications and conduct regular security assessments. This will help in the timely rectification of potential vulnerabilities and prevent their exploitation.