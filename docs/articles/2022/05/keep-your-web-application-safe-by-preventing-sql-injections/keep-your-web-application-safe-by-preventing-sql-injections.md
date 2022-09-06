:orphan:
(keep-your-web-application-safe-by-preventing-sql-injections)=

# Keep Your Web Application Safe by Preventing SQL Injections

SQL injection (or SQLi) attacks alter SQL queries by injecting malicious code through application vulnerabilities. SQLi attacks that are successful allow attackers to modify database information, access sensitive data, perform administrative tasks on the database, and recover files from the system. In some cases, attackers have the ability to execute commands on the underlying database operating system.

## Impact of SQL injection on the database

**Steal credentials:** Through SQLi, attackers can obtain credentials and then impersonate users in order to use their privileges.

**Database access:** Attackers can gain access to sensitive data stored on database servers.

**Change data:** Attackers can change or add new data to the accessed database.

**Delete data:** Attackers can delete individual database records or entire tables.

**Lateral movement:** attackers can gain access to database servers through operating system privileges and then use these privileges to gain access to other sensitive systems.

## Examples of SQL Injection Attacks

SQL injection can be classified into several types:

**Union-based SQL Injection** – The UNION statement is used in Union-based SQL Injection, which is the most common type of SQL injection. The UNION statement combines two select statements to retrieve data from the database.

**Error-Based SQL Injection** – This method is only applicable to MS-SQL servers. The malicious user causes an application to display an error in this attack. Typically, you ask the database a question, and it responds with an error message that includes the data you requested.

**Blind SQL Injection** – no error messages are received from the database in this attack; we extract the data by submitting queries to the database. Blind SQL injections are classified into two types: boolean-based SQL injection and time-based SQL injection.

SQLi attacks can also be classified based on how they inject data:

**SQL injection based on user input** – web applications accept user input via forms, which then send the user's input to the database for processing. An attacker can inject malicious SQL statements if the web application accepts these inputs without sanitizing them.

**SQL injection based on cookies** – modifying cookies to "poison" database queries is another approach to SQL injection. Cookies are frequently loaded by web applications and their data is used as part of database operations. A malicious user or malware installed on a user's device could modify cookies, allowing SQL to be injected in an unexpected way.

**SQL injection based on HTTP headers** – SQL injection can also be performed using server variables such as HTTP headers. Fake HTTP headers containing arbitrary SQL can inject code into the database if a web application accepts input from HTTP headers.

**Second-order SQL injection** – these are the most complex SQL injection attacks because they can go dormant for a long time. A second-order SQL injection attack sends poisoned data, which may be benign in one context but malicious in another. Even if developers sanitize all application inputs, they may still fall victim to this type of attack.

## How to Prevent an SQL Injection?

Input validation and parametrized queries, including prepared statements, are the only certain ways to prevent SQL Injection attacks. Never use the input directly in the application code. All input, not just web form inputs like login forms, must be sanitized by the developer. They must eliminate potentially malicious code elements like single quotes. On your production sites, you should also disable the visibility of database errors. SQL Injection can be used to gain information about your database by exploiting database errors.

## Final Words

SQL injections are a serious threat to any website or application that relies on a SQL database. If you're not familiar with SQL injections, they are basically a way for attackers to inject malicious code into your database in order to extract sensitive information or wreak havoc on your data. While there are many different ways to prevent SQL injections, the best way is to use parameterized queries. Parameterized queries basically involve using placeholders for your SQL code, which makes it much harder for attackers to inject malicious code into your database.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
