:orphan:
(an-overview-of-directory-traversal-attacks-in-a-web-application)=
# An Overview of Directory Traversal Attacks in a Web Application
 
Server security is a major problem for different enterprises. Due to their importance in ensuring the smooth operation of all other components of an information system such as networks, applications, or infrastructure, servers are frequently the primary targets of attacks. A web server hosts several files that must be protected from unauthorized access, either because they contain private information or because they are critical for the proper functioning of different services running on the server. These files include database records, configuration files, and files for server web applications, among many other things. In order to protect these files from unwanted disclosure, access, modification, or loss, the web server must be equipped with a number of security safeguards. 

The absence of such security controls can lead to a malicious adversary taking advantage of different security flaws to execute attacks that can have severe repercussions for the web application. One of the ways in which an attacker can get a hold of the confidential or sensitive files stored on the web server is through a directory or path traversal attack. This article goes over the basic concepts related to a path/directory traversal attack, its impact, how this attack works, and the different techniques that can be used to prevent the execution of this attack on a web server.

## What is a Directory Traversal Vulnerability?

Directory traversal vulnerability also called a path traversal vulnerability, is a security flaw that enables an attacker to read or obtain access to files located outside the web server's root directory or even issue commands on the server. The root directory of a web server is the base folder that is openly accessible to the public and is often referred to as the document root, web root, or site root directory. The index file for the web application, such as index.php, index.html, or default, is also located in this folder. The attacker's objective in a directory traversal attack is to navigate directories in order to access sensitive files that are typically off-limits. The underlying web server's security configuration error is the primary factor in the successful exploitation of the directory traversal vulnerability.

When a web server accepts input from the user through the web application's interface without sufficient validation or sanitization, it can lead to a malicious adversary getting access to restricted files on the web server. Threat actors frequently search through a directory tree in order to find routes to prohibited files on web servers before launching this attack. In some cases, an attacker might also be able to modify or write to important files on the web server or even lead to the attacker taking control of the server and result in a remote code execution attack. 

The web application runs from the root directory and doesn't allow its users to navigate outside the root directory of the web application. The exact location of the root directory depends upon the target operating system and the server hosting the application. For example, the root directory for an Apache server for Linux or mac operating system is "/var/www" whereas the root folder is "C:\Inetpub\www\root" in the case of a Windows operating system. Directory traversal attacks, although not very common, are particularly devastating for the web application. 

## Why do Directory traversal attacks occur?

As previously stated, a web server hosts plenty of resources such as images, text, CSS, Javascript, HTML files, etc. The web server uses these resources to perform various important tasks regarding the web application. Sometimes the web application allows the user to include these internal server resources via its input parameters. The directory traversal attack occurs when the web application has the following security weaknesses:

* The web application accepts the user input without sufficient validation or sanitization on the server side

* The web server has improper access control restrictions for the resources that are stored on it.

A malicious adversary can craft a malicious HTTP request to the web application in order to gain access to the resources that are not meant to be accessed by regular users of the web application. 

## What is the Impact of a Directory traversal attack?

An attacker can exploit this vulnerability to escape the root directory of a web application and gain unauthorized access to the restricted files on the web server. The malicious adversary can utilize this information to carry out further harmful activities such as complete takeover or compromise of the web server, stealing sensitive or confidential information (e.g. user passwords, customer records, credit/debit card numbers, etc.), modifying the behavior of the application and much more. Depending on how the user interface for accessing the website is configured, the attacker may also be able to run instructions on the web server under the context of a user that is connected to the web application. The success of this attack depends upon the access control restrictions on the website and the operations that the current user of the web application is allowed to perform.

## How do the Directory Traversal attacks work?

An attacker only requires a web browser and different reconnaissance tools to identify and locate default files and folders on the target system in order to conduct a successful directory traversal attack. An attacker can manipulate the file reference variables by using absolute file paths or by using the dot-dot-slash (../) character sequences i.e. relative file paths to perform a directory traversal attack. The (../) character is used to escape the current directory of the web application and goes one level up from that directory. A relative file path refers to the user's current directory in the web application. An absolute path, on the other hand, contains the root element and the complete directory list required to locate the file.

In order to understand how the path traversal attack works, consider the following example. Suppose the web page in a web application has the following URL:

`https://example-site.com/home.php?filename=somefile.php`

Now if the user accesses this web page using the above URL, the web server receives the request to fetch the file on the web server that is supplied in the "filename" parameter. Therefore the web server takes the value that is supplied by the user in the filename parameter and sends it in the response sent by the web server. Now after some trial and error, the attacker discovers that this parameter can fetch any files on the web server. The attacker can then exploit this vulnerability to access restricted files on the web server. Suppose the web server of the application is hosted on the Windows Operating system. The attacker can then use the dot dot slash (../) character sequence to escape out of the current directory and traverses directories to access the system files stored on the web server as follows:

`https://example-site.com/home.php?filename=..\..\..\..\Windows\system.ini`

In the Windows Operating system, the system.ini is a system initialization file. This file is a text file containing the configuration used by the operating system when it starts up. The `filename=..\..\..\..\Windows\system.ini` parameter will cause the dynamic page to retrieve the file system.ini from the file system and display it to the user. The expression ..\ instructs the target system to go one directory up and is commonly used as an operating system directive. The attacker has to guess how many directories he has to go up to find the required Windows folder on the system. However, this can be easily done by using the trial and error method.

It might be possible for an attacker to use a null byte (% 00) to effectively terminate the file path prior to the required extension if an application mandates that the user-supplied filename must conclude with an expected file extension, such as .php, .asp, .html, etc. For example, consider the URL from the above example:

`https://example-site.com/home.php?filename=somefile.php`

Now let us suppose the web server is hosted on the Linux operating system and requires that the filename parameter ends with a .php extension. The attacker can then use the null byte terminating character to access the /etc/passwd file on the web server. The /etc/passwd file contains usernames and password information for the users that are registered on any Linux operating system. The attacker can craft a malicious request to request the /etc/passwd file stored on the Apache web server hosted on this Linux operating system as follows:

`https://example-site.com/home.php?filename=../../../etc/passwd%00.php`

In this case, the request to the web server will be terminated at the null byte character and the .php extension will be ignored by the web server giving the attacker access to the /etc/passwd file successfully.

## Testing for Directory Traversal vulnerabilities

You may find directory traversal bugs and vulnerabilities in your web applications using a variety of testing methodologies. This section goes over some of the testing techniques that are in line with the recommendations offered by [OWASP](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md) (Open-Source Web Application Security Project).

### Identification of Web Application Injection Points

The first step in testing for directory traversal vulnerabilities is to identify all the attack vectors in the web application. This step involves the identification of all input parameters of the web application under consideration such as HTTP GET or POST requests parameters, different URL parameters, website forms, file upload forms, user comment section, etc. 

### Evaluation of Web Application Injection Points

This step involves a systematic evaluation of all the input parameters of the web application. This step will help in discovering if these input parameters lack sufficient validation and sanitization. Some of the important factors that must be checked after identifying the input parameters are as follows:

* It is important to evaluate these input vectors for interesting parameter names such as item, file, home, etc. 

* It is important to check if these parameters are related to operations requiring files. An example of this would be the use of include or require functions in a PHP-based web application.

* It is important to check these parameters for unusual file extensions.

* It is also important to identify if there are any cookies used by the web application for the dynamic generation of pages or templates.

### Discovering Vulnerable Inputs

After evaluating all the input parameters of the web application, it is necessary to identify if these parameters are exploitable i.e. if the input validation mechanisms can be bypassed to perform an attack. In order to successfully test for this flaw, the application security tester needs to have sufficient knowledge of the target system being tested (e.g UNIX, Linux, Windows, etc.) and the location of the files being requested. There are several encodings to check for this vulnerability. Some of these encodings are as follows:

* ../
* ..\
* ..\/
* %2e%2e%2f
* %252e%252e%252f
* %c0%ae%c0%ae%c0%af
* %uff0e%uff0e%u2215
* %uff0e%uff0e%u2216

A complete list of different payloads that can be used to discover directory traversal vulnerabilities can be found by visiting this [Github] repository(https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal).

## Preventive Techniques to Mitigate Directory traversal Attacks

This section goes over some of the recommended techniques that can be used to prevent directory traversal attacks in a web application. 

* One of the best techniques to prevent and mitigate the risk due to directory traversal attacks is to avoid passing user-supplied input into the filesystem APIs on the web server altogether. However, in many cases, the web application's functionality doesn't allow this and it is necessary to pass user-supplied input to filesystem APIs. In that case, it is imperative to apply the following controls in a defense-in-depth approach.

* The web application must have sufficient mechanisms that properly validate and sanitize the user-supplied input so that the users cannot access the restricted files or directories on the web server. The web application should not directly utilize the user-supplied data that is then used to determine the filename or part of it while accessing files or folders on the web server. However, if the user-supplied input is used, it must first satisfy a number of prerequisites, such as verifying that the filenames only contain alpha-numeric characters or determining whether the user has the necessary access rights to access the requested files.

* The web application developers can also implement a whitelist of allowed values for files in a web application such as files or folders that can be accessed, expressions that can be a part of the filesystem input parameters, etc.

* The web application should only allow specific file extensions to be used with the files in the web application. This can be achieved by hard coding specific file extensions to the requested filenames.

* The files and folders on the web server should have proper access restrictions. These access permissions must be defined and implemented in the form of proper access control lists. These access permissions should be implemented in such a way that is in line with the principle of least privilege. The principle of least privilege states that only the minimum access rights to a website's resources are to be assigned to its users. The web application should only allow the users to access those files or folders that they are authorized to access and these rights should be in effect for the shortest possible duration.

* Use web application vulnerability scanners to discover directory traversal flaws. Using these vulnerability scanners can help identify any inputs of the web application that can reveal hidden files or folders stored on the web server. Additionally, the web application must be periodically tested to discover security flaws. These vulnerabilities must be remediated according to the guidance provided by the application security testers.

* If the web server software is not patched to the latest version, then it is highly likely that a malicious adversary can attempt to exploit its security flaws that are known to the public. Ensure that the underlying web server software is updated to the latest version. This will ensure that the web server is fully patched to prevent the exploitation of the known security weaknesses in the previous versions of the server software.

> **Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).**