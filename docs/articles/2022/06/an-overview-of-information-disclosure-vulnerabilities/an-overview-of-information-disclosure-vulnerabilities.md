:orphan:
(an-overview-of-information-disclosure-vulnerabilities)=
# An Overview of Information Disclosure Vulnerabilities
 

In the reconnaissance stage of a penetration test, hackers, security testers, or bug bounty hunters gather pertinent data about the target application or network under consideration. The information acquired during this stage can provide the hacker or security tester with extremely valuable information about the target web application. Information disclosure vulnerabilities in web applications can lead to the attacker gaining information in an unauthorized manner that can help them to devise an effective hack strategy. This article covers the fundamentals of information disclosure vulnerabilities, the sources in the web application from where you can find significant information, the impact of these vulnerabilities, and several preventive strategies.

## What is meant by Information Disclosure?

Information disclosure, also known as sensitive information exposure, occurs when a web application releases or exposes sensitive or restricted information to persons who are not authorized to have access to it. This leaked information can vary in sensitivity or criticality for the organization. It might include sensitive information like passwords, PII (personally identifiable information), credit/debit card numbers, the organization's intellectual property, or data specific to an application, such as session identifiers, directory information, stack traces, back-end source code, and many other things.

The sensitive information may be revealed in a number of ways, such as by a user who is simply using the web application as intended or by a determined attacker who is aiming to gain sensitive information by fuzzing the application interfaces and monitoring the response. The majority of the time, information that is leaked cannot be directly exploited, but a malicious adversary who exploits the knowledge for his own ends may find it to be quite valuable. Regardless of the methods used to obtain information, it is critical to identify and address the root causes of these vulnerabilities in order to prevent them.

## Impact of Information Disclosure:

The impact of the information disclosure is determined by the nature of the information that is exposed or leaked, as well as the potential for harm that can be caused by an attacker using that information.

For example, if a security weakness in a web application exposes sensitive information such as user account passwords, then the bad actor can utilize this knowledge to cause significant harm. However, if the web application discloses information regarding the type/version of the back-end database framework, this information exposure might not cause significant risk if it is an updated version. On the contrary, if the organization is employing an old, unpatched database framework with known vulnerabilities, then this can be a cause for concern.

## Sources of Information Disclosure in a web application:

The information pertaining to a web application might be leaked from a variety of sources in a web application. The following are a few of these sources:

### Error Messages:

Error messages in a web application are one of the most typical sources of information exposure. If these error messages are not handled correctly, they may reveal valuable information. These error messages, which may include stack traces, database dumps, or different error codes, can expose information about the inner implementation of the web application. Such inside information about how the web application is implemented can give the attacker important knowledge about security flaws that can be used against it. For instance, the complete path to a resource on the web server might be displayed in an error message on the web application. As a result, an attacker may be able to access the web server's hidden folders or files such as its configuration files, database login passwords, IP addresses, and much more.

In addition to the content of the error messages that can be exploited, discrepancies in the error messages can provide an attacker with information about the internal structure of the web application and how it works. For instance, a "file not found" error message is shown if a user tries to access a file that doesn't actually exist on the web server. In contrast, if a user attempts to access a file on the web server that they are not permitted to, the "access denied" message is displayed. The attacker will be able to learn about the files that are accessible or inaccessible as well as the internal structure of the web application owing to these inconsistencies in the error messages.

### Developer Comments:

The developer comments are another source through which important information may be exposed in a web application. Programmers incorporate significant comments and metadata into the HTML code of a web application when it is being designed so that it reflects information about the internal operations of the website. These comments are sometimes not removed or are overlooked before the application is deployed into production. These comments can provide a wealth of knowledge about a website, including its default settings, any hidden files or folders on the web server, and much more.

### Directory Listing:

Sometimes the underlying web server of an application is configured in such a way that it lists the contents of directories that do not have an index page. This setting if turned on, can lead to the leakage of sensitive information depending upon the files that are listed and whether or not they can be accessed. For example, if an attacker visits the URL of the website www.sometargetwebsite.com without specifying any index page, then the website automatically redirects the user to the index page of the website. However, if the directory listing is turned on and there is no index page, then the web server can provide the user with the contents of the directory.

### Debug Messages:

The customizable error messages that some web applications offer may contain a lot of debugging information. While these are typically used in testing and development to aid in debugging, they can also frequently give an attacker access to a plethora of information about the state of the application at runtime. Debugging messages can disclose a wealth of information, such as filenames and directories on the web server, login information for the back-end database, susceptible session keys variable values, and much more. Such information leakage in the website's production environment constitutes a serious vulnerability that could be exploited by an attacker to change the state of the application and use the information to design a successful attack.

### Source code disclosure:

Source code disclosure occurs when an attacker is able to access the back-end code of the web application. The source code of the web application can reveal important details relevant to the inner working of the application as well as reveal some sensitive information such as hard-coded credentials or API keys. The severity of source code disclosure depends upon how much of the web application's source code is disclosed and the criticality of that information for the web application. There are a few sources from which the source code information can be exposed. They are as follows:

<b>Publicly available Repositories:</b>
Sometimes an organization places the source code of a web application in the public domain. If these code repositories are not well protected then they can expose the details for the server side code that can be used by the attacker to understand the application logic or discover its security weaknesses. If the attacker can identify that a particular open-source technology is being used in the web application, then this also provides easy access to a limited amount of its source code.

<b>Incorrect MIME types:</b>
In order for a web browser to properly interpret the information in the response received by the web server and provide the requested page to the user, the server that replies to an HTTP request sets the Content-Type header in the HTTP response. Now, if the web server is configured incorrectly, it can send the browser the wrong type of extension for the requested file. As an illustration, if the web server correctly sets the Content-Type header to text/html when a request to display an HTML page is received, the web browser displaying the page will process the response appropriately. Now, if the Content-Type header on the web server is configured incorrectly and is set to text/plain, the response will be treated as plain text. Because of this, the browser will expose the application's source code by rendering the response as plain text.

<b>Backup files:</b>
Sometimes the backup or old copies of the different files on the web server can end up revealing information about the web application's source code. These files are either generated automatically or manually on the web server and administrators tend to forget to remove such files from the web server. These files have a different extension than the original file e.g. having a tilde at the end file~ or having an extension like a file.php.bak, etc. If an attacker can somehow reference these files in an HTTP request to the web server, then the server can send the contents of these files to the attacker, thereby exposing parts of the web application's source code.

### Robots.txt file:

The robots.txt file is sometimes used by the underlying web server of the web application from preventing the robots from visiting specific locations or files on the server. A malicious adversary might also be able to discover sensitive files or folders on the compromised site using the information in this file. He can then either directly access them or use them as a target for additional attacks.

## Techniques for gathering important information:

Some of the techniques that may be used to discover important information related to the web application are as follows:

### Banner grabbing:

Security researchers or attackers can gather information about a local or remote host by employing a technique called banner grabbing. The information that is often exposed using this method includes obtaining application banner information (name and version), as well as the name and version of the underlying operating system, the name of the server, the open ports on the server, the services that are running on these ports, etc. This data is either gathered manually or with the aid of common OSINT(open source intelligence) tools like Telnet, Nmap, cURL, Wget, Netcat, and many others.

The information that is leaked used banner grabbing may not be directly exploitable but helps an attacker to plan his attack in an effective way. Sometimes banner grabbing may reveal information such as the outdated version of the underlying web server that can then be used by the attacker to exploit its documented vulnerabilities published on the internet.

### Fuzzing:

Fuzzing is a technique used for finding bugs in a web application by entering invalid or unexpected data and monitoring its response to discover important information. The goal of the fuzzing technique is to cause the web applications to behave in an unexpected manner such as crashes, race conditions or memory leaks, etc. in hopes of uncovering and discovering potential security weaknesses. 
Some of the tools that can be used to perform automated fuzzing are BurpSuite Intruder, OWASP ZAP Fuzzer, Peach Fuzzer, and much more.

### Extracting HTML Code Comments:

The HTML code of the web application can be analyzed to check for developer comments and to find sensitive information like hardcoded credentials or significant details about its internal organization. Some of the tools for obtaining developer comments are Burp's Engagement Tools or the "View Source" functionality of web browsers.

### Content Discovery:

The process of discovering website content that isn't directly linked to it is known as content discovery. Finding content such as system configuration files, backup files, various parameters, endpoints, and more that isn't intended for public viewing is the aim of content discovery. The information found can be used by the attacker to carry out attacks like Cross-Site Scripting (XSS), Open Redirection, Server-Side Request Forgery (SSRF), SQL Injection, and others. You can discover the web application's content either manually, automatically, or with the aid of an OSINT tool. In order to find unreferenced or hidden content on a website, contemporary content discovery technologies use wordlists. Ffuf, GoBuster, dirsearch, Burp Engagement tools, and many more are examples of these tools.

## Preventive techniques against Information Disclosure:

Some of the preventive techniques that can prevent the important information on a web application from being disclosed are as follows:

* The web server should be configured to disable directory listing. It should always display a default web page if an index page is not found.

* The web application should not have any debugging functionality enabled in the production environment.

* The error messages of the website should be generic and these messages should not provide any clues to the attackers about its internal structure.

* The sensitive information of the web application/web server must be protected from unauthorized access. Any important information that is not required for the web application to function correctly must be removed from the web server.

* The web server should be configured to not leak important information in its response headers about its internal details such as the type of its backend technology, version, and other related information.

* The services running on the open ports of the web server should not disclose any important information such as its build, version, etc.

* The web server should be configured to set the correct MIME types in the Content-Type header for different files on the web server so that they are interpreted correctly by the web browser.

* The web application should be designed to handle exceptions in a manner that doesn't expose sensitive or important information such as inner details of the web application, database credentials, API keys, etc.

* The web application code must be thoroughly tested and checked if it contains any sensitive information such as hard-coded credentials, API keys, references to hidden files or folders on the web server, and other sensitive information. The HTML comments must be thoroughly checked for the presence of such information leakage.

* The web application should show a generic error message for any resource that doesn't exist on the server or if the user is not allowed to access that resource. By using this functionality, the web application doesn't provide any clues to the attacker about the files that may or may not be present on the web server and their corresponding access restrictions.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html)**