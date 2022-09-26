:orphan:
(directory-traversal-what-is-it-and-how-to-prevent-it)=

# Directory Traversal: What is it and How to Prevent it

When an attacker gains access to a web server, they often attempt to move around the server to find sensitive information. One way they can do this is by using a technique called directory traversal. Directory traversal is when an attacker uses the directory structure of a website to their advantage.

By exploiting how web servers handle requests, an attacker can access files and directories that they should not have access to. To access a file, the file's path must be known. The path can be absolute, which specifies the full path from the root directory, or relative, which specifies the path from the current directory. This can lead to the disclosure of sensitive information, such as passwords, financial information, and more.

## Reading Files using Directory traversal

In this blog, we will check out different ways directory traversal can be used to access the file systems. For instance, let us consider an e-commerce application that displays images of its products using an `<img>` HTML tag.

`< img src=”/products/img?file=9re.png”>`

In the above tag, the `/products/img` directory has a parameter known as "file" which holds the name of the file. This file can then be retrieved from the `/products/img` directory via the file name. By default, a web server in any Linux system considers `/var/www` as its default directory. So in our case, the images are stored in `/var/www/products/img`, In this case, the application has read the file from the directory given below

`/var/www/products/img/9re.png`

This shows that the application has no defenses against directory traversal attack, the attacker can use the file retrieving parameter and can request any file from the server

For instance, if the attacker wants to check the contents of the `/etc/passwd` page, the malicious URL looks like the one below.

`https://hacked-website.com/products/img?file=../../../../etc/passwd`

In the above URL, the `../` command is used to go back to the previous directory, so in our case, the file system goes back through multiple directories, to the root directory, and retrieves the `/etc/passwd` file.

_You might find some security mechanisms during the exploitation, which can be bypassed using any one of the following ways._

If the server is expecting a .png file extension and any file except png is rejected, a workaround could be to use a **null byte** to bypass the filter and extract the file, as seen in the below URL:

`https://hacked-website.com/products/img?file=../../../../etc/passwd%00.png`

Another way is to Single or double encode the URL. Some web servers discard any known directory traversal paths before accepting the values, by using URL encoding, an attacker can bypass the security filter and gain access to the internal file system. The URL looks like the one below:

`https://hacked-website.com/products/img?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd%0A`

## Directory traversal prevention measures

There are many different ways to prevent directory traversal attacks, but some of the most common methods include input validation and output encoding. Input validation is a process of ensuring that all user-supplied input is valid and safe before using it. This can be done in many different ways, but some common methods include whitelisting, blacklisting, and sanitization. Output encoding is a process of ensuring that all output is properly encoded so that it can't be interpreted as code. This can be done in many different ways, but some common methods include HTML encoding, URL encoding, and JavaScript escaping.

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html)
::: In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
