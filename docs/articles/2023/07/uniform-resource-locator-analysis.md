:orphan:
(uniform-resource-locator-analysis)=

# Uniform Resource Locator (URL) Analysis

A Uniform Resource Locator (URL) is a web address that is used to identify and locate resources on the internet. URL analysis refers to the process of dissecting and understanding the components of a URL to extract valuable information about the resource it points to.
A typical URL has the following format:

scheme://host:port/path?query_string#fragment_id

**-	scheme:** The protocol or scheme used to access the resource (e.g., http, https, ftp).

**-	host:** The domain name or IP address of the server hosting the resource.

**-	port:** The port number on the server to connect to (optional, default is 80 for HTTP and 443 for HTTPS).

**-	path:** The specific file or location on the server where the resource is located.

**-	query_string:** Optional parameters used to pass data to the server in key-value pairs.

**-	fragment_id:** An identifier used to navigate within the resource (often used for anchor links on a webpage).

URL analysis is essential for various tasks, including security analysis, web scraping, and understanding the structure of web pages.

## HTTP Methods

HTTP (Hypertext Transfer Protocol) methods, also known as HTTP verbs, are commands used to specify the desired action to be performed on a resource identified by a URL. HTTP methods define the semantics of the request and dictate how the server should handle the request.

Common HTTP methods include:

**-	GET:** Used to retrieve data from the server. It is safe and idempotent, meaning multiple identical requests will produce the same result.

**-	POST:** Used to submit data to the server to be processed. It is not idempotent, as multiple identical requests might result in different outcomes.

**-	PUT:** Used to update or replace a resource on the server. It is idempotent, as repeated requests have the same effect as a single request.

**-	DELETE:** Used to delete a resource on the server.

**-	HEAD:** Similar to GET, but it only retrieves the headers of the response, not the actual content.

**-	PATCH:** Used to apply partial modifications to a resource.

HTTP methods are crucial for building RESTful APIs and controlling the behavior of web applications during interactions with the server.

## Percent Encoding

Percent encoding, also known as URL encoding, is a mechanism used to represent special characters and non-printable ASCII characters in a URL. Some characters, such as spaces, question marks, ampersands, and slashes, have special meanings in a URL and cannot be used directly as data. Percent encoding replaces these characters with a percent sign (%) followed by their hexadecimal ASCII value.

For example, the space character (32 in decimal) is represented as %20 in percent encoding.

Percent encoding allows data to be safely transmitted in a URL without interfering with the URL's structure and intended purpose. It is commonly used when passing query parameters, form data, or any data that needs to be included in a URL.

For example, if you have a URL with a query parameter like this:
Sql:    https://example.com/search?q=some query string 

The space in the query parameter should be percent-encoded to become:

Perl: https://example.com/search?q=some%20query%20string 
This ensures that the URL remains valid, and the server correctly interprets the query parameter.