:orphan:
(content-security-policy-in-web-application-security)=
# Content Security Policy in Web Application Security
 
Weak security settings in a web application are exploited to perform different attacks that occur on its client-side. These types of attacks have the potential to steal important user information such as his credentials, credit/debit card information, and money from the user's account, among other things. It is possible to configure the web application's underlying web server in such a way that it becomes extremely challenging for an attacker to execute client-side attacks successfully. 

One of these security methods is to correctly configure the Content Security Policy of the web application. A solid defense strategy against various attacks can be achieved by combining a well-written Content Security Policy with a variety of other security controls. This article discusses the basics of Content Security Policy, various CSP directives, how to write your own policy while creating a web application, and how CSP helps to prevent different attacks.

## What is Content Security Policy?

Content Security Policy is a security countermeasure that adds an extra layer of protection against client-side attacks such as Cross-Site Scripting (XSS), Clickjacking, and other code injection attacks. The execution of these attacks hinges on taking advantage of the confidence a web browser has in a web application's content. As a result, a properly designed Content Security Policy can be used to defend against the execution of malicious scripts within the context of a trusted online application, as well as any attempts to circumvent the Same-Origin Policy. The Content Security Policy can be used to improve the security of a web application by identifying the data sources that are permitted in your web application.

## Why do you need a Content Security Policy?

The Same-Origin Policy, which prevents scripts on one origin from accessing data on another origin, is the foundation of web application security. A domain, port number, and URI scheme make up an origin. Modern online applications, on the other hand, incorporate content from numerous sources, including fonts, styles, social media buttons, and much more. Due to this, the majority of online apps have a Same-Origin Policy that permits the integration of material from outside sources. Now, a clever attacker can get around the Same-Origin restriction by including scripts or code from a malicious site to run when the web application is viewed via a browser, on the client's end.

By enforcing a well-designed Content Security Policy, you can control as well as prevent code execution on your web page and drastically lower the risk of XSS attacks. For further security, CSP by default imposes contemporary script coding standards.

## Content Security Policy Headers:

There have been different implementations of CSP. Different CSP headers names are given below:

* Content-Security-Policy (current): This is the standard header name recommended by W3C and used by all modern implementations of web browsers such as  GoogleChrome version 25+, Firefox version 23+, and Opera version 19+. This is the header that should be currently used by all web browsers.

* X-WebKit-CSP and X-Content-Security-Policy (deprecated): These header names are obsolete now(since Firefox version 23, Chrome version 25) and should not be used due to the presence of various security flaws.

## How to configure Content Security Policy Header:

You can configure your web server to return the Content-Security-Policy header to be attached to HTTP responses while designing your web application. If you want to configure an Apache web server to include the CSP header, you can add the following line in the httpd.conf or .htaccess file as follows:

`Header set Content-Security-Policy "default-src 'self';"`

If you want to configure the Nginx web server to include the CSP header, then modify config files within the server{} blocks as follows:

`add_header Content-Security-Policy "default-src 'self';";`

Alternatively, If you do not have access to your web server's configuration files, you can also specify different CSP directives on different pages on the web application using HTML meta tags. One such example is setting the default-src directive to none using the meta tag as follows:

`<meta http-equiv="Content-Security-Policy" content="default-src 
    'self'">`

## Content Security Policy Directives:

This section gives a brief description of different directives that can be used with the CSP header. The purpose of these directives is to specify the permitted locations from which different content can be loaded on the web page. Some of these directives are as follows:

**default-src:** The default-src content security policy directive is the fallback or default directive for other CSP fetch directives(directives that fetch resources from external specified sources). 

**script-src:** The script-src content security policy directive specifies the allowed or permitted sources for the scripts that can be loaded into the web page.

**img-src:** The img-src content security policy directive is used to whitelist the sources/location from images or favicons that can be retrieved.

**style-src:** The style-src content security policy directive is used to specify the valid sources for CSS stylesheets on a web page.

**media-src:** The media-src content security policy directive is used to specify a whitelist of sources from which the media files like audio or video files can be loaded on the web page.

**object-src:** The object-src content security policy directive is used to specify valid sources from which the plugins can be loaded on a web page.

**connect-src:** The connect-src content security policy directive specifies the permitted origins from which URLs can be loaded using script interfaces such as XMLHttpRequest, EventSource, beacon, or WebSocket connections.

**base-uri:** The base-uri content security policy directive restricts the URLs which can be used in a document's base element. If this value is absent, then any URL is allowed. If this directive is absent, the web browser will use the value in the base element.

**report-uri:** The report-uri content security policy directive instructs the web browser to report any attempts to violate the Content Security Policy. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.

**frame-ancestors:** The frame-ancestors content security policy directive specifies the locations from which another web page can be loaded into elements such as frame, iframe, object, embed, or applet element.

**form-action:** The form-action content security policy directive restricts where the form results on the web page can be submitted. 

## Special Keywords to be used with CSP directives:

Some of the special keywords that can be used with the Content Security Policy directives are given below:

**none** The none keyword when used with a CSP directive doesn't allow any content to be loaded on the web page.

**self** The self keyword when used with a CSP directive only allows resources to be loaded from the current origin.

**strict-dynamic** The strict-dynamic keyword informs the web browser to trust the scripts that originate from a root trusted script. This directive cannot be used alone and is always used with other keywords such as hashes or nonces.

**unsafe-inline** The unsafe-inline keyword when used with a CSP directive allows the usage of inline scripts or styles.

**unsafe-eval** The unsafe-eval keyword allows the use of eval in scripts. This keyword allows for dynamic code evaluation on the web page.

## How to write your own policy:

In order to create your own Content Security Policy, it is very important to identify the required security and functionality settings of your web application. After you have a clear picture of the required settings you can use a combination of different directives and keywords to form your policy that will be used with the Content-Security-Policy header as follows:

`Content-Security-Policy:<specify your policy settings here>`

Let us consider a few examples to understand the Content Security Policy creation process.

If you wanted to prevent the loading of any content on your website you can set the default-src to none as follows :

`Content-Security-Policy:default-src 'none'`

If you wanted to restrict scripts from any domain except your own domain or website and allow the images to be loaded from all sources, you can use the following CSP directives:

`Content-Security-Policy:script-src 'self';img-src *`

Here the '*' character is a wildcard character that allows you to load resources from all domains.

If you wanted to allow content to be only loaded from the same origin, a trusted website, and its subdomains, you can use the following CSP directives:

`Content-Security-Policy:default-src 'self' example-site.com *.example-site.com`

If you wanted to allow images to load from any sources whereas allowing only those media and script files that come from a trusted source, you can use the following:

`Content-Security-Policy:default-src 'self';img-src *;media-src example-site.com;script-src example-site.com`

If you wanted to allow images, scripts and media files to be only loaded from a trusted site and wanted nothing else to be loaded, then you can use the following CSP directives:

`Content-Security-Policy:default-src 'none';img-src example-site.com;media-src example-site.com;script-src example-site.com`

## How to test your policy:

After creating your policy, it is necessary to test your policy before deployment in order to ensure that it is working as required. You can use the Content-Security-Policy-Report-Only header to use the report-mode which allows the developers of the web application to monitor the violations of the CSP without enforcing the policy. You can use this header as follows:

`Content-Security-Policy-Report-Only:<your test policy>`

Alternatively, you can use the report-uri directive to send the violations of your CSP policy to a specified location of your choice as follows:

`Content-Security-Policy: default-src 'none';report-uri https://example-site.com/reports`

Note that in this case, your policy will now be enforced and any violations will be reported/sent to the address you provided. The policy will not be enforced only when using the Content-Security-Policy-Report-Only header.

## How can CSP defend against Cross Site Scripting Attacks:

Cross Site Scripting attacks occur when a web application vulnerability can be exploited to inject malicious scripts so that they get executed on the client-side of the web application. The attacker can use these attacks to steal sensitive client information such as his credentials or his bank account details to cause further harm. This section briefly reviews two methods to deal with Cross Site Scripting attacks using Content Security Policy. These methods are given below:

## Using script-src to create a whitelist of allowed sources:

The script-src CSP directive can be used to defend against Cross Site Scripting attacks. The script-src directive can be used to specify a whitelist of sources from where the scripts can be loaded into a web page as follows:

`Content-Security-Policy: script-src example-site-one.com example-site-two.com example-site-three.com`

However, a clever hacker can use sophisticated techniques to bypass whitelist restrictions which can lead to the execution of malicious scripts on a web page. 

## Using Nonce or Hashes-based Content Security Policy:

Another approach to deal with Cross Site Scripting attacks is to use a Content Security Policy that uses nonces and hashes to prevent or mitigate the risk due to the execution of malicious scripts. A Content Security Policy based on nonces and hashes is also called a Strict Content Security Policy. 

A nonce is a randomly generated value that can be used only once and it is used to verify that the script actually came from a trusted source. The script must contain the same nonce as specified by the CSP directive for successful execution on the web page.

A hash is generated by converting your code into a compressed numerical value. The CSP directive can specify a hash of the contents of the trusted script. If the hash of the actual script does not match the value specified in the CSP directive, then the script will not execute. Thus a Content security Policy based on nonces and hashes is more efficient than the one that is based on the domain whitelist approach to prevent XSS attacks.

The structure of nonce-based CSP looks something like this:

`Content-Security-Policy: script-src 'nonce-somer@nd0mvalue' 'strict-dynamic'`

Now if the script has the same nonce value in its script tag only then will it be allowed to execute on the web page.

`<script nonce="somer@nd0mvalue">`

`.....`

`</script>`

The structure of a hash-based CSP looks something like this:
`Content-Security-Policy: script-src 'sha256-hash_value_of_your_script'`

Now if the hash of the script is the same as specified by the CSP directive, only then will the script be allowed to execute on the web page. The CSP Level 2 specification allows sha256, sha384, and sha512 hashing algorithms to be used for calculating the hashes.

## How to use Content Security Policy to defend against Clickjacking attacks:

The Clickjacking attack often referred to as a UI redress attack, involves using several transparent or opaque layers to fool the user into clicking an element that is invisible or an element that is being disguised as another element on the web page. Thus when a user clicks on that element in the web page, it can result in different negative consequences including compromise of user credentials, malware execution on the user's device, compromise of financial information related to the user, and much more. Attackers that utilize the Clickjacking technique overlay the page the user sees with an invisible page or HTML element that is displayed inside an iframe. The user thinks that they're clicking on a seemingly harmless web page, but in fact, they are clicking on that invisible element in another web page that is laid on top of it.

Clickjacking attacks can be prevented through the use of the X-Frame-Options header, which restricts the web page to be loaded inside a frame or iframe tag on another web page. However, Clickjacking attacks can also be prevented using the Content Security Policy header. Using these two headers in tandem can efficiently defend against Clickjacking attacks. The frame-ancestors CSP directive can be used to restrict the loading of a web page in a frame or iframe element on another web page. In order to prevent a web page to not being framed at all you can use this directive in a CSP header as follows:

`Content-Security-Policy:frame-ancestors 'none'`

If you restrict the web page to not be framed except by web pages of the same origin you can use this directive as follows:

`Content-Security-Policy:frame-ancestors 'self'`

In order to allow framing of the web page by trusted domains as well as its subdomains and web pages of the same origin you can use this directive in a CSP header:

`Content-Security-Policy:frame-ancestors 'self' https://example-website.com https://*.example-website.com`

The usage of the Content Security Policy to prevent the framing of a website page is far more flexible than using the XFrame-Options header since it allows you to build a whitelist of sites. You can also use wildcard characters to add subdomains. In contrast to X-Frame-Options, which only checks the top-level frame, the Content Security Policy header also verifies each frame in the parent frame hierarchy. Because of this, using the CSP header is a more effective method for preventing clickjacking attempts.

## Conclusion:

A content security policy is not a replacement for secure web application development techniques. It can, however, serve as another line of defense against client-side attacks that occur in a web application. The resilience of a web application against the most frequent and severe attacks, such as XSS attacks, is ensured by the implementation of different types of security controls working in tandem in a defense-in-depth strategy.

> **Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).**