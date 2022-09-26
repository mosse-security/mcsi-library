:orphan:
(secure-your-web-application-against-cross-site-scripting-xss)=

# Secure your Web Application Against Cross-Site Scripting (XSS)

XSS attacks are a type of injection in which malicious scripts are injected into trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code to a different end user, typically in the form of a browser side script. The flaws that allow these attacks to succeed are quite common, and they occur whenever a web application uses user input within the output it generates without validating or encoding it.

An attacker can use XSS to deliver a malicious script to an unknowing user. The browser of the end user has no way of knowing that the script should not be trusted and will execute it anyway. Because the malicious script believes the script came from a trusted source, it has access to any cookies, session tokens, or other sensitive information stored by the browser and used with that site. These scripts can even rewrite the HTML page's content.

Cross-Site Scripting (XSS) attacks occur when the following conditions are met:

1. Data enters a Web application from an untrustworthy source, most commonly a web request.
2. The data is embedded in dynamic content that is delivered to a web user without being checked for malicious content.

XSS attacks can generally be categorized into three categories: stored, reflected and DOM Based XSS.

## Stored XSS Attacks

Stored attacks occur when the injected script is permanently stored on the target servers, such as in a database, a message board, a visitor log, a comment field, and so on. When the victim requests the stored information, the malicious script is retrieved from the server. Persistent or Type-I XSS is another name for stored XSS.

## Reflected XSS Attacks

Reflected attacks occur when the injected script is reflected off the web server, for example, in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the request. Reflected attacks are delivered to victims through another channel, such as an e-mail message or another website. When a user is duped into clicking on a malicious link, submitting a specially crafted form, or simply visiting a malicious site, the injected code travels to the vulnerable web site and reflects the attack back to the user's browser. Because the code came from a "trusted" server, the browser executes it. Reflected XSS is another term for it.

## DOM Based XSS Attacks

DOM Based XSS (or "type-0 XSS" in some texts) is an XSS attack in which the attack payload is executed as a result of modifying the DOM "environment" in the victim's browser used by the original client side script, causing the client side code to run in a "unexpected" manner. That is, the page itself (the HTTP response) remains unchanged, but the client side code contained within the page executes differently as a result of the malicious DOM modifications. This differs from other XSS attacks (stored or reflected), in which the attack payload is embedded in the response page (due to a server side flaw).

## XSS Attack Consequences

The outcome of an XSS attack is the same whether it is stored or reflected (or DOM Based). The distinction is in how the payload is delivered to the server XSS can cause a wide range of issues for the end user, ranging from annoyance to complete account compromise.

The most serious XSS attacks involve the disclosure of a user's session cookie, which allows an attacker to hijack the user's session and take over the account. Other harmful attacks include the disclosure of end-user files, the installation of Trojan horse programs, the redirection of the user to another page or site, and the modification of presentation.

## Final Words

Cross-site scripting is a serious issue that can result in data breaches, customer distrust, and legal action against the offending company. To protect your company, make sure your website is secure against cross-site scripting attacks. You can accomplish this by deploying a web application firewall, employing input validation, and raising employee security awareness.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
