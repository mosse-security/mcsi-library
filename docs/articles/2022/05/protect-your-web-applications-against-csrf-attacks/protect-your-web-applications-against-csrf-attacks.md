:orphan:
(protect-your-web-applications-against-csrf-attacks)=
# Protect your Web Applications Against CSRF Attacks
 

Cross-site request forgery (CSRF) is a type of attack that allows an attacker to do unauthorized actions on behalf of a user. A CSRF attack happens when a malicious site sends a request to a victim site, causing the victim site to perform an action intended by the attacker. This can be used to steal information, such as login passwords, or to take acts on the user's behalf, such as moving funds from their account.

## How does Cross-site request forgery work?

There are numerous methods for a user to be tricked into disclosing critical information; in this post, we will look at one example to better understand Cross-site request forgery.

*Bob wishes to send $500 USD to Michel. This transaction is carried out on the banking website transferbank.com, which is vulnerable to a CSRF attack. A malicious actor wishes to mislead Bob into transferring money to him rather than Michel.*

To begin, the attacker must generate a malicious URL that appears authentic to Bob and then deceive Bob into clicking the malicious link. Furthermore, if the banking website in question is using a GET request to deliver data to its server, the URL for sending $500 USD to Michel looks like this.

`http://trasnferbank.com/acctransfer/accounts?acc=Michel&amt=500`

This URL is now used by the malicious actor to create the Malicious URL, which will be used to mislead BoB into transferring money to the attacker. The acc name is replaced with the attacker’s username as shown in the command below, and the attacker can set any amount of their choice.

`http://trasnferbank.com/acctransfer/accounts?acc=attacker&amt=9000`

The Malicious URL is now complete; the next stage is to create a foolproof email that will trick Bob into clicking the malicious link; the link can be placed in anything, such as an image or an attachment. Bob may not see anything on the browser after clicking the link, but the server has already received the request for a payment transfer.

Most banking websites use POST requests to transfer data from the user to the server. In this case, the post request looks like the following.

```
POST http://trasnferbank.com/acctransfer/accounts HTTP/1.1

acc=Michel&amt=500
```

Now the attacker will generate a link that contains HTML code for a FORM tag and hide it from the user. The exploit is crafted and sent to bob, when he clicks the button, the form data is submitted to the server for a transfer request of funds to the attacker's account. The exploit looks like the one below.

```
<form action="http://trasnferbank.com/acctransfer/accounts" method="POST">

<h1> Click on the link below to see the video </h1>

<input type="hidden" name="acc" value="attacker"/>
<input type="hidden" name="amt" value="9000"/>
<input type="submit" value="Click here"/>

</form>
```

## Cross-site request forgery Prevention measures and best practices

There are several ways to prevent cross-site request forgery (CSRF) attacks.

The most popular and effective technique is to use a session-specific token. This token is usually saved in a cookie or a hidden form field. When a form is submitted, the token is validated to ensure that it is valid.

Another frequent way is to examine the referrer header to ensure that the request is coming from the same website. If the attacker has access to the victim's cookies, CSRF attacks can be extremely difficult to avoid. In this situation, the attacker can simply replicate  the cookie token and include it with the malicious request. Some websites employ a double submit cookie to prevent this.

In addition, Web applications can use a security measures known as the Same Origin Policy (SOP). This policy blocks a web page from accessing resources in another domain. This policy would prevent an attacker from submitting a request to a web application from a different domain.

**Best Practices include:**
- Keep security token in the server-side session
- Use double submit cookies
- Use the POST method for all sensitive data handling
- Set proper Content-Type
- Use same-site cookie attribute
- Check Referrer and Origin header
- Implement a double submit cookie pattern
- Use a CAPTCHA on all forms
- rate-limit all requests from a single IP address

## Conclusion

In conclusion, CSRF is a type of attack that can be used to exploit web applications that do not properly verify the source of the request. This can lead to the attacker being able to perform actions on behalf of the user, such as changing their password or making purchases in their name. CSRF attacks are relatively easy to carry out and can be very difficult to detect, so to protect against this type of attack, web sites should implement a number of security measures, such as using cryptographically secure tokens to verify user requests.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**