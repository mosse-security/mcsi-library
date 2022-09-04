:orphan:
(the-advantages-and-disadvantages-of-proxy-servers)=
# The Advantages and Disadvantages of Proxy Servers
 

People frequently pause to consider how the internet works. Along with the benefits of using the internet, there are drawbacks and risks. But what happens when you browse the internet? You could be using a proxy server at work, on a Virtual Private Network (VPN), or you could be one of the more tech-savvy people who always uses some kind of proxy server.

## What's a Proxy Server?

A proxy server serves as a link between your computer and the internet. It's an intermediary server that sits between end users and the websites they visit. Depending on your use case, needs, or company policy, proxy servers provide varying levels of functionality, security, and privacy.
When you use a proxy server, internet traffic passes through it on its way to the address you requested. The request is then routed through the same proxy server (with some exceptions), and the proxy server forwards the data received from the website to you. Why bother with a proxy server if that's all it does? Why not just go from the website to the website and back? 

Modern proxy servers do far more than simply forward web requests in the name of data security and network performance. Proxy servers serve as a firewall and web filter, as well as providing shared network connections and caching data to speed up common requests. A good proxy server protects users and the internal network from malicious content on the internet. Finally, proxy servers can provide an extremely high level of privacy.

## How Does a Proxy Server Operate?

Every computer connected to the internet requires a unique Internet Protocol (IP) address. Consider this IP address to be your computer's street address. The internet knows how to send the correct data to the correct computer by using the IP address, just as the post office knows how to deliver your mail to your street address.

A proxy server is essentially an internet computer with its own IP address that your computer recognizes. When you send a web request, it first goes to the proxy server. The proxy server then makes your web request on your behalf, receives the response from the web server, and forwards the web page data to you so you can view it in your browser.

When the proxy server forwards your web requests, it can modify the data you send while still delivering the information you expect to see. A proxy server can change your IP address, which means the web server has no idea where you are in the world. It can encrypt your data so that it is unreadable while in transit. Finally, a proxy server can restrict access to specific web pages based on IP address.

## Types of Proxy Servers

Not all proxy servers function in the same way. It is critical to understand the functionality provided by the proxy server and to ensure that the proxy server meets your needs.

### Transparent Proxy

A transparent proxy informs websites that it is a proxy server, but it continues to pass your IP address along, identifying you to the webserver. Businesses, public libraries, and schools frequently use transparent proxies for content filtering because they are simple to configure on both the client and server sides.

### Anonymous Proxy

An anonymous proxy will identify itself as a proxy, but it will not send your IP address to the website, preventing identity theft and keeping your browsing habits private. They can also prevent a website from serving you location-based marketing content. Anonymous browsing will prevent a website from using some ad targeting techniques, but it is not a guarantee.

### Distorting proxy

A distorted proxy server sends you a false IP address while identifying itself as a proxy. This function is similar to the anonymous proxy, but by passing a false IP address, you can appear to be from a different location to circumvent content restrictions.

### High Anonymity proxy

High Anonymity proxy servers change the IP address they present to the web server on a regular basis, making it difficult to determine which traffic belongs to whom. Proxies with high anonymity, such as the TOR Network, are the most private and secure way to browse the internet.

## 5 reasons why Should You Use a Proxy Server

-	To control internet usage of employees and children: Organizations and parents set up proxy servers to control and monitor their employees' or children's internet usage. Most organizations don't want you looking at specific websites on company time, and they can configure the proxy server to deny access to specific sites rather than redirecting you with a nice note asking you not to look at said sites on the company network. They can also monitor and log all web requests, so even if they don't block the site, they know how much time you spend surfing the internet.

-	**Bandwidth savings and improved speeds:** A good proxy server can also help organizations improve overall network performance. Proxy servers can cache (save a copy of a popular website locally) – so if you request `https://blog.mosse-institute.com/`, the proxy server will check to see if it has the most recent copy of the site, and then send you the saved copy. This means that when hundreds of people use the same proxy server to access `https://blog.mosse-institute.com/` at the same time, the proxy server only sends one request to `https://blog.mosse-institute.com/`. This saves the company bandwidth and improves network performance.

-	**Privacy benefits:** Proxy servers are used by both individuals and organizations to browse the internet more privately. Some proxy servers will alter the IP address and other identifying information contained in the web request. This means that the destination server has no idea who made the original request, which helps to keep your personal information and browsing habits private.

-	**Improved security:** Proxy servers offer security benefits in addition to privacy benefits. To prevent prying eyes from reading your transactions, configure your proxy server to encrypt web requests. You can also block known malware sites from being accessed via the proxy server. Organizations can also combine their proxy server with a Virtual Private Network (VPN) so that remote users always access the internet through the company proxy. A VPN is a secure connection to a company's network that is made available to external or remote users. The company can control and verify that their users have access to the resources (email, internal data) they require by using a VPN, while also providing a secure connection for the user to protect the company data.

-	**Get access to blocked resources:** Proxy servers enable users to bypass content restrictions imposed by businesses or governments. Is the online game of the local sportsball team blacked out? Watch from a proxy server on the other side of the country. The proxy server makes you appear to be in Australia, but you are actually in Albania. Several governments around the world closely monitor and restrict internet access, and proxy servers provide their citizens with uncensored internet access.

Now that you understand why organizations and individuals use proxy servers, consider the risks listed below.

## Proxy Server Risks

When selecting a proxy server, you must exercise caution because a few common risks can negate any potential benefits:

### Free proxy server risks 

Have you ever heard the expression "you get what you pay for?" Using one of the many free proxy server services, even those with ad-based revenue models, can be quite risky.

When something is free, it usually means that they aren't investing heavily in backend hardware or encryption. There will almost certainly be performance issues as well as potential data security issues. If you come across a completely "free" proxy server, proceed with caution. Some of them are simply looking to steal your credit card information.

### Browsing history log

The proxy server has your original IP address and possibly unencrypted web request information saved locally. Check to see if your proxy server logs and saves that data, as well as what kind of retention or law enforcement cooperation policies they adhere to.

If you expect to use a proxy server for privacy but the vendor is simply logging and selling your data, you may not be getting the value you expect.

### No encryption

If you don't use an encrypted proxy server, you might as well not use one at all. If you do not encrypt your requests, they will be sent in plain text. Anyone who is listening will be able to easily obtain usernames, passwords, and account information. Make certain that the proxy server you use supports full encryption.

## Final words

A proxy server provides numerous advantages to an organization, including the ability to control internet traffic, improve security, and cache content. However, there are some disadvantages to using a proxy server, such as the possibility of decreased speed and reliability. To summarize, a proxy server can be a valuable tool for an organization, but it is critical to weigh the benefits and drawbacks before implementing one.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**