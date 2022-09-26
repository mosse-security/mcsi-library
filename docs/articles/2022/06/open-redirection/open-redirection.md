:orphan:
(open-redirection)=
# Open Redirection
 

Occasionally, programs must redirect visitors to a different page. The intended functionality of that would be to redirect the user to a desired website, but it's quite easy for attackers to mess this up when their user input might impact the redirections' outcome. In other terms, an open redirect occurs when a website allows for a redirection to an unexpected page.

The user should never be able to affect the outcome of a redirection since this lends credibility to a phishing effort to deceive a victim.

## Description

When a person has leverage over a redirect or forward to some other URL, this is known as an open redirect vulnerability. An adversary might offer a URL that leads an unwary target out of a legal sector to an attacker's fake website if the application does not authenticate unverified data from the user.

Open redirection are used by cybercriminals to give their spoofing assaults more legitimacy. The majority of consumers see the real, trustworthy domain but are unaware of the fraudulent site redirection.

Even though this flaw may not necessarily have a direct effect on the genuine application, it can harm the company image. Furthermore, while open redirects may still not appear to get a significant effect on the company, it is critical to prevent jeopardizing consumers' faith in the company. It's worth remembering that an open redirect on your website might be exploited via your staff!

## Example

Mark, a music addict and aspiring DJ, has gotten up and is reading her mails. Her preferred streaming site is on sale, and she receives a good discount in her mailbox. MusicLovers is usually \$90 per quarter, but for a short period, it is only $30 per quarter.

Mark navigates to the MusicLovers user account page by clicking the website address. After logging in, she is prompted to submit her payment card information in order to complete the new membership. She fills out all of the required information, only to be dismayed when she sees the message "Unfortunately, you are not suitable for this discount" and is routed to the site.

Mark examines her credit card bill later that week and discovers a slew of unauthorized charges!

When we go to the MusicLovers portal, we could see there was an element named "url_redirect" in the Web address. We appear to be taken to the personal profile after submitting a login request.

> www.musiclovers.com/login?url_redirect=/my_profile

By checking in by our own login details, we can verify the reroute. Use a profile name like "test" and a passcode "test" to login in. We'll be taken to our personal profile .

Replace the '/my_profile' phrase with a different URL and attempt logging in once more.

> www.musiclovers.com/login?url_redirect=https://www.youtube.com/watch?v=0vxCFIGCqnI

If we were redirected to the URL that we give, this indicates that this redirect is in risk.

## Open Redirect beneath the surface

The real application routed him to our scam site once he logged in after we changed the url redirect option and emailed it to Mark. Because the URL is not validated, anybody can offer any URL they choose.

Mark was completely unaware of the reroute to our fraudulent site, which looks identical to the authentic MusicLovers webpage. Even if he had double-checked the URL, he would have been unconcerned because they are so similar. So, without hesitation, Mark typed his login details into our system, allowing us to collect them. He was redirected to his home page after we presented him with an apparently legitimate reason why we couldn't grant a discount. I'm sure he was disappointed that he didn't obtain reduction, but I doubt he realized he'd just made a loss.

Since we are establishing a connection to a verified genuine site, employing open redirects for scamming is quite successful. Even if the target is technically smart and has double-checked the URL's address and possibly even the SSL certificate, the shift would still take them to an undesirable destination.

## Linking Open Redirect vulnerability with other ones

Open redirect flaws may be linked with some other vulnerabilities to maximize their effect, in addition to spoofing and social engineering consequences. An adversary may, for example, use an open redirect to:

- To accomplish complete server-side request forgeries, circumvent a domain-based backend request filter.

- Redirect to a website having JavaScript schema may cause an XSS.

- Using the referrer headers, we may be able to grab private tokens.

## How to mitigate Open Redirect

There are a few options for fixing the script so that the open redirect is no longer an option. We can either discover a mechanism to check the parameter's entry so that only acceptable addresses are allowed, or we may eliminate the parameter entirely.

### Create a "permit list"

If deleting the argument doesn't fit for your application's flow, we could change the software to allow only redirects to pages from a "permit list." When logging in, all url redirect arguments that aren't similar to the profile or contact info page will just redirect the visitor to the main page.

### Create a permanent domain.

If the app has a lot of possible valid pages to redirect to, we can set up a fixed domain and just attach the redirected page to it.

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html)
:::