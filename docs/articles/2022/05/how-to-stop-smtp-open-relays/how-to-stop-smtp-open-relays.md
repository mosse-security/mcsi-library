:orphan:
(how-to-stop-smtp-open-relays)=
# How to Stop SMTP Open Relays
 

SMTP stands for Simple Mail Transfer Protocol. This protocol allows email messages to be sent from one computer to another. The Internet was originally designed to allow computers to communicate directly with each other, without human intervention. In order to send emails, you need to know the address of the recipient (the person or company who receives the message).

## What is SPAM?

Spam is an unsolicited email sent from someone who wants to sell something or promote their services. Spammers often send out millions of emails every day, hoping to catch a victim. If you receive too much spam, it can slow down your computer and even damage your files.

## How do attackers transmit spam?

Each spam communication consumes network bandwidth, occupies user mailboxes, and necessitates you to read or partially read the message before deleting it. This loses large amounts of user productivity within enterprises and annoys home users.

Corporate mail systems often use fast servers with vast network pipes; nevertheless, personal PCs, while far slower than corporate systems, may send millions of spam messages every day. When the number of home computers with open mail relays is doubled, either actively installed or quietly installed via malware, both are great candidates for relaying messages.

When an attacker transmits a mailing message, the content rebounds off an open mail relay and then forwards the content to the attacker's desired address.
Examining message headers and other network logs would point to the location of the mail relay program rather than the hacker.

**Spam and SMTP**

The majority of spam is sent via open SMTP relays on business networks or residential PCs without the owner's knowledge or agreement.

## Open Relay risks for businesses and home users

Aside from being the source of spam communications that might bring authorities back to your firm during a cyber investigation, delivering spam over an open mail relay has other risks:

- **Denial-of-Service (DOS) issues:** Despite the fact that corporations frequently employ huge Internet pipes, a single mail relay can soon choke this pipe, resulting in a DoS circumstance in which legitimate company services cease to function owing to a lack of network resources.

- **Impairing the company’s brand:** Spam mail may contain advertisements, pictures, or malware in some circumstances. If one of these infections affects another firm, particularly a customer, that corporation may interpret the incidence as an indicator of internal security issues, which may have an impact on future business.

- **Being blacklisted:** Blacklisting sites track machines on the Internet that have been identified as a major source of generating spam. These lists are managed by spam-fighting companies and serve as the foundation for many antispam solutions that prohibit emails from computers on these spam lists.

The preceding risks are most applicable to businesses but also apply to home users.

## Keeping Mail Servers Safe

To avoid mail relaying, you need to configure mail relays and mail servers to block mail relaying. In circumstances when legal mail relaying is required, you should set limits on your mail application to restrict which devices can forward messages out of it.

Besides, the exact process for configuring will vary based on the application. The vendor's documentation always has the most recent information.

## Conclusion

Open relaying has many risks for your business and home network. As a business owner or IT professional, now you know how to keep your simple mail transfer servers safe.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**