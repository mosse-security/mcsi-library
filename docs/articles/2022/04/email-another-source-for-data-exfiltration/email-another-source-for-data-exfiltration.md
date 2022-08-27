:orphan:
(email-another-source-for-data-exfiltration)=
# Email: Another Source for Data Exfiltration
When a data exfiltration occurs, the cyber threat hunt may begin by examining public web servers, databases, and file servers. Those are obvious first choices due to their accessibility from the internet and within the organization. Knowing the type of data exfiltrated could provide clues on where to begin the hunt. That is, hoping the organization knows where all their data is located within the organization. Insights on the type of data leaked and where the data is stored within the organization could help generate a hypothesis to begin the threat hunt. Though another service to check is email.

## Email as a vector

Using email as a vector for data exfiltration could go unnoticed due to the email volume that an organization sends and receives, particularly in large and/or distributed organizations. It also may not be a vector that is considered in the hunt to determine the source of the exfiltration. By examining email headers or the mail logs, it may be possible to identify the exfiltration source, whether by a threat actor who compromised an account or a disgruntled internal employee. Additionally, determining who in the organization has access to the data that was stolen is another artifact to help generate a hypothesis on how to start the hunt.

## Email indicators

Threat hunters often have to sift through voluminous amounts of data from different sources. One tool that is critical to a threat hunter is statistical analysis and data visualization to help make sense of the data and find potential leads.

Several key indicators can be examined when examining email as a source of data exfiltration. These include:

- Email headers
- Mail logs
- Access control lists
- User accounts

By looking at these indicators, it may be possible to determine the source by analyzing patterns in the data. Some methods to employ for the hunt in mail logs:

- Frequency in which emails are sent by the hour, day, and week. This can be done by the time of day as well.
- The average number of emails sent by a user on an hourly, daily, and weekly basis.
- The average size of attachments or size of the email sent in bytes per user and aggregated.
- Examining the total number of emails sent per person to each recipient and how many replies were received from the recipient's address.
- Examining the recipient and domain name. High-entropy domains or nonsensical email user handles should raise flags.
- Querying suspicious domains against known bad mail relays or domains reported to RBLs (Real-time block lists).
- Analyzing alerts regarding attachment size limits or files blocked from being sent.

Having mail logs over an extended period can help create a baseline to detect anomalies. However, if a user sends 30 - 50 emails a day and there is a sudden spike to dozens within a few minutes or over an hour or more, that could raise suspicion. While an employee can CC and BCC dozens of people, the email server is what sends the email to each address—knowing how the email protocol SMTP (Simple Mail Transfer Protocol) works is essential. In the previous example, malware could use client-side programs like Outlook to exfiltrate data.

The same is true for the total number of recipients. If a user typically sends emails to only a handful of people and there is a sudden increase in emails sent to one address, that could be another sign that data exfiltration occurred. Similarly, if the email has one recipient and there are few to no replies from the recipient after dozens of email messages are sent, that should raise a red flag.

Not all spikes in email activity are indicative of data exfiltration. The threat hunter should inquire about corporate events and activities because those could cause the frequency and the average number of emails sent to spike.

## Summary

Email should be considered a source of data exfiltration. It is possible to detect when data exfiltration has taken place by retrieving the proper logs and aggregating data using statistical analysis. Threat actors may exfiltrate data through an email client installed on a user's workstation and delete the messages from the 'Sent' folder. However, having access to the mail logs and to network flows could aid in the hunt.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**