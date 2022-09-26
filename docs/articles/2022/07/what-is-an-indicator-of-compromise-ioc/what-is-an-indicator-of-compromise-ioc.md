:orphan:
(what-is-an-indicator-of-compromise-ioc)=
# What is an Indicator of Compromise (IOC)
 
This blog post will provide you with what is indicators of compromise (IOC), the lifecycle of an indicator, and Traffic Light Protocol (TLP).

## Indicators of compromise (IOC)

In order to reveal threats, security analysts employ indicators of compromise (IOC). IOCs are networking events that are recognized to anticipate or follow a type of attack. Any behavior, artifact, or log record that is commonly connected with an attack of some kind is considered an indication of compromise (IoC). The following are some typical examples:

- Signatures of viruses
- Malicious file extensions
- Domains of well-known botnet servers

Managing the gathering and analysis process of this information can be quite difficult. That's where we need indicator management solutions.

**Indicator management solutions**

These technologies offer insight into signs existing in networks that may not yet be visible in your organization. In this way, they act as an alert system. Here are some indicator management solution platforms:

- Structured Threat Information eXpression (STIX)
- Trusted Automated eXchange of Indicator Information (TAXII)
- OpenIOC (Open Indicators of Compromise)

### Lifecycle of an Indicator

The very first step is to verify the indicator, which is the method of validating if the indicator is real, studying the source signal, and assessing its effectiveness in spotting the dangerous behavior that you anticipate discovering in your ecosystem. Features to evaluate during validation include the dependability of the indication sources and extra information about the artifacts that may be discovered via additional investigation. Even when produced from internal network data, indicators can have usefulness outside of your business.

## Traffic Light Protocol (TLP)

Known indicators of compromise are communicated utilizing the Traffic Light Protocol (TLP) to categorize the IoCs. The UK government's NISCC developed the Traffic Light Protocol to improve the threat exchange of threat information among businesses.

TLP is a collection of identifiers intended to guarantee that confidential material is only communicated with the right people.

It has color-coded markings that are intended to assist the distribution of critical information to the right audience while also safeguarding the sources of the information.

## Conclusion

Upon completion of this blog page, we have learned that in order to complete the view of what occurred during an event, an analyst needs to convert an indication into something actionable for subsequent remediation or discovery. We have also learned that exchanging threat intelligence is an essential component of any security operations endeavor.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::