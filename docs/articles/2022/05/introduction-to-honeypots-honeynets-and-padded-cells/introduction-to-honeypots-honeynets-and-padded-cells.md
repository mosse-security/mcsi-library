:orphan:
(introduction-to-honeypots-honeynets-and-padded-cells)=

# Introduction to Honeypots, Honeynets, and Padded Cells

Honeypots, honeynets, and padded cell systems are all terms for a family of sophisticated security solutions that go beyond ordinary intrusion detection. To understand why these technologies aren't more frequently utilized, first understand how they vary from typical IDPs.

## Honeypots and Honeynets

Honeypots are deception systems used to divert potential attackers' attention away from important systems.

A honeynet is formed when many honeypot systems are linked together on a network segment. A honeypot system, also known as a honeynet subnetwork, has pseudo-services that mimic well-known services, but it is designed in such a way that it appears vulnerable to assaults. This combination is intended to entice attackers into disclosing themselves; the idea being that once these attackers are identified, companies can better secure their networks against future attacks that target actual assets.

## What can a Honeypot do?

Honeypots are intended to perform the following:

- Shift an attacker's concentration away from key systems.
- Obtain data about the bad actor's behavior and urge the attacker to be on the desired system for an adequate time. This way you could record and maybe respond to the incident. Since the information in a honeypot looks to be valuable, any unwanted access to it raises suspicions.
- Honeypots are supplied with sophisticated detectors and incident recorders. These features help identify attempted system access and collect data on the behavior of the potential attacker.

## What is a Padded Cell?

A padded cell is a tightened honeypot that works in unison with the traditional Intrusion Detection and Prevention System (which is abbreviated as IDPS).

- Honeypot lures the attackers with enticing material,
- The IDPS makes a discovery
- Moves them to a unique mock environment (padding cell) where they are neutralized.

Padded cells, like honeypots, are well-equipped and provide a unique opportunity for a target company to watch an attacker's operations.

Here are some advantages of these tools:

- You can direct attackers to destinations they can’t harm.
- You have time to create a response plan.
- You can record and analyze the attackers' actions.
- You can also detect inside threats prowling about a network.

Hovewer there are some points you should also take into consideration if you want to integrate these systems to your defense:

- You should clearly understand the legal consequences of utilizing such tools.
- Honeypots and padded cells have yet to be proven to be general-purpose security systems.
- Once you redirect a skilled attacker into this baiting system, he or she may launch a more aggressive attack on your systems.
- You need specialists to operate these systems. In such cases, the dangers are almost certainly well known, and suitable security safeguards, protocols, and procedures are almost certainly already in place (and properly practiced).

## Conclusion

Honeypot, honeynet, and padded cell techniques may be useful for businesses seeking to identify and pursue attackers more aggressively.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
