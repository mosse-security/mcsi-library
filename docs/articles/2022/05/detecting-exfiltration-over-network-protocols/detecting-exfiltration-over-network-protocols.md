:orphan:
(detecting-exfiltration-over-network-protocols)=

# Detecting exfiltration over network protocols

Data exfiltration (exfil) is when data is transferred out of the organization without authorization. This can be done through a number of methods, including using protocols in an unintended way to inject data into the traffic stream. By understanding how protocols work and what data is supposed to exist in each field, a threat hunter can better identify threat actors who are trying to or have stolen sensitive information from an organization.

## The need for traffic analysis

Injecting data into traffic streams is not a novel method of transferring secret data. [Craig Rowland](https://journals.uic.edu/ojs/index.php/fm/article/view/528), wrote about using TCP for creating covert communication channels in 1997. The use of network protocols to exfil data from an organization can go undetected if trained people are not available to detect those types of threats or if the organization doesn't have sensors that are able to detect anomalous data in data packets for a protocol. Tools such as [DNSSteal](https://github.com/m57/dnsteal) makes it trivial for threat actors to exfil data.

## Automated tools

The use of automated tools can greatly reduce the amount of manual work that goes into detecting data exfiltration in network protocols. Automated tools can provide alerts when suspicious activity is detected and allow analysts to focus their efforts on investigating those events.

Network tools that can help with the detection of data exfiltration are [Wireshark](https://www.wireshark.org) and [tcpdump](https://www.tcpdump.org). However, both require that the analyst have a significant amount of experience with interpreting the network traffic. However, tools such as snort or [suricata](https://suricata.io) can be used to alert in real-time or used to later parse a pcap file to detect anomalies in protocols. The limitation of this method is due to the how many signatures are created to examine network traffic.

One reason to use an automated tool is because organizations can generate terabytes of data that would need to be analyzed for anomalies. Traffic samples of 100MB can be very time consuming to analyze, as well. The automated tools can be the first indicator of suspicious traffic where protocols fields do not contain expected data, such as an unused field in a protocol. The "unused" fields exist because the protocols author(s) wanted to have options available for the protocol to grow in its use. Instead of having to rewrite entire applications to adopt to the new protocol, it would only require small changes for an application to examine an existing field.

# Creating signatures

To create signatures, analysts need to have a good understanding of how the protocol works and what data is supposed to exist in each field. This can be a difficult task because most people are not familiar with all of the protocols that are used on their network. Even more difficult are the custom protocols that which may exist without documentation. Regardless, a tool such as snort or suricata are good for the initial analysis and to alert on anomalies.

In order to create signatures that can detect anomalies in protocol headers, the analyst will need to use tools to craft packets like [scapy](https://scapy.net/download/) to send the data across the network and determine if the intrusion detection system (IDS) detects it. If not, they can create a rule for the IDS to detect it. It is important to routinely test the custom signatures to ensure there are no changes to the IDS which may cause the rule to not generate an alert. Similarly, if there is a known threat group that uses a protocol to exfil data, examine threat intelligence reports for examples of the traffic flow. Those examples can then be crafted with scapy to determine if any of the organizations sensors can detect the anomaly.

## Aggregating network data

Another invaluable tool is one that can aggregate and create statistics on network flows like [silk](https://tools.netsa.cert.org/silk/). Performing traffic analysis on large datasets requires a good amount of computing power including multicore CPUs, large amount of RAM, and a system with good disk I/O performance. Network aggregation tools work well because those can display total number of packets and data sent between individual hosts over long periods of time. That is due to stealthy malware that exfiltrates slowly. Aggregating traffic flows allows analysts to quickly identify which protocols are being used and how much data is being transferred. A quick way to determine if the amount of data being transferred is normal or not is by looking at the average and maximum for each protocol. If there is a sudden increase in the amount of data being transferred for a particular protocol, that would raise red flags. For instance, if there are 20,000 DNS queries in rapid succession or over a period of 5 to 6 hours to a single IP, that is highly suspicious because that many queries is highly unusual. Another unusual behavior would be DNS request queries that contain extraneous data or unintelligible data. It would suggest exfiltration by an encoding scheme like base64.

## Scoping the hunt

The better the analyst knows their network, the more efficient hunts they can run. For example, if IPv6 is not used on a LAN then that is trivial to search on for anomalies. Even detecting anomalies in DNS or ICMP is trivial because those protocols do not generate communicate back and forth to one host for extended periods of time. Detecting it in HTTP or SMTP traffic could be more problematic for manual inspection so learning how to use automated tools can reduce the amount of work the analyst has to perform.

One way to limit the scope and workload involved with analyzing traffic for exfiltration is knowing the types of threats that are relevant an organization. A good place to start is to research the threat actors which target the type of industry where the hunt is taking place and begin looking for the activity of those threat actors. If the organization is a news agency that reports on Southeast Asia, they must be aware of the Vietnamese threat group [APT32](https://attack.mitre.org/groups/G0050/) who uses the subdomain field in DNS traffic to exfiltrate data. Knowing the behavior of APT32 provides an analyst a better idea of what to look for during their hunts and if there is currently technology that can detect anomalies DNS traffic within the organization.

## Capturing network traffic samples

Packet capture samples can also be collected over a period of time. Variables such as determining if the number of people currently in the organization is representative of normal traffic they'd generate, ensuring network scans or other automated tool are not in use, or capturing data backups across the network should be considered. Learning to filter and only retrieve the header information from data streams, and not the 'body' can help reduce the size of packet capture files. Packet capturing tools that can rotate the file are helpful to make it more manageable for the tool that is parsing the files. Instead of trying to examine a 100GB file, those can be split into 500MB files so each one is read into memory more efficiently, barring any I/O problem. Network flows may already exist within an organization and those can be used for threat hunting.

## Detection

In order to begin hunting for data exfiltration using network packets, the threat hunter must know what protocols are commonly used within the organization. From there, they can filter on protocols that do not match what is normally used. They could also look for IDS alerts that generate events on anomalies with packets.

Some ways to detect exfiltration over DNS is to look for base64 encoding within subdomain names:

_VGhpcyBpcyBub3QgYSByZWFsIG1hbGljaW91cy4K.somewhere.com_

or analyzing the TXT record of a DNS query which can generally hold 255 characters though it can store up to 4,000 characters by splitting the record. SPF records are another location to store data.

A general rule of thumb is to learn which protocols are frequently seen on a network, then look for any abnormalities. For example, ICMP echo-request and echo-reply packets are normal, but how often is it occurring? An echo-request and echo-reply are 32 bytes, respectively. Filter for bytes less than or greater than 32 bytes for those respective ICMP codes.

## Conclusion

In order to detect data exfiltration within network protocols, it is important to have a baseline understanding of how network protocols work and what data is supposed to be in each field. Network tools that can aggregate data and provide results on the number packets and bytes sent per protocol and further to specific hosts can help identify which protocols are being used and if the amount of data being transferred is normal. If there is a sudden increase in the amount of data being transferred for a particular protocol, that would raise red flags. Custom rules may need to be created to aid in the hunt because some organizations use non-standard protocols. Routinely testing the custom signatures is important to ensure they are still working as intended. Knowing which threat actors target the type of industry where the hunt is taking place can help limit the scope and workload involved with analyzing traffic for exfiltration.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::
