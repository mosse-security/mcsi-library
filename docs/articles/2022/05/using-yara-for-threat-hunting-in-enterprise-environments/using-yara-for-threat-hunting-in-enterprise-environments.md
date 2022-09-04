:orphan:
(using-yara-for-threat-hunting-in-enterprise-environments)=
# Using YARA for Threat Hunting in Enterprise Environments
 

Yara is a powerful application that allows forensic and malware analyst to search within artifacts discovered during an investigation. Yara allows for fine-grain searches based on offsets within an executable, timestamp, specific strings, and dozens of other criteria.  Previous articles have discussed Yara and demonstrated some of its (see [Introduction to Yara Part I](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-1) and [Introduction to Yara Part II](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-2)). Threat hunters also use Yara to search for indicators of compromise (IOC) to help support their hypothesis.  They are able to search for the IOCs using threat intelligence reports, malware analyst reports, or knowledge they have about a specific type of malware.

## Scheduled scans

Yara is available on multiple platforms so it is ideal for both heterogenous and homogenous IT environments. Each group of operating systems may have their own unique rules based on the threat model for the services it offers and for any threat groups that may target an organization. Operating systems have their own scheduling applications which allows for scanning with Yara on a continuous basis.  On Windows, the Scheduled Tasks application can be used and cron can be used on Linux. Several factors are necessary for consideration of automated scans:

1. What files and directories should be scanned?
2. How often should the scan occur?
3. How will alerts be monitored?
4. The threat hunter must test the performance of the rules on the systems where it needs to run and it is particularly important since the scans are performed unattended.

One drawback to the scheduled scans is that malware may be introduced to a system and not be discovered until a significant amount of time after an incident.  Another pitfall is a threat actor may discover the Scheduled Task and disable it or delete the rulesets.

## Real-time Yara Scanning

A potentially more effective method of using Yara is to perform scans in real-time, very much like an anti-virus program. [Kraken](https://github.com/botherder/kraken) is a cross-platform Yara scanner written in Go.  Yara rules are compiled into the Kraken binary and run on multiple operating systems. Since it is written in Go, the binary can be used on multiple versions of operating systems without having to install additional software. Further, Kraken has a feature which allows it to run in the background and scan newly created processes.  That has the benefit of providing real-time alerting when a match is found for a given ruleset.

Kraken can also scan autoruns and automatically scan when a new autorun entry is created.  However, Kraken can also be used to perform one-time scans.  One of the major benefits is that "Kraken" filename can be changed so it looks like a normal running processes on a system, though compiled into it is a dataset that is continuously checking for malicious behavior.

Kraken also has a web interface where new alerts could be stored and can be reviewed by analyst on a routine basis. it also has a debug mode so log monitoring tools such as splunk forwarder, OSSEC, rsyslog, syslog-ng, or nxlog could monitor the file and send the events in the file to a centralized monitoring system which could trigger an alert.

With any real-time scanning program there are some drawbacks to consider:

1. Monitoring the Kraken process and alerting if it crashes or stops.

2. Monitoring performance since the Yara rules and the location they are scanning could impact system performance.

3. Critical system processes could potentially crash while being scanned.

These drawbacks could be mitigated with thorough testing. Additionally, some type of process monitoring or service monitoring needs to be employed to ensure the kraken program is running as expected.

## Enterprise scanning

Scanning in an enterprise can occur via installing Yara on multiple computers of interest and performing scheduled scans. A tool such as Kraken can offer a more robust enterprise scanning capability by running a service on key assets to monitor for malicious activity.
It may not be necessary to install Yara or kraken on every computer, though it should be installed on assets that contain sensitive information and ones which would be of value to a threat actor. Threat hunters should leverage threat intelligence to help inform which assets should have real-time or scheduled scans. 

A good rule of thumb is to have it on servers that are public facing since those are likely points of initial access for an infective. Performance could be tested on user workstations to scan folders such as their Downloads, Documents, and Temp folders.  File servers, domain controllers, and database servers are other assets to consider performing scheduled or real-time scans. It may not be feasible to scan network shares because it could introduce a significant performance hit on the file server due to it potentially containing hundreds of thousands of files.  Other locations to scan are C:\Users\Public and c:\program data since those are locations users may be able to write into without requiring administrative privileges.

Another method for scanning in an enterprise could be periodic scans where yara or kraken is copied over to a system, scans are performed, a report generated, and the binary removed. That could be done with existing enterprise tools that allow pushing files to systems, via psexec, scp and ssh, or Powershell remote login capabilities.

## Conclusion

Yara is a powerful program that allows creation of fine-grain searches of files, particularly malware.  Tools such as Kraken build off of the Yara framework and provides robust scanning capabilities such as real-time scanning.  In an enterprise, threat hunters can use threat intelligence to determine where Yara is best utilized to help support their hypothesis and hunts. 

It would also behoove threat hunters to periodically test the kraken program and the scheduled tasks to inject benign files, though ones containing signatures it should match to determine if an alert will be generated.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**