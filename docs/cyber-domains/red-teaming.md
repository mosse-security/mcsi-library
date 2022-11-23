# Red Teaming

```{admonition} What is Red Teaming?
:class: dropdown

Red Teaming is a security testing method that simulates a real-world attack on an organization's systems and infrastructure. It is an important cybersecurity activity for organizations to use in order to identify weaknesses in their security posture and to harden their defenses against potential attacks. Red Teaming can help organizations to identify and fix vulnerabilities before they are exploited by attackers. Additionally, Red Teaming can help organizations to develop better incident response plans and to test their ability to detect and respond to attacks.
```

## Articles

### Concepts

* [](why-do-we-red-team)
* [](a-simple-introduction-to-red-blue-and-purple-teaming)
* [](what-is-the-right-mindset-for-red-teaming)
* [](designing-threat-emulation-scenarios)
* [](the-importance-of-freedom-of-movement-when-running-red-team-exercises)
* [](how-can-cisos-make-sense-of-cyber-red-team-results)
* [](the-business-case-against-red-teaming)
* [](can-red-teaming-exercises-be-automated)
* [](what-is-the-ooda-loop-and-why-is-it-relevant-to-red-teaming)
* [](introduction-to-red-team-tools-and-techniques)
* [](choosing-a-command-and-control-infrastructure)
* [](top-reasons-why-red-teamers-should-know-how-to-write-their-own-custom-tools)
* [](using-the-cyber-kill-chain-and-the-mitre-matrix-for-red-team-operations)
* [](what-is-the-difference-between-red-teaming-penetration-testing-and-vulnerability-assessments)

### Techniques

When discussing "red team techniques", we are referring to the various ways in which a security team can simulate a real-world attack on their systems in order to test their defenses. This can include everything from social engineering attacks (e.g. phishing) to more technical attacks (e.g. privilege escalation). One of the most important aspects of red teaming is that it allows organizations to see their systems from the perspective of an attacker.

* [](ntfs-data-stream-manipulation)
* [](data-exfiltration-with-the-help-of-linux-binaries)

## Tools

There are various tools that are used by red teams in order to assess and improve the security of an organization. Some of these tools include penetration testing, social engineering, and threat modeling. Red team tools can be used to identify vulnerabilities in an organization's systems and to help create a plan to mitigate these vulnerabilities.

### Poor Man's Reverse Shells

A reverse shell is a type of shell in which the primary purpose is to enable remote access to a machine, typically for the purpose of executing commands on the machine. Unlike a standard shell, which is typically accessed by logging into the machine, a reverse shell is accessed by connecting to the machine from another machine.

* [](perform-remote-code-execution-with-the-use-of-reverse-shells)
* [](using-netcat-as-a-reverse-shell)

### Password Dumping

There are two main methods for obtaining passwords: password dumping and password cracking. Password dumping is the process of extracting passwords from a system that has already been compromised. This can be done manually, by an attacker who has physical access to the system, or remotely, by exploiting a vulnerability in the system. Once the passwords have been obtained, they can be cracked, which is the process of guessing the passwords using a computer program.

* [](password-grabbing-dump-and-crack-sam-hashes)

## Workflow

```{admonition} What is a workflow?
:class: dropdown

A workflow is a series of steps that are followed in order to complete an engagement. In penetration testing, a workflow is important in order to ensure that all steps are followed in order to complete the testing process. By following a workflow, penetration testers can ensure that they are thorough in their testing and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn Red Teaming:

```{thumbnail} ../images/procedures/red-teaming.svg
:alt: Red Teaming procedure and workflow
:class: block grey-border mb-5
```

**Articles:**

* [](designing-realistic-cyber-threat-emulations)
* [](key-metrics-to-measure-the-success-of-a-red-team-exercise)