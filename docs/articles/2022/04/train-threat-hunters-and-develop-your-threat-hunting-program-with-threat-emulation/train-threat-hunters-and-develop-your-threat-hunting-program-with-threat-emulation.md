:orphan:
(train-threat-hunters-and-develop-your-threat-hunting-program-with-threat-emulation)=
# Train Threat Hunters and Develop your Threat Hunting Program with Threat Emulation

Organizations are under constant attack from sophisticated cyber adversaries. To defend against these threats, security teams must employ threat hunting techniques to identify and neutralize them. One such technique is threat emulation, which involves replicating an adversary's behavior to understand their methods better, detect their behavior, and develop mitigating controls to block their attacks.

Threat emulation can be an effective way to improve an organization's threat hunting capabilities. Security teams can more effectively identify and prepare by blocking their attack attempts by understanding how an adversary operates. Additionally, threat emulation can help to provide insights into an adversary's future plans and intentions, allowing security teams to stay one step ahead.

## What is threat emulation?

Threat emulation involves executing real-world threats using known threat actor TTPs or software functionality to test an organization's security posture. By emulating known threats, security teams can see how their systems and defenses would respond against an actual attack. By understanding how an attacker thinks and operates, you can more easily find them in your environment and generate better hypotheses to plan a hunt. This knowledge can also help you determine what data to collect, ensuring the data sources exist in the organization and how to analyze it. The emulation allows an organization to identify weaknesses and gaps in their security that need to be addressed.  

## The need for threat emulation

Threat emulation should be a part of every organization's threat hunting process. By constantly testing and improving their hunting capabilities, organizations can stay ahead of the curve and be better prepared when a real threat is detected. It allows you to test your detection capabilities against known threats and will enable you to generate new detections based on the behavior. It can help you find hidden threats and better understand your environment.

## Adding Threat Emulation: Step-by-Step process

To use threat emulation in your threat hunting process, start by identifying the goals of your threat hunting. *What are you trying to accomplish?  What assets will you focus on?  What methods of attack are of concern?  What types of threats would target the organization?*

Next is to begin determining the capability of the software or threat actor to emulate. That can be done by analyzing past attacks or using a resource such as the MITRE ATT&CK framework. The Att&ck framework has resources that allow mapping the behavior of a threat actor using the [Att&ck navigator](https://mitre-attack.github.io/attack-navigator/), determining the data sources where the behavior could be detected,  it provides information on [threat actors](https://attack.mitre.org/groups/), the type of industry they target, and detailed descriptions of the behavior of many known threat groups and [malicious software](https://attack.mitre.org/software/). Emulating an adversary that targets the type of organization you are in is a good start.

Once you have identified the threat group or software to emulate, a plan needs to be developed that outlines the behavior that will be emulated, how it will be emulated, and which devices in the organization will be involved.  The [Center for Threat informed Defense](https://github.com/center-for-threat-informed-defense) has templates that can be followed to create a threat emulation plan.

Then the emulation exercise needs to be executed. That can be done by creating scripts or programs that mimic the behavior of the threats, or by using an automated tool like [Scythe](
Adversary Emulation as a Service - Scythe.iohttps://www.scythe.io › adversary-emulation), [Mitre Caldera](https://caldera.mitre.org/), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Prelude](https://www.prelude.org/), or [Infection Monkey](https://www.guardicore.com/infectionmonkey/).

Once the threat emulation exercise is complete, the threat hunter can begin using relevant tools for hunting for the threat. Detecting the threats can occur in two ways:

1. The threat hunter has full knowledge of the plan.
2. The threat hunter has no knowledge of the plan.

Both have benefits though the context and objective should be clearly defined.  

A mature threat hunting program may benefit more from not having full knowledge so they can test their hypotheses generation, process, tools, and analytic skills. No knowledge could also be beneficial once a team has developed a threat hunting program and has all the tools and training to begin the hunt. However, the team that is just starting may want to have full knowledge to test each step of the threat hunting process. As they mature, they can phase into no knowledge hunts. Platforms such as Mitre Caldera gamify threat emulation, and the threat hunters could use that to document what they find. When gamifying the exercise, it would work best with the hunters not knowing the adversary emulation plan. Both approaches should result in a debrief that includes an explanation of a full emulation scenario and determine what was and wasn't discovered. The debriefing can help with:

- identifying weaknesses and strengths in analytic skills
- examining if hypotheses generation needs improvement
- identifying data sources needed to provide further coverage for a given threat
- determine the capability of the tools used for hunting
- identify knowledge gaps with the threat hunters on detecting threats on an OS or network analysis.

The more planning which goes into a threat emulation program that supports threat hunting, the better it will be for the entire organization. Accordingly, the threat emulation exercises must be relevant to the organization, support its mission, and add value to the cybersecurity program.

## Summary

Threat emulation is an exercise that can help train threat hunters and develop the threat hunting program in an organization. However, it is essential to create realistic threat scenarios to prepare for real cyberattacks.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**