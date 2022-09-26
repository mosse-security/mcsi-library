:orphan:
(how-can-cisos-make-sense-of-cyber-red-team-results)=

# How can CISOs make sense of Cyber Red Team results?

Red teams are frequently used to assess a company's cybersecurity posture and detect potential flaws. While their work is intended to assist CISOs in making better judgments about how to safeguard their enterprises, the results might be difficult to interpret. This blog post will look at some of the difficulties that red team evaluations can present, as well as some recommendations on how to get the most out of them.

## Metric 1: Access to and effects on Key Cyber Terrain

This is the most obvious metric: could the Red Team compromise critical ICT systems?

Less obvious are the effects:

- Did they have the ability to delete data?
- Did they have the ability to read confidential information?
- How much business disruption could they have caused?
- If a real threat actor had been on the network instead of the Red Team, what other impacts could they have caused?

## Metric 2: Movement Restriction

Limiting a red team's freedom of movement can have a substantial impact on their ability to execute an attack. You can make it more difficult for them to achieve their task by restricting their access to certain sections of the network or blocking specific communication channels.

We recommend that you observe and measure how well your defences prevented the Red Team from operating within your networks.

## Metric 3: Escalation of Privileges

A threat can elevate privileges on individual systems through a variety of methods, including exploiting vulnerabilities, guessing passwords, or by installing malicious software. If a threat can access sensitive data or systems on a single machine, it may be able to use that information to gain access to other systems on the network. However, most threats are not able to gain domain-wide access, and must instead rely on compromised machines or user credentials to move laterally within the network.

One of the most critical insight to evaluate when analyzing the success of a Red Team engagement is whether they needed to increase privileges to complete their tasks. If you answered no, it's possible that security controls are so flaky or non-existent that a standard user account can wreck havoc on the network.

Here are some key questions to drive your analysis:

- Did the Red Team need domain administrator privileges?
- Did the Red Team need to compromise multiple user accounts or was a single one sufficient?
- How many machines did the Red Team need to obtain local administrator privileges on to achieve its goals?

## Metric 4: Incident Detection, Response and Recovery

This is generally the most sensitive metric: how quickly did the defenders identify the attacks and how well did they respond?

As a CISO, you're likely to witness your employees react defensively when their performance is evaluated, and you may feel upset if the Red Team uncovers significant gaps in skills and procedures. This is where things start to get real: have you improved defences to the point where the organization you guard could withstand a major cyber event?

- How long did the Red Team go undetected?
- _Could the Red Team still achieve its goals despite being detected?_
- How far must a real threat actor go to get detected by the Blue Team?
- Could the Blue Team remove the Red Team from the network?
- Could the Blue Team prevent or deter the Red Team from attacking again?
- How well did the Blue Team follow their incident response procedures?
- _If the Red Team launched a second attack campaign with the knowledge their obtained from the first one, how prepared is now the Blue Team?_

## Metric 5: Goals Achieved

Last but not least, we should assess if the Red Team met the objectives set forth and agreed upon before to the start of the exercise. We can readily evaluate whether defences are functioning or need further effort by summarizing the results into a series of yes/no replies against a set of goals.

## Final Words

In our experience, it takes 3-5 Red Team exercises for organizations to see significant gains. Cybersecurity is extremely challenging, and considerable investments are required before tangible cyber defence results are achieved.

As a CISO, this can be extremely frustrating because you will almost certainly receive negative reports and results for the next few years. Some of the expectations you've set with your direct reports and the board may be contradicted by these reports. As a result, it's critical to foresee this problem and handle this communication from the start.

One of the best ways to do this is to request Red Team exercises as a means of validating your performance, rather than having such a test sprung on you by another group inside the organization. You'll come across as a person who is serious about getting cybersecurity right if you appear proactive and open to contradiction. You should also highlight that cybersecurity is a shared duty, and that other IT executives are accountable for following your recommendations, policies, and procedures. As a result, the Red Team is testing not only the Blue Team, but also the organization as a whole.

:::{seealso}
Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html)
::: In this course, you'll learn about the different aspects of red teaming and how to put them into practice.**
