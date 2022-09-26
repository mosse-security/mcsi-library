:orphan:
(implement-security-in-all-phases-of-sdlc)=
# Implement Security in All Phases of SDLC
 
Secure SDLC starts with an analysis of your security posture using specified procedures. Only then can you define and implement SDLC processes in your environment. This blog article will show you how to assess your security posture and build a secure SDLC.

## Recognize your security posture

Identifying your deficiencies and general status is essential for implementing new technology, service, or adjustment into your environment.

The first step is to identify what activities and policies are in place and how successful they are in your organization. This is possible by conducting a gap analysis. When doing a gap analysis, you should specify each policy clearly. You can also set agreeable goals by implementing a blueprint such as Software Security Initiatives (SSI). Then you can track Secure Coding Standards, policies, and metrics as well as playbooks. The next step is to formalize these activities inside your SSI. You need to give time to your teams to become comfortable with it and communicate their feedback.
Invest in security training as well as proper tools for engineers. You should never underestimate the power of training people ideally before creating/launching the tool.

Now that you have evaluated your organization’s security posture you can focus on securing the processes themselves.

## Secure SDLC Processes

After you've determined your security posture, it's time to integrate security into your SDLC. We can integrate security by applying the following procedures:

**Risk Assessment**

Remember that security should come by design. During the early phases of SDLC, we gather functional requirements in the planning and analysis phases. We must ensure the security of developer credentials and who has access to our development environment. It is critical to identify security factors that facilitate security by design. You should train your teams on the importance of security so that everybody on the team agrees on its importance.

**Threat Modeling and architectural review**

Now it’s time to threat model. Threat modeling is the technique of recognizing various risks when suitable protections are inadequate. When developing the architecture of your application, you should consult with professional security teams about the architecture's security. Threat Modeling is particularly successful when used after a risk assessment and during the design stage of the SDLC. First, you must identify possible risks and explain why attackers might want to exploit your company or service. You must first inventory your assets and then determine which ones are crucial. After you've identified risks and assets, you should consider and model how an attacker can get access to them. It is critical to consider as many potential possibilities as possible. Then you can make an architectural review of your inner infrastructures such as network devices and configuration, IAM roles, and privileges to assess the lateral movement of a possible attack.

**Secure Code Scanning / Review**

Now it’s time to code! You should adopt both manual and automatic code reviews in your development environment because each has weaknesses and strengths. For example, you can apply manual code scanning for contextual vulnerabilities and logic flaws and automated tools for forgotten secrets.

**Security Testings**

Till now, we have followed all the steps and come to the Operations & Maintenance phase of the SDLC. You need to make some tests for your running application. You can employ some testing tools such as Dynamic Application Security Testing (DAST) for analyzing the runtime vulnerabilities of your app. You should also conduct various security assessments such as Penetration Testing and Vulnerability Assessments. These tests may uncover crucial pathways of an application that could lead to vulnerability exploitation.

**Maintenance and incident response**

To prevent security issues, implement infrastructure as code security tools as your app scales. You should also have a clearly defined incident response plan to help you defend your organization more effectively in a possible breach or attack.

## Conclusion

Security is an ongoing process. Integrating procedures such as security testing and other activities into an existing development process is what a secure SDLC comprises. Through some methods such as risk assessment, threat modeling, scanning and testing, and operational assurance techniques, now you’re ready to apply security in every phase of secure SDLC.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::