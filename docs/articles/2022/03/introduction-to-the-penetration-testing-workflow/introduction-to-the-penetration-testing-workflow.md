:orphan:
(introduction-to-the-penetration-testing-workflow)=

# Introduction to the Penetration Testing Workflow

Implementing a standard workflow can help an organization become more efficient and productive. A standard workflow should be simple and easy to understand, so that it can be followed by everyone in the organization. It enables better communication and collaboration between team members. By having standardized procedures, employees are able to easily complete their tasks and know what is expected of them. Additionally, standard workflow can help to ensure that tasks are completed in a timely and accurate manner.

The following is an example of a flexible penetration testing workflow that we follow at Mossé Security. Depending on the client and the project, there may be variations to this workflow. But in general, our process is as follows:

<img src="images/penetration-testing.svg" alt="introduction-to-the-penetration-testing-workflow" width="100%" >

Standard workflows can help to streamline the process and ensure that all aspects of the service are taken into consideration. Organizations can reduce variability in their processes by using standard workflows, which can lead to improved quality and lower costs. This aids in error prevention and ensures that the service is of the highest quality. Standard workflows also help to ensure that the process can be repeated, which in turn improves efficiency.

We have developed our own workflow after delving deeper into this domain. When compared to outside industry, you'll notice that we place a greater emphasis on trying to understand the mission, our target and end goals more than anything else.

We recommend that you consider the following essential steps in creating your own workflow:

## Phase 1: Prepare

The motivation behind this phase is to help define the goals and scope of the test. By understanding the target and how they operate, we can plan accordingly and ensure that the test is tailored to meet our specific needs.

1. **Customer Interview:** Interviewing key stakeholders prior to the commencement of an engagement is paramount. For penetration testing, you'll need to identify the key business drivers, the desired outcomes, and any constraints or limitations.
2. **Develop Statement of work:** This step involves defining clear statements about what the team is expected to accomplish and scope of the work.

3. **Develop Objective and Task Plan:** This plan should outline the goals the team will accomplish during the project based on the statement of work. It should include a list of what will be achieved by the team and how it will be produced in the given timeline.

4. **Commence and Operate:** Finally, the team should present its plan and obtain Authority to Commence and Operate (ATC/ATO). In our case, the presentation is done in the form of a Concept of Operation (CONOP) Brief.

## Phase 2: Testing

This phase is the action oriented phase. Testers uncover vulnerabilities in the target's machine using attack vectors like cross-site scripting, SQL injection and backdoors, and then try to exploit these vulnerabilities in order to understand the amount of damage they can cause.

**Industry recognized Testing Methodologies:**

Penetration testing methodologies and frameworks are important tools in the arsenal of any information security professional. Some of the common ones are as follows:

- Open Source Security Testing Methodology Manual (OSSTMM)
- Penetration Testing Execution Standard (PTES)
- Information System Security Assessment Framework (ISSAF)
- National Institute of Standards and Technology (NIST)
- Open Web Application Security Project (OWASP)
- Council for Registered Ethical Security Testers , UK (CREST UK)
- Penetration Testing Framework (PTF)
- Web Application Penetration Testing Framework (WAPTF)
- Mobile Application Penetration Testing Framework (MAPTF)
- Wireless Penetration Testing Framework (WPTF)

**Research and Planning:**

Research, planning and development are crucial steps in testing phase. This phase includes detailed study and understanding of your target, types of tests, identifying possible locations with critical vulnerabilities, how system may respond to certain planned actions and whether the deliverables meet all the expectations.

**Identify and Exploit Vulnerabilities:**

In this stage, the tester breaks into the network or computer system in order to find and exploit the security weaknesses. The objective is to identify a range of potential vulnerabilities in a target system, by examining various attack avenues and threat vectors. Both manual and automated testing methods should be adopted. Once vulnerabilities have been identified in the target environment, testers should use exploitation frameworks, standalone exploits, and other tactics to try and take advantage of these weaknesses to gain unauthorized access to the target system. Some exploit techniques could involve injecting commands into application, privilege escalation or pivoting. It is also equally important to analyze and verify the raw data to ensure that the test is is comprehensive and that it is conducted thoroughly.

**Technical Cause Analysis:**

The process of determining the technical cause of vulnerabilities is known as technical cause analysis (TCA). Examples of common TCAs include: insufficient input validation, missing access controls or usage of an outdated software package.

**Root Cause Analysis:**

Root Cause Analysis (RCA) is a method for determining the source of the vulnerabilities. The purpose of RCA is to avoid similar vulnerabilities from reoccurring in the future.

It's crucial to distinguish between RCA and TCA. Root cause analysis entails a thorough investigation of the vulnerabilities as a whole and discovering what caused them. For example: insecure IT practices, usage of legacy software, inadequate or missing information security procedures, and a lack of developer training.

**Risk Rating:**

The process of determining the severity of potential vulnerabilities discovered during a penetration test is known as risk rating. A risk rating's purpose is to help prioritize the order in which vulnerabilities are fixed. The severity of a vulnerability is typically determined by the impact it would have if exploited, such as data loss, financial damage, or service disruption.

**Report Writing:**

A report product is a document that is produced as a result of a penetration test. It describes the test environment, the target systems and networks, the exploits and tools used, and the test results. The report also includes recommendations for improving the target environment's security.

## Phase 3: Follow Up

Most of the organizations stop once the testing phase is complete. However, they fail to recognize that it is equally important to engage in the participation of stakeholders from different levels right after, to follow up and add insights on the findings of the test, analyze reports and address any risks encountered.

**Governance Uplift:**

Governance is fundamentally about assigning responsibility and holding people accountable. It is important for organizations to have a clear governance framework in order to ensure that everyone understands their role and responsibilities. Communications with the upper management post penetration testing can help identify any existing gaps in these roles.

**Process Uplift:**

Following the penetration test, we recommend that process improvements be made to further secure the environment. Examining access controls to ensure that only authorized users have access to sensitive information, strengthening password policies,auditing user activity to detect any suspicious activity, and regular reviewing of security controls to ensure they are effective in mitigating risk are all steps that should be taken. We believe that taking these steps will help to secure the environment and protect against malicious activity.

**Management Controls:**

One of the most significant parts of post-penetration testing is the implementation of management controls. The systems and data that were recently tested could be exposed to future attack if sufficient management oversight and enforcement is not in place. As a result, having a procedure in place for managing and tracking penetration testing results, as well as ensuring that the necessary corrective actions are implemented, is critical.

**Mentoring:**

Finally, the penetration testing team may be allocated to mentor developers, system administrators and project managers. This may involve giving technical demonstrations, answering questions and delivering structured training. The objective is to upskill key IT personnel on cybersecurity to prevent similar vulnerabilities from being reintroduced in the IT environment.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
