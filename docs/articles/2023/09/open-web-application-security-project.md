:orphan:
(open-web-application-security-project)=

# The Open Web Application Security Project (OWASP)

There's no doubt that web applications have become a critical aspect of operations for most organisations – business, charities and individuals interact with web services more than ever before. Not surprisingly, web apps have therefore become one of the major targets for hackers and other bad actors - with the increasing reliance on web-based services and applications, vulnerabilities in these systems can have far-reaching consequences from data loss to full scale breaches. This is where the Open Web Application Security Project (OWASP) comes into play. In this article, we'll look at what OWASP is, its significance, and how it helps in ensuring the security of web applications. 

 

## What is OWASP?

The Open Web Application Security Project (OWASP) is a non-profit organization that focuses on improving the security of software. OWASP is renowned for its extensive collection of resources and best practices for securing web applications. It was founded in 2001 and has since become a leading authority in web application security. It is also a membership organisation which you can (and probably should) join if you work in web app security! 



## Mission and Goals

OWASP's mission revolves around making software security visible so that individuals and organizations can make informed decisions about true software security risks. To achieve this mission, OWASP has set forth a set of core principles:

1. **Openness**: OWASP operates as an open community where anyone can participate, contribute, and access resources. This transparency helps in building trust and collaboration within the security community.
2. **Innovation**: OWASP strives to stay at the forefront of emerging security threats and evolving technologies. This ensures that its resources and guidance remain relevant in the ever-changing landscape of web application security.
3. **Global Impact**: OWASP's goal is to make a global impact by helping organizations worldwide improve their security posture. Its resources are available in multiple languages to reach a diverse audience.
4. **Integrity**: OWASP promotes integrity by providing unbiased and vendor-neutral information. This ensures that the focus remains on security best practices rather than promoting specific products or services.

 

## Key OWASP Initiatives

OWASP’s primary output takes the form of initiatives and projects – currently, it has several key initiatives and projects that contribute significantly to its mission, as well as many smaller projects which while lesser in scope are no less valuable. Some of the key initiatives include:

- **OWASP Top Ten**: This is perhaps OWASP's most famous project. The OWASP Top Ten is a regularly updated list of the ten most critical web application security risks. It serves as a guide for developers, testers, and security professionals to prioritize their efforts and address these common vulnerabilities.
- **OWASP Web Security Testing Guide**: This project provides a comprehensive guide for testing the security of web applications. It covers various testing techniques, tools, and best practices to ensure thorough security assessments.
- **OWASP Application Security Verification Standard (ASVS)**: ASVS is a framework of security controls for web applications and web services. It helps organizations define security requirements and assess the security posture of their applications.
- **OWASP ZAP (Zed Attack Proxy)**: ZAP is a popular open-source security testing tool used for finding vulnerabilities in web applications during development and testing phases. It provides automated scanners and a wide range of manual tools for in-depth testing.
- **OWASP SAMM (Software Assurance Maturity Model)**: SAMM is a framework that helps organizations assess and improve their software security practices. It provides a roadmap for enhancing software security maturity.



## OWASP Juice Shop

One notable project within the OWASP ecosystem is the OWASP Juice Shop. It's an intentionally insecure web application designed for the purpose of security training and awareness. Juice Shop includes a wide range of security vulnerabilities and challenges, making it an excellent tool for developers, testers, and security enthusiasts to practice identifying and mitigating common web application security issues. Users can interact with Juice Shop to discover and exploit vulnerabilities, thus gaining valuable hands-on experience in a safe and controlled environment. This project exemplifies OWASP's commitment to education and skill development in the field of web application security. Juice Shop's gamified approach to learning makes it engaging and effective for honing security skills – you may well want to take a look at Juice shop as part of your learning journey!

 

## Why is OWASP Important?

OWASP's significance lies in its role as a valuable resource for organizations and individuals concerned about web application security. As much as anything, OWASP represents a source of reliable information and a system for developing best practices. Key areas include:

**Education**: OWASP offers extensive educational material, including documentation, guides, and training resources. This empowers developers and security professionals with the knowledge needed to identify and mitigate security risks. 

*Tip: By signing up for OWASP as a member you can also access additional training materials at an affordable cost!*

**Awareness**: The OWASP Top Ten and other projects raise awareness about common web application vulnerabilities – while this in and of itself does not prevent or address vulnerabilities, this knowledge is essential for proactive security measures and by making developers aware of common issues it’s hoped that fewer issues will end up in production code!

**Best Practices**: OWASP promotes industry-standard best practices for secure software development. Following these practices can significantly reduce the likelihood of security breaches.

**Collaboration**: OWASP fosters collaboration among security experts, developers, and organizations. It creates a global network where professionals can share experiences and expertise.

**Free Resources**: Most of OWASP's resources are freely available, making it accessible to organizations of all sizes and budgets.

 

## The OWASP Top 10 (2021)

The OWASP top 10 is updated every few years – the current version is the top 10 2021. It's well worth being familiar with the top 10 issues, and checking in from time to time to see what’s changed or moved in ranking. Currently, the top 10 consists of: 

1. **A01:2021-Broken Access Control** moves up from the fifth position; 94% of applications were tested for some form of broken access control. The 34 Common Weakness Enumerations (CWEs) mapped to Broken Access Control had more occurrences in applications than any other category.
2. **A02:2021-Cryptographic Failures** shifts up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed focus here is on failures related to cryptography which often leads to sensitive data exposure or system compromise.
3. **A03:2021-Injection** slides down to the third position. 94% of the applications were tested for some form of injection, and the 33 CWEs mapped into this category have the second most occurrences in applications. Cross-site Scripting is now part of this category in this edition.
4. **A04:2021-Insecure Design** is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to “move left” as an industry, it calls for more use of threat modeling, secure design patterns and principles, and reference architectures.
5. **A05:2021-Security Misconfiguration** moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration. With more shifts into highly configurable software, it’s not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.
6. **A06:2021-Vulnerable and Outdated Components** was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
7. **A07:2021-Identification and Authentication Failures** was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
8. **A08:2021-Software and Data Integrity Failures** is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. Insecure Deserialization from 2017 is now a part of this larger category.
9. **A09:2021-Security Logging and Monitoring Failures** was previously Insufficient Logging & Monitoring and is added from the industry survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn’t well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
10. **A10:2021-Server-Side Request Forgery** is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time. 

# Final words

The Open Web Application Security Project (OWASP) plays a vital role in enhancing the security of web applications. Its commitment to openness, innovation, and global impact has made it a trusted source of knowledge and best practices in the field of web application security. Whether you're a developer, tester, or security professional, OWASP helps to provide the tools and resources needed to build and maintain secure web applications in an increasingly digital world.
