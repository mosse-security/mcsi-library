:orphan:
(devsecops-automated-security-for-continuous-delivery)=
# DevSecOps: Automated Security for Continuous Delivery
  

DevSecOps is the abbreviation for development, security and operations and is both the theoretical and practical implementation of automated integration of security at every step of the software development lifecycle. It is known as a mixture of software development and information technology’s operational management to provide continuous delivery of applications and services. In order to properly understand DevSecOps, one should have a good grasp of what is involved in the software development lifecycle. 

## The software development life cycle

What is included in this cycle? The software development life cycle, more commonly referred to as SDLC, is a process of producing software in the industry to design, develop and analyze software in aims of producing high quality. There are several phases of a typical SDLC including planning, defining requirements, designing, building, testing and deployment.

### Planning

The most important stage as it is used to evaluate the terms of the project with tangible goals in mind. Relevant information is gathered from consumers to develop a product within their expectations. To understand the expectations of the consumer, the purpose of the product, feasibility and profit, among other variables are examined, making it a crucial step in this model’s process.

### Defining the requirements

After the planning phase is completed, the next step is to clearly define and document the requirements of the product ad have them to be approved from either the market analysts or consumers themselves. In order for this to be completed, a Software Requirement Specification (SRS) document that obtains all product requirements to be used in the following stages of the software development is utilized. 

### Designing

This phase molds the way the software will work with the usage of the SRS document. The SRS document is used as an input and software architecture for implementing the software development in tandem of being a reference for the design architects to use for the highest quality product to be produced. 

### Building

The building phase of the model is where development is commenced and the program is written out by the developers.

### Testing

One of the most critical stages of the product, which can be either automated testing, manual testing or a combination of the two. The defects of the product are reported, rectified and then furthermore tested until given the go ahead from the requirements of the SRS document. 

### Deployment

Once the product is ready to be deployed, a formal release is done in the market and based on user experience, enhanced. Like the testing phase, this can be automated, manual or a combination of both.

## Understanding DevSecOps

DevSecOps is a representation of a necessary evolvement of the way in which security is approached by organization. Security was a last thought at the end of the SDLC, rather than being integrated at every step of the way, making DevSecOps a way to break the traditional approach. This new approach tackled security issues from their emergence, making the organization dodge expensive fixes and makes the responsibility fall on both developers and the security team. It is a combination of both DevOps and security operations to ensure the application’s secure delivery which is in tandem with improving the quality of code and the delivery speed. 

## Advantages and Disadvantages

### Advantages

- Makes it easier for software developers to deploy applications quicker and more frequently.
- Combination of Security Operations and DevOps
- Allows organizations to have a greater control over their security posture and the pipeline delivery for software such as continuous integration/continuous deployment (CI/CD)
- Saves cash resources through improved operations, automated testing and monitoring and less delays in product delivery.

### Disadvantages

- Training is necessary for both the security and development teams
- Due to the changes in the workflow process, challenges such as the initial speed at which application solutions are deployed, are inevitable
- High operational costs because of the continuous monitoring from both the security and development teams 

## Key Assumptions of DevSecOps

- Information security practices be integral in the Software Development Life Cycle and enforced at every phase of the cycle.
- Issues are found at the initial stages as it is integrated in the Software Development Life Cycle (SDLC)
- Automated testing is integral to the success of this process.

## Tools

### Static Application Security Testing (SAST)

Static Application Security Testing tools allows the development team to scan their own source code for vulnerabilities that should be fixed based on their categorization. When this is integrated into either the CI/CD pipeline or the Software Development Static Application Security Testing (SAST) Life Cycle, teams can do their risk assessment by identifying how many vulnerabilities and their remediations. 

### Dynamic Application Security Testing (DAST)

Dynamic Application Security Testing (DAST) tools provides an automated service that performs security testing on applications without reviewing or accessing the source code. It can be configured as a black box testing method which identifies risks from a threat actor’s point of view which simulates well known attack vectors. 

### OWASP Zed Attack Proxy (ZAP)

The OWASP ZAP tool helps developers to perform better software security and comes with various features such as active scanning that can be integrated into the CI/CD Pipeline. 


:::{seealso}
Want to learn practical DevSecOps skills? Enroll in [MDSO - Certified DevSecOps Engineer](https://www.mosse-institute.com/certifications/mdso-certified-devsecops-engineer.html)
:::