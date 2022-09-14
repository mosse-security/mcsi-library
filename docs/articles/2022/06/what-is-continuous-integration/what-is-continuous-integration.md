:orphan:
(what-is-continuous-integration)=
# What is Continuous Integration?
 

In this blog page, we will make a quick introduction to what is continuous integration pipeline.

## Continuous Integration and code changes

In the typical waterfall method, you deploy code once or twice a week. However, with CI you check code all the time. In the CI approach development teams work with small functionalities in software development. Integration is done quickly and the developers can share their code with the rest of the team for peer review in just a few minutes. This approach is especially practical since any errors discovered during the build process can be quickly located and fixed.

## Continuous Integration and Automation

Continuous Integration (CI) necessitates the use of automation technologies that are specific to the whole project team. These technologies aid in the integration of code into a continuous form that is evaluated by automated tests, making the development team's work more efficient by enabling them to spot faults in the early phases of the development cycle.

## Security and continuous integration

Let’s look at how CI can reveal common security vulnerabilities involved in software development.

Various crews are dedicated to using continuous integration to minimize the security problems at the end of the development process, which allows us to incorporate changes directly in the program daily, and if feasible, more than once a day.
When you continuously review the code and make automated testing, you identify security flaws as soon as possible.

You can also integrate vulnerability analysis tools that evaluate code and dependencies to prevent known flaws from being integrated and accessing a live environment.

## What are repositories?

In CI, you merge all changes in your application code into a shared repository. Each developer works on different jobs, and after each phase is done, the modifications to the repository's primary line are incorporated. Each time you commit, it‘s the build tool and CI integration server’s responsibility to immediately conduct the building process, as well as perform the tests to ensure that the submitted code is fully operational.

While there are so many commits how you can control the building process? Several important actions may be taken to achieve continuous integration:

- Create a code repository to organize development.

- Begin an automated building and test process to ensure that the modifications and changes are acceptable and have not affected any element of the application.
- Execute this method numerous times every day, paying close attention to identified security issues. This allows us to have the most recent functional version of the project status on the main line, which is updated multiple times each day.

> **Want to learn practical DevSecOps skills? Enroll in [MDSO - Certified DevSecOps Engineer](https://www.mosse-institute.com/certifications/mdso-certified-devsecops-engineer.html)**