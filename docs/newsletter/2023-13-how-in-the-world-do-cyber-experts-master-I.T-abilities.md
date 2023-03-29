:orphan:
(how-in-the-world-do-cyber-experts-master-I.T-abilities)=

# MCSI #013: How in the world do cyber experts master I.T abilities?

Are you feeling overwhelmed by the breadth of technical knowledge and capabilities required to carry out cybersecurity tasks? From coding to knowing about vulnerabilities, and operating system internals, the list of requirements can seem endless.

Do we have any advice for you? Yes! Of course we do!

## Introduction

Marit asked a great question in our [Discord forums](https://discord.gg/wAu383DPWX) this week: she was working on an exercise to execute commands on a vulnerable application's server through SQL injection, but after watching videos and reading articles, she still wasn't clear on how it works. She noted that many resources seemed to "skip a thorough explanation of SQL injection and start doing things right away".

This newsletter will provide clarity on the topic for Marit and anyone else who may have similar questions.

```{thumbnail} ../images/newsletter/2023-013-marit.png
:class: block grey-border max-width-500 mb-4 mt-4 mx-auto
```

## Are you expected to master I.T. skills?

The reality of the cybersecurity industry is that it requires a certain level of knowledge and skills in I.T fundamentals before engaging with industry problems. This means that regardless of whether you attend a conference presentation or enrol in a training platform, it is expected that you already have some existing I.T skills.

Are you expected to know programming? Yes.

Are you expected to know Windows internals? Yes.

Are you expected to know how enterprise networks are built and managed? Yes.

Are you expected to know how cloud services work? Yes.

**At first, this may seem daunting; however, having a system in place to learn fundamental I.T skills can make the process easier.** Additionally, once you have a handle on the fundamentals, cybersecurity skills become much more accessible.

## What should Marit do?

We suggested to Marit that she should create a test environment in order to gain a comprehensive understanding of SQL. We recommend that she take the following steps:

1. Download and install [WAMP](https://www.wampserver.com/en/)
2. Develop a simple PHP application that uses a SQL database
3. Use the PhpMyAdmin interface to familiarize herself with all the SQL statements

The ultimate objective is to become familiar with the functions of CREATE TABLE, SELECT, INSERT, UPDATE, DELETE and UNION. PhpMyAdmin offers a convenient platform to practice SQL statements and observe the outcomes.

Once proficient in these areas, executing SQL injection becomes much more straightforward - it’s simply constructing valid SQL statements!

To begin this process, Marit can set up a Microsoft SQL server and trial command execution in the [Query Editor](https://learn.microsoft.com/en-us/sql/ssms/f1-help/database-engine-query-editor-sql-server-management-studio?view=sql-server-ver16). After that, the final step is to try the same on the target vulnerable application.

## Learn a method to solve all use cases

Gaining proficiency in cybersecurity requires utilizing the same approach, although it may look slightly different in practice depending on the use case. If you are able to learn and apply this method, you will become an expert.

- Step 1: Identify the different technologies you have to understand
- Step 2: Build a lab environment
- Step 3: Create the simplest proof-of-concept (POC) possible
- Step 4: Spend several hours understanding the inner workings of each component
- Step 5: Upgrade your POC to look like the production environment
- Step 6: Execute a simulation against your POC that simulates production
- Step 7: Carry out the work in production with all the knowledge and abilities you’ve gained from the previous steps

The method consists in achieving success through a series of small steps that will eventually lead you to your ultimate goal.

## Enter Natalie Silvanovich!

Would you like to gain insight into how this method works in a practical setting? We invite you to watch [Natashenka](https://twitter.com/natashenka)'s presentation about her experience of discovering vulnerabilities in multiple mobile messaging applications through eavesdropping.

<iframe class="block mb-4 mx-auto" width="560" height="315" src="https://www.youtube.com/embed/s44K1IBnw4I" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

In her presentation, you’ll see:

- A description of what WebRTC is
- Architecture diagrams for the main WebRTC components
- Data flow diagrams that explains WebRTC’s protocol
- Testing methods employed (e.g., recompiling apps, instrumentation with Frida)
- Reusing knowledge and experience gained from one use case to solve another use case

Furthermore, she has other [amazing presentations](https://www.youtube.com/watch?v=ySxzkBSFkxQ&ab_channel=BlackHat) where she describes her workflow. We particularly want to show you this slide:

```{thumbnail} ../images/newsletter/2023-013-natalie-silvanovich.jpg
:class: block grey-border max-width-500 mb-4 mt-4 mx-auto
```

**All cyber experts strive to create professional work through building proof of concepts, creating diagrams, and brainstorming and testing ideas. You must do this too!**

## When you’re ready, this is how we can help you

We understand that trying to learn cybersecurity by merely copying tutorials or finding answers elsewhere can leave you unprepared for success in this field. That is why we created the MCSI Online Learning Platform - a realistic way of learning that simulates the real-world. Instead of providing answers, our exercises encourage you to use critical thinking, research and trial and error to succeed. Each exercise is a chance to practice the methods described in this newsletter and the more you do it, the more you'll be able to develop the skills of an expert.

- **Free Course:** We invite you to take advantage of our free [MICS course](https://www.mosse-institute.com/certifications/mics-introduction-to-cyber-security.html), which provides 100 hours of practical training. Completing this course will help you to improve your working methods and develop the correct approach to your work.

- **Professional Certifications:** Once you have decided which direction you would like to take your career, please take a look at our [certifications](https://www.mosse-institute.com/certifications.html) and choose the one that interests you the most. If you are uncertain which one to select, [MOIS](https://www.mosse-institute.com/certifications/mois-certified-osint-expert.html) is a great starting point, as it provides the fundamentals of Open Source Intelligence. Practicing the correct method will ensure you have a strong foundation regardless of which path you decide to take in the future.

```{thumbnail} ../images/newsletter/2023-013-gabrielle-b.png
:class: block grey-border max-width-500 mb-4 mt-4 mx-auto
```

### Subscribe to our newsletter

Are you looking to learn cyber security, land a job, or improve your current skills? MCSI's newsletter is the perfect resource for you. Our newsletter is dedicated to helping students stay up to date on the latest news and trends in the cyber security industry. We provide helpful tips and tricks on how to land jobs, as well as insights into how to improve your skills. Don't miss out - subscribe to our newsletter today and start taking advantage of all the benefits it has to offer!

<iframe src="https://newsletter.mosse-institute.com/embed" style="background:white;" frameborder="0" scrolling="no"></iframe>