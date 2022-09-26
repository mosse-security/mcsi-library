:orphan:
(the-role-of-fuzz-testing-in-improving-security)=
# The Role of Fuzz Testing in Improving Security
 
A malicious adversary may use a variety of underlying weaknesses to undermine the security of a system, application, or piece of software. The security, functionality, and availability of these systems may be significantly impacted by the exploitation of some of these vulnerabilities. Therefore, it is imperative to thoroughly test the software or application before deployment in order to find and fix any bugs or security problems. 

This security testing tends to safeguard the systems from many attack vectors before malicious adversaries have a chance to exploit these security weaknesses. Fuzz testing, often known as fuzzing, is one of the many methods used to test the security of software or applications. Fuzzing has gained a lot of popularity over the years in the field of application security testing and is very commonly employed by security testers to find different bugs in web applications. This article goes over the basics of fuzzing, its importance, types of fuzzing and fuzz testing tools, and the advantages of using fuzzing while testing the security of an application.  

## What is Fuzzing or Fuzz Testing?

Fuzzing, commonly referred to as fuzz testing, is a method for identifying any design or security issues in an application by supplying unexpected, erroneous, or invalid information as inputs to the target system. With the aid of automated testing tools, fuzzing is done by injecting random values into various inputs of the system or web application and monitoring the response. Malformed inputs are injected into the target system and it is monitored for any unusual behavior, such as crashes, memory leaks, information leakage, or other security issues. The goal of fuzzing is to detect known, unknown, and zero-day vulnerabilities.

Prof. Barton Miller from the University of Wisconsin made the initial discovery of the fuzzing technology in the 1980s. Miller saw substantial signal interference while accessing a UNIX system over a dial-up network during a storm. A collision was eventually caused by the tampering. Miller later had his students reenact his experiment by simulating his experience with a fuzz generator and hammering UNIX systems with noise to see whether they would crash. From then on forwards, fuzzing has developed into a well-acclaimed method for assessing the reliability of software and applications.

## How can fuzzing help to improve your web application's security?

Finding unknown vulnerabilities or security flaws in your target application or piece of software can be accomplished by fuzzing or fuzz testing. This testing methodology can be combined with other established testing methods, including static testing, code reviews, or various dynamic testing methodologies, to offer a deeper understanding of the security of the application or software. Finding faults in the target application that are outside the purview of manual testing by a human is the primary objective of fuzzing. While traditional testing tools such as SAST tools(Static application security testing) or DAST tools(Dynamic Application Security Testing Tools) aim to find known vulnerabilities in the system/application, fuzz testing tools can discover vulnerabilities that cannot be discovered by using SAST or DAST tools. Fuzzing testing can be particularly useful for finding flaws in software or apps that handle suspicious inputs or employ complex data processing techniques.

## Steps involved in Fuzz testing:

This section goes over the general steps that are involved in fuzz testing. Some of the major steps in fuzzing are as follows:

### Identification of the target system

This is the first step of the fuzz testing process. In this step, the target system is identified by the security testers. The target system can be some software, web application, operating system, network, etc. 

### Determination of inputs

After identifying the target system under consideration, the inputs for the target system must be identified. Some of the examples of inputs based on the target system are as follows:

* Files having different file extensions such as .pdf, .jpeg, .png and much more
  
* Data related to Network Communication Protocols such as http, ftp, ssl, and much more
  
* Operating system configuration files such as reg keys, environment variables, and much more

### Generation of fuzzed data

After the inputs of the target system are determined, the next step is to generate the test cases for these inputs. These test cases are generated with the help of fuzzing tools, also known as fuzzers, that use either generation or mutation based fuzzing to generate the test cases.

### Execution of the tests with the fuzzed data

In this step, the test cases generated from the previous step are fed into the target system to perform the testing process. 

### Monitor and analyze the system behavior

After the execution of the fuzz testing with the given test cases, the target system is monitored for expected crashes or memory leaks, or other violations. These violations are then analyzed by security testers in order to determine the source and root cause of the security flaw so that it can be remediated.

### Logging the security issues

In the final step, all the security issues that have been identified during the testing process are recorded and stored in the form of logs.

## Types of Fuzz Testing

When it comes to identifying new crashes and flaws in applications, protocols, and other systems, fuzz testing is very helpful. Depending on the target system being examined, there are various types of fuzz testing. Below is an explanation of each of these testing types:

### Application Fuzz Testing

In this type of fuzz testing, all of the application's inputs, such as URL parameters, form fields, cookies, and so on, are given different random and semi-random values. The purpose of application fuzz testing is to monitor the application for potential security and implementation flaws that can be exploited by attackers to cause further harm.

### Protocol Fuzz Testing

In protocol fuzz testing, the fuzz testing tool manipulates the transmission protocols such as http, ftp, ssh, telnet, etc. used for making requests to the target server. The goal of the protocol testing is to test and monitor the behavior of the target server by either sending forged or malformed packets or intercepting, modifying, and replaying the requests being sent to the web server. 

### File-Format Fuzz Testing

In file format fuzz testing, a malformed file is created by the fuzz testing tool and uploaded to the target program or application to be used for processing. Files are typically in commonly used formats like.jpg,.docx, or.xml most of the time. This kind of testing works by supplying a file with different extension or by creating a file with malformed contents which application is not expecting.

## Types of Fuzzers or Fuzz testing tools

A fuzzer is an automated fuzz testing tool that injects random or semi-random data into the inputs of a software, program, application, or a system in order to detect bugs. This section lists and describes the most common types of fuzzers that are used today.

### Dumb Fuzzers

A Dumb fuzzer produces random input and is unaware of the application or target system's internal structure or its input format. These fuzzers don't have any knowledge of the system's execution state or if the input was correctly accepted by the system. These fuzzers are only aware of the input that was supplied to the target system and the inputs that caused the system to crash. However, simply injecting randomized data into the system without any background knowledge is inefficient and would cause the input to be rejected. Therefore dumb fuzzers although easy to use, are not very effective at finding security flaws.

### Smart Fuzzers

A smart fuzzer is more efficient than a dumb fuzzer as it has more knowledge about the desired format of the input that is accepted by the system. Thus the randomized data produced by these fuzzers have a better probability of being accepted by the target system. As a result, these fuzzers are more efficient at finding bugs in the system or the application.  Because it takes longer to set up and requires an in-depth understanding of input format, this kind of fuzzing is more expensive as compared to a dumb fuzzer.

### Feedback based or Code Coverage Fuzzers

A Feedback based fuzzer, also known as a code coverage fuzzer, generates test cases depending on how much code has been covered by the testing. Code coverage fuzz testers are therefore more efficient while testing and covering more paths inside the application or software as compared to smart fuzzers. These fuzzers make use of this feedback information to make informed decisions about which inputs should be randomized to maximize coverage.

### Generation based Fuzzers

A generation based fuzzer utilizes the knowledge of the input format to generate test cases for the underlying target system. The test cases generated by these fuzzers have a greater chance of being validated by the target system and therefore achieve a higher coverage of the target system, especially if the expected input format is rather complex. Typically, generation fuzzers take a valid input, separate it into pieces, and then randomly fuzz each of the selected pieces. The goal is to maintain the data's overall structure while fuzzing out some portions of it. With a detailed understanding of the input format of the system under test, these fuzzers are very efficient in finding different vulnerabilities in the target system. 

### Mutation based Fuzzers

A mutation based fuzzer takes a set of valid inputs that are accepted by the target system and mutates them in order to generate the test cases. These fuzzers require less setup time as compared to generation fuzzers since inputs are created via seeds and then over time become more robust due to the mutations. Some of the techniques that are used in mutation based fuzzers are: flipping the least significant bit of integer values, modifying the headers of a valid HTTP request, or using templates of valid input formats. A template is based on the valid data structure or format used by the target system. By using these templates it is ensured that the mutated inputs or test cases are accepted by the test system thereby reducing the time and effort to perform the testing.

### Evolutionary Fuzzers

An Evolutionary fuzzer combines the capabilities of generation and mutation based fuzzers. In evolutionary fuzzers, initial test cases are generated using the generation fuzzing approach and subsequent test cases are formed using a mutation based approach. Evolutionary fuzzers use code coverage analysis to calculate how well different test cases perform. These fuzzers then use mutational fuzzing to generate more test cases similar to the high-performing ones. Evolutionary fuzzers are based on the genetic programming concept in artificial intelligence to select and mutate the test cases that are most successful in producing the errors. This process is also used to eliminate the test cases that don't result in errors and generates subsequent test cases by making changes to the remaining test cases.

## Advantages of using Fuzz testing

Some of the advantages of using fuzz testing are as follows:

* Fuzz testing improves the overall software/application security and safety because it frequently identifies unusual errors and vulnerabilities that human testers would miss and for which even diligent human test designers would fail to write tests.

* Fuzz testing is a low cost security testing method that requires significantly lower resources and effort as compared to conventional testing techniques in order to discover security weaknesses. With the increase in the sophistication of fuzzing technologies, many modern day fuzzers possess auto-learn capabilities that allow the security testers to carry out automated fuzz testing seamlessly and quickly.

* Fuzz testing is particularly useful for finding zero-day exploits in the target software or web application. With the growing rate of zero-day exploits targeting different enterprises and the increase in the damage caused by them, it is imperative for the enterprises to detect the security flaws before the hackers can exploit them to cause further damage. Fuzzing, therefore, prevents malicious adversaries to take advantage of such security flaws and improves the robustness of the target system.

* Fuzzing is also very useful in finding errors that are not handled well by software or the application such as buffer overflows or memory leaks. These vulnerabilities can be particularly useful for the attackers who can exploit them to perform harmful activities. 

* Fuzz testing or black box fuzz testing is one of the main approaches that is used in detecting vulnerabilities in systems or applications where the tester doesn't have access to the internal details of the system such as its source code. This enables the testers to find hidden security vulnerabilities which may be hard to detect through conventional testing methods.

* Integrating fuzz testing in your application or software development lifecycle will allow the developers to secure the application from different attack vectors by applying appropriate security controls. This will result in applications that are more resilient to different cyber-attacks by ensuring the development of the code that is more secure.

## Commonly Used Fuzz testing tools

Some of the most commonly used and popular fuzz testing tools are as follows:

**Peach Fuzzer:** Peach Fuzzer is a robust application security testing tool that allows for both generation and mutation-based fuzz testing. It allows the security testers to configure different test settings such as specifying input format, logging interfaces, relationships in the data to be fuzzed, and much more. 

**OWASP WSFuzzer:** WSFuzzer is a fuzzing penetration testing tool used against HTTP SOAP(simple object access protocol) based web services. It tests numerous aspects such as input validation, XML Parser, etc. of the SOAP target.

**American fuzzy lop:** American fuzzy lop, or AFL for short, is a free smart fuzzer that uses genetic algorithms in order to efficiently increase code coverage of the test cases.

**BFuzz:** BFuzz is an automated input-based fuzzer for web browsers. This tool takes .html as an input, opens up your browser with a new instance, and passes multiple test cases to discover bugs.

**APIFuzzer:** APIFuzzer is a python-based fuzz testing tool that reads your API description and step-by-step fuzzes the fields to validate if your application can cope with the fuzzed parameters.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::