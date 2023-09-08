:orphan:
(network-troubleshooting-command-line-tools)=

# Network Troubleshooting - Command Line Tools

Network troubleshooting is a critical skill for anyone dealing with computer systems and the internet - these skills are also of great value to security professionals looking to understand a network!

When network issues arise, being able to diagnose and resolve them efficiently can save both time and frustration. Command line tools are essential for network troubleshooting, as they provide detailed information and control over network configurations. In this article, we will explore a selection of command line tools for network troubleshooting on both Windows and Linux platforms, explaining their use and providing examples of how they can help an administrator understand and remediate issues.



## Windows Tools

### **Ping**

Ping is a fundamental utility for testing network connectivity. It sends ICMP Echo Request packets to a target IP address or hostname and measures the time it takes to receive a response. Ping is available on almost any system you can imagine.  You should use the`ping` command when you need to verify whether a host on the network is reachable. It's particularly useful for diagnosing basic connectivity issues and measuring response times.

**Example (Successful Ping)**:

```shell
ping google.com
```

**Expected Output (Successful)**:

```shell
Pinging google.com [172.217.4.174] with 32 bytes of data:
Reply from 172.217.4.174: bytes=32 time=15ms TTL=117
```

**Example (Failed Ping)**:

```shell
ping non-existent-domain.com
```

**Expected Output (Failed)**:

```shell
Ping request could not find host non-existent-domain.com. Please check the name and try again.
```



### Tracert (Windows) or traceroute (Linux)

Tracert/traceroute helps trace the path that packets take from your computer to a destination, showing each hop along the way. It's useful for identifying network bottlenecks or failures. While the function is essentially the same, the command on Windows is `tracert` whereas on Unix  it's `traceroute`. Use `tracert` or `traceroute` when you need to visualize the network path to a target and identify where packet loss or delays occur. This tool is valuable for troubleshooting routing issues. For a network engineer, these tools can help you quickly identify where an issue is, or at least show that the problem lies in a network you do not control. 

**Example (Successful Tracert)**:

```shell
tracert google.com
```

**Expected Output (Successful)**:

```shell
Tracing route to google.com [172.217.4.174] over a maximum of 30 hops:

 1   1 ms   1 ms   1 ms your_router_ip
 2  10 ms  12 ms  11 ms isp_router_ip
 3  12 ms  10 ms  11 ms destination_router_ip
 4  14 ms  15 ms  16 ms google.com [172.217.4.174]
```

**Example (Failed Tracert)**:

```shell
tracert non-existent-domain.com
```

**Expected Output (Failed)**:

```shell
Unable to resolve target system name non-existent-domain.com.
```



### Netstat

Netstat provides detailed information about network connections, routing tables, interface statistics, masquerade connections, and more. It's helpful for identifying open ports, connections, and network statistics. You should use `netstat` when you want to examine active network connections, identify listening ports, or diagnose network-related issues like port conflicts or unauthorized connections.

**Example (Successful Netstat)**

```shell
netstat -ano
```

**Expected Output (Partial)**

```shell
Proto Local Address     Foreign Address    State      PID
TCP  0.0.0.0:80       0.0.0.0:0       LISTENING    1234
TCP  192.168.1.2:55056   8.8.8.8:53       ESTABLISHED   5678
```

**Example (Failed Netstat)**

Suppose you are trying to identify a port that should be listening but is not. In this case, the output would simply not display the expected listening port entry. 



### Nslookup

`nslookup` (Name Server Lookup) is a command-line tool used for querying Domain Name System (DNS) servers to retrieve information about domain names and IP addresses. It's used to diagnose DNS-related issues, resolve domain names, and check DNS server configurations.You should use `nslookup` when troubleshooting DNS-related problems, verifying DNS configurations, or performing DNS lookups to map domain names to IP addresses.

**Example (Successful nslookup)**:

```
shell
nslookup google.com
```

**Expected Output (Successful)**:

```
yaml
Server:  dns-server.example.com
Address:  192.168.1.1

Non-authoritative answer:
Name:    google.com
Addresses:  172.217.4.174
          2607:f8b0:4004:80b::200e
```

**Example (Failed nslookup)**:

```
shell
nslookup non-existent-domain.com
```

**Expected Output (Failed)**:

```
vbnet
Server:  dns-server.example.com
Address:  192.168.1.1

*** dns-server.example.com can't find non-existent-domain.com: Non-existent domain
```



### ipconfig

IP Configuration - `ipconfig` is a Windows command-line tool used to display and manage IP configuration settings for network interfaces on a Windows computer. It provides information about IP addresses, subnet masks, gateways, and more. Use `ipconfig` to view and manage network settings on a Windows machine, check the current IP configuration, renew DHCP leases, or flush DNS resolver cache.

**Example (Successful ipconfig)**:

```
shell
ipconfig /all
```

**Expected Output (Successful)**:

```
yaml
Windows IP Configuration

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . : example.com
   IPv4 Address. . . . . . . . . . . : 192.168.1.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
```

**Example (Failed ipconfig)**:

```
shell
ipconfig /renew
```

**Expected Output (Failed)**:

```
kotlin
An error occurred while renewing interface Ethernet : The system cannot find the file specified.
```



### pathping

**Purpose**: `pathping` is a Windows utility that combines the functionality of `ping` and `tracert`. It provides a more detailed analysis of network latency and packet loss by sending multiple packets to each hop along the route.

**When to Use**: You should use `pathping` when you want a comprehensive analysis of network latency and packet loss along the entire route to a destination. It helps identify network bottlenecks.

**Example (Successful pathping)**:

```
shell
pathping google.com
```

**Expected Output (Partial - Successful)**:

```
less
Tracing route to google.com [172.217.4.174]
over a maximum of 30 hops:

  0  your_computer [192.168.1.2]
  1  your_router [192.168.1.1]
  2  isp_router [203.0.113.1]
  3  ...
  ...
```

**Example (Failed pathping)**:

```
shell
pathping non-existent-domain.com
```

**Expected Output (Failed)**:

```
css
Unable to resolve target system name non-existent-domain.com.
```



### arp

The `arp` (Address Resolution Protocol) command is used to display and manage the ARP cache, which maps IP addresses to MAC (hardware) addresses on a local network. It's useful for diagnosing and troubleshooting ARP-related issues. Use `arp` when you need to examine the ARP cache, clear ARP entries, or troubleshoot connectivity problems related to ARP resolution.

**Example (Successful arp)**:

```
shell
arp -a
```

**Expected Output (Partial - Successful)**:

```
sql
Interface: 192.168.1.2 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.100         00-66-77-88-99-aa     dynamic
```

**Example (Failed arp)**:

```
shell
arp -d non-existent-ip
```

**Expected Output (Failed)**:

```
yaml
No ARP entries found.
```



## Linux Tools

### Ping

The same as it's Windows counterpart, `ping` is used to test network connectivity and measure round-trip time - on Linux however, the ping command will keep pinging until terminated - pass the  `-c` flag (count) to specify the number of pings.  You should use `ping` when you need to verify the reachability of a host on the network, assess network responsiveness, or diagnose basic connectivity problems.

**Example (Successful Ping)**:

```shell
ping google.com
```

**Expected Output (Successful)**:

```shell
PING google.com (172.217.4.174) 56(84) bytes of data.
64 bytes from 172.217.4.174: icmp_seq=1 ttl=117 time=15.6 ms
```

**Example (Failed Ping)**:

```shell
ping non-existent-domain.com
```

**Expected Output (Failed)**:

```shell
ping: non-existent-domain.com: Name or service not known
```



### Traceroute 

Traceroute in Linux is equivalent to `tracert` in Windows. It traces the path to a destination, showing each hop and the time taken - most Linux distributions also come with an improved tool called MTR which offers additional functionality. Use `traceroute` when you want to identify the network path to a destination and pinpoint where network issues or delays are occurring. It's valuable for diagnosing routing problems - MTR takes this a step further by providing monitoring over time. 

**Example (Successful Traceroute)**:

```shell
traceroute google.com
```

**Expected Output (Partial - Successful)**:

```shell
1  your_router_ip 1.235 ms 1.173 ms 1.085 ms
2  isp_router_ip  8.981 ms 8.874 ms 8.765 ms
3  destination_router_ip 9.754 ms 9.645 ms 9.536 ms
4  google.com (172.217.4.174) 10.112 ms 10.003 ms 9.895 ms
```

**Example (Failed Traceroute)**:

```shell
traceroute non-existent-domain.com
```

**Expected Output (Failed)**:

```shell
traceroute to non-existent-domain.com (unknown), 30 hops max
1  * * *
2  * * *
3  * * *
```



### MTR

MTR is powerful network diagnostic tool that combines the functionality of `ping` and `traceroute`. It continuously sends packets to a destination and provides real-time statistics about the route, including latency and packet loss at each hop. MTR is particularly useful when you need to perform continuous network monitoring or when you want to identify the exact point along a network path where issues like high latency or packet loss are occurring. It provides ongoing insights into network performance, making it a valuable tool for diagnosing intermittent problems.

**Example (MTR)**:

```shell
mtr google.com
```

**Expected Output**:

```shell
                             My traceroute  [v0.92]
host.example.com (192.168.1.2)                     Thu Sep  7 12:00:00 2023
Keys:  Help   Display mode   Restart statistics   Order of fields   quit
                                       Packets               Pings
 Host                                Loss%   Snt   Last   Avg  Best  Wrst StDev
 1. your_router_ip                     0.0%    10    1.0   1.2   1.0   1.4   0.1
 2. isp_router_ip                      0.0%    10    9.0   8.8   8.0   9.5   0.5
 3. destination_router_ip              0.0%    10    9.9   9.6   9.0  10.3   0.4
 4. google.com (172.217.4.174)        0.0%    10   10.1  10.0   9.5  10.5   0.3
```



The MTR tool continuously sends packets to the destination (in this case, google.com) and displays statistics for each hop along the route. It provides real-time information on packet loss, latency (in milliseconds), and more. This ongoing monitoring helps pinpoint network issues as they occur.

Tip:  *You can stop MTR by pressing `Ctrl+C`.



### Netstat / SS

The `netstat` command on Linux provides similar functionality as on Windows, displaying network connections and statistics.Use `netstat` when you want to view active network connections, check open ports, and examine network statistics. It's a valuable tool for diagnosing issues like port conflicts or unauthorized connections.

**Example (Successful Netstat)**:

```shell
netstat -tuln
```

**Expected Output (Partial)**:

```shell
Proto Recv-Q Send-Q Local Address      Foreign Address     State
tcp6    0   0 :::80          :::*          LISTEN
tcp6    0   0 :::22          :::*          LISTEN
```

**Example (Failed Netstat)**:

As on Windows, if a particular port you expect to see is not listed, it would indicate that the service associated with that port is not running or listening. The output would lack the expected entry for that port.



#### The Shift from `netstat` to `ss` on Linux

Traditionally, Linux administrators and users relied on the `netstat` command for displaying network information and statistics. However, in recent Linux distributions, there has been a shift towards using the `ss` (Socket Statistics) command as a replacement for many `netstat` functionalities. Indeed, some linux distributions no longer ship with netstat installed (although you can install it if you want!) The good news is that the command syntax for `ss` is almost identical to `netstat` - it also offers several advantages, including better performance and improved functionality for advanced network analysis. The move to `ss` is in response to evolving networking standards and a desire for more efficient network management tools - so expect to see it feature more heavily in the future!



###  ifconfig

**Purpose**: `ifconfig` (Interface Configuration) is a Linux command used to configure and display network interface settings, including IP addresses, netmasks, and hardware addresses (MAC).  It's very similar to `ipconfig` on Windows - However, it is being gradually replaced by `ip` command. Use `ifconfig` to view and configure network interfaces on a Linux system, check the current IP configuration, or activate/deactivate network interfaces.

**Example (Successful ifconfig)**:

```shell
ifconfig
```

**Expected Output (Partial - Successful)**:

```shell
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.2  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe75:168d  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:75:16:8d  txqueuelen 1000  (Ethernet)
        RX packets 3338  bytes 3265933 (3.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1432  bytes 136156 (136.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

**Example (Failed ifconfig)**:

```shell
ifconfig eth1 up
```

**Expected Output (Failed)**:

```shell
SIOCSIFFLAGS: No such device
```



### iptables

`iptables` is a powerful Linux firewall tool used to configure and manage packet filtering, network address translation (NAT), and stateful inspection rules. It helps control network traffic and enhance security. Use `iptables` when you need to configure firewall rules, restrict or allow network traffic, implement port forwarding, or perform network address translation (NAT) tasks.

**Example (Successful iptables)**:

```shell
iptables -L
```

**Expected Output (Partial - Successful)**:

```shell
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

**Example (Failed iptables)**:

```shell
iptables -A INPUT -j DROP
```

**Expected Output (Failed)**:

```shell
iptables: No chain/target/match by that name.
```



### tcpdump

`tcpdump` is a command-line packet analyzer that allows you to capture and display network packets on a Linux system. It's a versatile tool for monitoring and analyzing network traffic in real-time. Use `tcpdump` when you want to capture and inspect network packets for diagnostic purposes, troubleshoot network issues, or analyze network traffic patterns.

**Example (Successful tcpdump)**:

```shell
tcpdump -i eth0 -n
```

**Expected Output (Partial - Successful)**:

```shell
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
12:00:00.123456 IP 192.168.1.2 > 8.8.8.8: ICMP echo request, id 12345, seq 1, length 64
12:00:00.123567 IP 8.8.8.8 > 192.168.1.2: ICMP echo reply, id 12345, seq 1, length 64
```

**Example (Failed tcpdump)**:

```shell
tcpdump -i non-existent-interface
```

**Expected Output (Failed)**:

```shell
tcpdump: non-existent-interface: No such device exists
```



### route

The `route` command is used to display and manage the kernel routing table on a Linux system. It helps determine the routing path packets take through the network. Use `route` to view the routing table, add or delete routes, or troubleshoot routing issues on a Linux machine.

**Example (Successful route)**:

```shell
route -n
```

**Expected Output (Partial - Successful)**:

```shell
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0
```

**Example (Failed route)**:

```shell
route add -net 10.0.0.0 netmask 255.0.0.0 dev eth1
```

**Expected Output (Failed)**:

```shell
SIOCADDRT: No such process
```



### dig

`dig` (Domain Information Groper) is a command-line tool for querying DNS servers to retrieve DNS-related information, including name servers, IP addresses, and DNS records. It's commonly used for DNS troubleshooting and debugging. Use `dig` when you need to perform DNS queries, retrieve DNS records (such as A, MX, or TXT records), verify DNS configurations, or diagnose DNS-related issues.

**Example (Successful dig)**:

```shell
dig google.com
```

**Expected Output (Partial - Successful)**:

```shell
; <<>> DiG 9.16.24 <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;google.com.            IN   A

;; ANSWER SECTION:
google.com.         299  IN   A   172.217.4.174
```

**Example (Failed dig)**:

```shell
dig non-existent-domain.com
```

**Expected Output (Failed)**:

```shell
; <<>> DiG 9.16.24 <<>> non-existent-domain.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 54321
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; AUTHORITY SECTION:
com.         899  IN   SO
```



## Troubleshooting Methodology - how to use the tools !

Knowing the tools which are available is only half the battle, to be an effective network troubleshooter you'll also need a systematic approach to the troubleshooting process.  This structured approach helps identify, isolate, and resolve issues methodically.



### Step 1: Define the Problem

The first step in troubleshooting is to clearly define the problem. This may seem obvious, but it's essential to articulate what's wrong precisely. Ask yourself or the person reporting the issue questions like:

- What symptoms are you experiencing?
- When did the problem start?
- Has anything changed recently (e.g., software updates or configuration changes)?
- Is the problem affecting a specific component, system, or network?

By gathering this information, you can create a precise problem statement, which is crucial for effective troubleshooting.



### Step 2: Reproduce the Issue

Once you've defined the problem, try to reproduce it. Reproduction allows you to verify that the issue is consistent and helps you understand its scope. If you can consistently reproduce the problem, you're in a better position to investigate its root cause.

**Tools**: During this step, you might use tools like `nslookup` and `ping` to check network connectivity and resolve domain names. If the issue is related to network communication, `ping` can help confirm if the target host is reachable.



### Step 3: Gather Data

Gathering relevant data is a critical aspect of troubleshooting. Depending on the nature of the problem, you may need to collect logs, error messages, or performance metrics. It's essential to document everything you discover, as this information will be invaluable in later stages of troubleshooting.

**Tools**: You can use various tools here. For Windows, `Event Viewer` can provide system logs and error messages. In Linux, tools like `tcpdump` can capture network traffic for later analysis.



### Step 4: Identify Possible Causes

With data in hand, it's time to brainstorm potential causes of the issue. This is where your knowledge and experience come into play. Consider all the factors that could contribute to the problem, and create a list of hypotheses.

**Tools**: At this stage, you might not use specific tools, but your expertise and knowledge of the systems and applications involved are critical.



### Step 5: Test Hypotheses

Testing your hypotheses involves a process of elimination. Start with the most likely causes and systematically rule them out by performing tests or making changes to the system. As you test each hypothesis, document your findings and whether or not it had an impact on the problem.

**Tools**: Depending on the hypotheses, you might use tools like `ping` or `traceroute` to check network connectivity, or `nslookup` to verify DNS configurations.



### Step 6: Isolate the Issue

Sometimes, troubleshooting reveals that the problem is multifaceted, with multiple underlying causes. In such cases, it's crucial to isolate each issue and address them one at a time. Isolation helps prevent confusion and ensures that solutions are effective.

**Tools**: While isolating issues, you may use network diagnostic tools like `arp` to check ARP cache entries and identify any issues with address resolution.



### Step 7: Implement Solutions

Once you've identified the root cause(s) of the problem, implement solutions. Be methodical in your approach, and consider the potential impact of each change. It's often a good practice to make one change at a time, followed by thorough testing to confirm that the issue is resolved.

**Tools**: If the problem was related to network security, you might use `iptables` in Linux to configure firewall rules or make changes to network security policies.



### Step 8: Verify and Document

After implementing solutions, verify that the problem is resolved. Test the system rigorously to ensure that the issue no longer exists. Once you're confident that the problem is solved, document the entire troubleshooting process. This documentation is valuable for future reference and for sharing knowledge with others.

**Tools**: During the verification phase, you might use tools like `ping` or `pathping` to confirm that network connectivity and latency issues have been resolved.



### Step 9: Prevent Recurrence

To prevent the problem from recurring, it's important to identify any underlying systemic issues. Implement preventive measures, such as software updates, improved monitoring, or changes to configuration management processes, to avoid similar problems in the future.

**Tools**: In the prevention phase, you may use tools like `route` to review and update routing tables to prevent routing-related issues from recurring.

### Step 10: Learn and Improve

Every troubleshooting experience is an opportunity for learning and improvement. Reflect on the entire process, including what went well and what could be done differently. Share your insights with colleagues to build a culture of continuous improvement.

**Tools**: While this step doesn't necessarily involve specific tools, it's essential to gather feedback and use the knowledge gained from troubleshooting to improve your troubleshooting skills and processes.

## Final Words

In this article we looked at command line network troubleshooting tools - we also saw how you could implement these tools as part of a troubleshooting strategy. Knowledge of both will stand you in good stead to tackle all sorts of network issues! 