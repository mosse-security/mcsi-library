:orphan:
(load-balancing-strategies)=

# Load Balancing Strategies

Load balancing involves distributing network traffic or workload across multiple servers, ensuring that no single server is overwhelmed and that resources are utilized efficiently. Other articles on our library have looked at different types of load balancer, and in this article will explore some of the various load balancing strategies, including active/active and active/passive configurations, scheduling techniques, virtual IP, and the concept of persistence.

 

## Active/Active Load Balancing

Active/active load balancing is a configuration where multiple servers or devices are actively processing requests simultaneously – that is to say, both are active. This setup ensures load distribution across all servers, thereby preventing any single server from becoming a bottleneck. This approach maximizes resource utilization, enhancing system efficiency and responsiveness. In an active/active setup, servers continuously share the load, providing redundancy and fault tolerance. If one server fails, the remaining servers continue to handle traffic seamlessly. This architecture is particularly effective for scenarios requiring high availability and performance, such as content delivery networks (CDNs) or large-scale web applications.

For an example, imagine a large e-commerce platform that experiences high traffic volumes, especially during peak shopping seasons. An active/active load balancing configuration would be ideal in this scenario. The platform could have multiple servers actively processing incoming requests simultaneously. This approach ensures that the workload is evenly distributed across the servers, preventing any one server from becoming overwhelmed. If one server experiences a sudden surge in traffic, the load balancer can direct new requests to the other available servers, maintaining smooth performance and preventing downtime.

 

## Active/Passive Load Balancing

Active/passive load balancing involves designating one server as the primary or “active” server, responsible for processing incoming requests, while the others remain passive (often called “standby”), ready to take over if the active server fails. In the event of a failure, the passive server takes on the active role, minimizing downtime. Active/passive setups are often used for critical applications where seamless failover is essential. This configuration provides redundancy but may underutilize resources during normal operation since only one server handles traffic. On the other hand, active/passive systems tend to be less complex and are typically more straightforward to document as part of governance risk and compliance exercises. 

Consider a critical financial application used for online trading. In this case, maintaining uninterrupted service is of paramount importance. An active/passive load balancing setup would be suitable. The primary active server would handle incoming requests and transactions. However, since the application deals with financial transactions, there's no room for errors or downtime. Therefore, a passive server is kept on standby. If the primary server fails, the passive server takes over seamlessly, ensuring that trading activities continue without disruption. The system is relatively simple to document, which helps meet the strict compliance requirements financial organisations have to adhere to. 

 

## Scheduling Techniques

Scheduling algorithms determine *how* incoming requests are distributed among the available servers. Various algorithms cater to different needs, including round-robin, affinity-based, least connections, and least response time. 

Affinity-based scheduling, also known as session affinity, aims to maintain continuity for a session by directing all session-related traffic to the same server. This approach is particularly beneficial for applications like web applications, where maintaining session state is crucial. With affinity-based scheduling, the load balancer keeps track of the last server it directed a particular session to. Subsequent traffic from the same session is consistently routed to the same server, ensuring that session-related data and context remain intact. When a new connection is established, the load balancer assigns the session to the next available server in the rotation. Affinity-based scheduling enhances user experience by preventing data loss and ensuring seamless interactions.

Round-robin scheduling involves a straightforward approach of sending each new request to the next server in rotation. This even distribution ensures that all available servers receive an equal share of incoming traffic. Round-robin is commonly used in situations where server loads are relatively uniform and predictable. However, to account for variations in server capacities or performance, a modification known as weighted round-robin is often implemented. Weighted round-robin assigns a numerical weight to each server, reflecting its capacity or capabilities. Servers with higher weights receive more requests, providing a balance between load distribution and server efficiency.

Least Load scheduling focuses on directing incoming requests to the server with the lowest current load. This approach ensures that server resources are efficiently utilized, preventing potential overloading of any specific server. By dynamically evaluating the server loads and adjusting traffic distribution accordingly, least load scheduling maximizes overall system performance.

Finally, on the other hand, Least Response Time scheduling places emphasis on user experience by directing requests to the server that exhibits the quickest response time. This approach is particularly valuable for applications where low latency and swift interactions are paramount. By continuously monitoring server response times and selecting the server with the shortest response time for each request, least response time scheduling minimizes delays and provides users with a smoother and more responsive experience.

The above scheduling techniques all underscore the importance of dynamic decision-making in load balancing. These strategies leverage real-time data to ensure optimal resource utilization and user satisfaction. Let's say you're running a media streaming service with a diverse user base, including both free and premium users. To ensure optimal resource usage and provide a smooth streaming experience, you could use a scheduling technique like Least Response Time. This algorithm would direct users to the server with the quickest response time. Premium users, who may expect higher performance, would benefit from this approach as they are more likely to experience minimal buffering and lag. You might choose to use Least load for free users, who still need a good experience but whose connections we do not want to overload a server. 

 

## Virtual IP (VIP)

A Virtual IP (VIP) is a single IP address assigned to a load balancer that fronts multiple servers. Clients interact with the VIP, which then forwards the requests to the appropriate server based on the load balancing strategy employed. VIPs are also often used in networking as a single point to direct management or control plane traffic to. The main benefit of VIPs is to mask the complexity of the backend server infrastructure, simplifying access for clients. This abstraction enhances scalability, as servers can be added or removed without affecting the VIP or the client-side configuration. A VIP configuration also helps greatly when servers need to be taken offline for maintenance or upgrades, since the server “behind” the VIP can simply be swapped without any configuration changes being needed on the customer end. 

Consider a cloud-based productivity suite used by businesses. The suite includes various applications like document collaboration, email, and project management. Each of these applications runs on different servers, but users interact with a single unified platform. Implementing a Virtual IP (VIP) in this scenario would simplify user access. Users would access the suite through a single IP address, and the VIP would distribute the traffic to the appropriate application servers based on the user's actions. This abstraction hides the backend complexity, providing a seamless user experience.

 

## Persistence

Persistence, also known as session affinity, is the mechanism that ensures that requests from a specific client are consistently directed to the same server for the duration of a session. As we mentioned above, while load balancing typically aims to distribute traffic evenly, certain applications require sessions to remain on the same server to maintain state. For example, in e-commerce websites, maintaining a shopping cart throughout a user's session necessitates persistence. Load balancers can employ techniques like source IP affinity or cookie-based affinity to achieve this, ensuring seamless user experiences without losing session context.

Think of a social media platform where users engage in real-time chats and discussions. To ensure that users can maintain ongoing conversations without interruption, session affinity or persistence is essential. If a user is interacting with a specific chat thread, the load balancer should consistently direct their requests to the same server that hosts that chat thread. This way, the user doesn't lose their context or ongoing conversation. Persistence ensures that the session remains intact, enhancing user satisfaction and engagement. 

# Final words

Load balancing is a vital technique to achieve high availability, fault tolerance, and efficient resource utilization in modern IT environments. As we have seen here, choosing the right load balancing strategy can have a significant impact on user experience. Active/active and active/passive configurations offer different approaches to distributing traffic and handling failures, catering to various use cases. Scheduling techniques determine how requests are allocated among servers, while Virtual IPs abstract the complexity of server infrastructure. Persistence ensures that sessions remain intact by directing specific clients to the same server. 
