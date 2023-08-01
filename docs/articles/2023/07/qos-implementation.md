:orphan:
(qos-implementation)=

# QoS Implementation

Quality of Service (QoS) is a set of techniques and policies used to prioritize network traffic based on its specific characteristics to ensure a certain level of performance for critical applications. The goal of QoS is to manage and control the flow of data within a network to meet the requirements of specific applications, especially those that are sensitive to factors like bandwidth, latency, and jitter.

### Latency

Latency, also known as network delay or round-trip time (RTT), refers to the time it takes for a data packet to travel from the source to the destination and back again. It is essentially the time it takes for a signal to traverse the network. Latency is measured in milliseconds (ms).

High latency can lead to noticeable delays in real-time applications. For example, in video conferencing, high latency can cause participants to experience delays between their actions and the response on the screen, resulting in a disjointed and less natural conversation. In online gaming, high latency can lead to "lag," making the game less responsive and affecting the overall gaming experience.

### Jitter

Jitter, on the other hand, refers to the variation in latency over time. It is the irregularity or inconsistency in the delay of data packets arriving at their destination. Jitter is typically measured in milliseconds (ms) as well.

In real-time applications, consistent latency is preferable. However, jitter can cause variations in the arrival time of data packets, leading to uneven playback in audio and video streams. For instance, in video streaming, jitter can cause fluctuations in the video's frame rate, resulting in a jittery or stuttering playback experience.

Jitter can be particularly problematic in Voice over Internet Protocol (VoIP) calls, where varying delay times can result in choppy or garbled audio, making it challenging for users to communicate effectively.

## Prioritizing Traffic

QoS provides a framework for identifying different types of traffic flowing through a network and assigning priorities to each type based on its specific requirements. For example, real-time applications like voice and video conferencing are assigned higher priority as they demand consistent and reliable transmission to maintain quality.

### Supporting Voice and Video Applications

Voice and video applications are examples of real-time traffic that require a minimum level of bandwidth and low latency. In video conferencing, for instance, delays (jitter) in transmitting data packets can lead to choppy or laggy video, negatively impacting the user experience. QoS helps ensure that such applications receive the necessary network resources to function smoothly.

### Minimum Bandwidth and Low Latency

QoS ensures that voice and video applications receive a guaranteed minimum amount of bandwidth to avoid congestion. Additionally, it reduces the delay in transmitting packets (low latency) to maintain the real-time nature of these applications.

### Traffic Shaping and Prioritization

QoS mechanisms involve traffic shaping and prioritization. Traffic shaping controls the rate at which data is sent or received, preventing network congestion. Prioritization assigns higher priority to real-time traffic, allowing it to bypass lower-priority data during congestion.

### Differentiated Services (DiffServ) Model

QoS often follows the DiffServ model, where traffic is classified into different classes (such as real-time, interactive, and bulk) and treated accordingly. This classification helps routers and switches handle traffic based on the assigned class and priority.

## QoS Implementation

QoS is implemented through various techniques like traffic policing, traffic shaping, and queuing mechanisms. Network administrators configure QoS policies to ensure that critical applications get the required resources while maintaining a fair allocation for other less-sensitive traffic.

The goal of QoS implementation is to ensure that critical applications receive the necessary bandwidth, low latency, and minimal jitter, while maintaining a fair allocation of resources for less time-sensitive traffic. Below is described step by step how QoS implementation works:

**1.	Traffic Classification:** The first step in QoS implementation is to classify the network traffic into different classes or categories based on specific characteristics or requirements. For example, real-time traffic like voice and video communication is classified into one class, while bulk data transfer or file downloads are placed in another class.

**2.	Differentiated Services (DiffServ):** The DiffServ model is often used in QoS implementation. Each class of traffic is assigned a Differentiated Services Code Point (DSCP) value, which represents its priority level. Routers and switches use the DSCP value to differentiate and handle traffic accordingly.

**3.	Traffic Policing and Shaping:** Traffic policing and shaping are QoS mechanisms used to control the rate of data transmission. Traffic policing monitors the incoming and outgoing traffic rates and enforces limits on data flows that exceed specified thresholds. Traffic shaping, on the other hand, buffers and queues traffic to regulate its flow and smooth out bursts.

**4.	Priority Queuing:** Priority queuing involves organizing traffic into different queues based on their priority levels. High-priority traffic is placed in queues with guaranteed bandwidth and low latency, ensuring that it receives preferential treatment during congestion.

**5.	Class-Based Queuing (CBQ):** Class-Based Queuing is a QoS technique that allocates bandwidth to different classes of traffic based on their priority levels. It allows administrators to define bandwidth guarantees for each class, ensuring that critical applications get the required resources.

**6.	Congestion Management:** During periods of network congestion, QoS mechanisms help manage traffic and prevent bottlenecks. For example, Weighted Fair Queueing (WFQ) allocates bandwidth proportionally to each class, preventing a single high-bandwidth flow from dominating the network.

**7.	Traffic Prioritization:** QoS prioritizes real-time and critical traffic over non-critical traffic. This ensures that real-time applications receive the required resources for low latency and minimal packet loss, while non-critical traffic is allocated available resources in a fair and equitable manner.

**8.	End-to-End QoS:** QoS implementation often involves cooperation between different networking devices, including routers, switches, and firewalls, to maintain consistent QoS policies throughout the network path.

## Final words

By employing these QoS techniques and mechanisms, network administrators can ensure that critical applications, such as voice and video communication, receive the necessary performance characteristics, providing users with a smooth, reliable, and high-quality experience.