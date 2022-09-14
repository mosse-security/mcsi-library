:orphan:
(network-protocols-the-foundation-of-digital-communication-snmp)=
# Network protocols The Foundation of Digital Communication SNMP
 
If a business has 1000 devices, checking each one individually every day to see if they are operating correctly or not is a time-consuming operation. Simple Network Management Protocol (SNMP) is used to help with this.

## Simple Network Management Protocol (SNMP)

The Simple Network Management Protocol (SNMP) is a network management protocol that allows network devices to communicate management information. SNMP is commonly used to monitor network devices for issues with performance or availability. Although less prevalent, SNMP may also be used to set up network devices. SNMP is a basic protocol that does not offer the same level of administration as more complex protocols such as the Simple Object Access Protocol (SOAP).

## SNMP components

There are 3 components of SNMP:

**1. SNMP Manager:** An SNMP manager is a piece of software that is used to manage SNMP-enabled devices on a network. The manager is responsible for sending SNMP requests to SNMP-enabled devices, and for processing the responses that are received. SNMP managers can be used to monitor and manage a wide variety of devices, including routers, switches, servers, and printers

**2. SNMP agent:** An SNMP agent is a piece of software that runs on a network-connected device and implements the SNMP protocol. SNMP agents expose management information for the device, which can be queried and monitored by SNMP management systems. SNMP agents usually run in the background and are transparent to users of the device.

**3. Management Information Base:** The Management Information Base (MIB) is a database used by a network management system (NMS) to store information about managed devices on a network. The MIB contains objects that can be queried by the NMS to retrieve information about the status and performance of the devices on the network. The MIB is organized into a tree structure, with each object in the MIB having a unique identifier. The MIB can be accessed using the Simple Network Management Protocol (SNMP).

## SNMP messages

SNMP messages are the primary mechanism of exchanging management information between SNMP entities. An SNMP message has a header and a body. The message header provides information about the message, such as the message type, message length, and message ID. The actual SNMP data is contained in the body. Traps and informs are the two types of SNMP messages. Traps are uninvited communications delivered by an SNMP agent to an SNMP management. Informs are messages that are requested by an SNMP manager and sent to an SNMP agent.

Different variables are:

**1. GetRequest:** This message is sent by the SNMP manager to seek data from the SNMP agent. It just retrieves data from SNMP agents. In response, the SNMP agent sends a response message providing the requested value.

**2. GetNextRequest:** This message can be delivered to learn about the data accessible on an SNMP agent. The SNMP manager can request data indefinitely until no more data is available. As a result, the SNMP manager has access to all accessible data about SNMP agents.

**3. GetBulkRequest:** This message is used by the SNMP manager to retrieve huge amounts of data from the SNMP agent at once. It first appears in SNMPv2c.

**4. SetRequest:** The SNMP manager uses it to set the value of an object instance on the SNMP agent.

**5. Response:** It is a message issued by the agent in response to a management request. It will include the data sought when sent in response to Get messages. It will contain the newly set value as confirmation that the value has been set when sent in response to the Set message.

**6. Trap:** These are the messages delivered by the agent without the manager's request. It is sent when there is a problem.

**7. InformRequest:** It was added in SNMPv2c and is used to determine whether or not the trap message was received by the management. The agents can be set to deliver trap messages indefinitely until they get an Inform message. It is similar to a trap but includes an admission that the trap does not offer.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**