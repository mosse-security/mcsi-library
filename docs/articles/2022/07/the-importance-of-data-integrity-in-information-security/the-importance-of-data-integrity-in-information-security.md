:orphan:
(the-importance-of-data-integrity-in-information-security)=
# The Importance of Data Integrity in Information Security
 
Organizations acquire and store massive amounts of data. Numerous critical business procedures within the organization depend on the accuracy and comprehensiveness of this stored data. There are several ways in which the data's accuracy can be harmed. If this data is altered or deleted by a third party without authorization, the consequences for the business could be severe, especially if the compromised information was of a sensitive nature. Thus, it is crucial for a company to protect the accuracy of the data it stores by implementing the necessary security measures. This article covers in-depth information about data integrity along with details on its significance, various types, and several techniques that can be used for the preservation and verification of data integrity.

## What is meant by Data Integrity?

In the context of information security, data integrity refers to the assurance of the reliability and accuracy of the information and information systems, and the prevention of any unauthorized modification. In order to protect the information from unexpected modification and to deliver it safely to its intended destination, it is important that different security controls(hardware and software controls) work together. Strict access controls, intrusion detection, error checking, and validation in the form of hashing algorithms are some of the ways that can be used to combat the threats that can harm the integrity of information and information systems.

When an attacker introduces malware such as a logic bomb, or a back door into a system, the integrity of the system may be jeopardized. This can therefore compromise the accuracy of the data stored on the system through corruption, malicious modification, or the substitution of accurate data with false information. Most often, people make mistakes that compromise a system's integrity or its data (although internal users may also commit malicious deeds). Users may unintentionally delete configuration files, for instance, if their hard drives are full and they mistakenly believe that since they don't recall ever using the file, it's safe to remove it. Or, for instance, a user may enter inaccurate information into a data-processing application, resulting in a consumer being charged $3000 rather than $300. Another frequent way in which individuals can mistakenly modify or corrupt the data is by incorrectly altering the data stored in databases—a mistake that can have long-lasting consequences.

It is therefore imperative that the users' capabilities are minimized and restricted by the use of security controls so that the mistakes become less frequent and less harmful. Users shouldn't be allowed to read or access system-critical files. Applications must include checks for legitimate and reasonable input values. Only authorized users should be able to alter data in databases, and any data that is being sent over a network should be encrypted or protected in some other way.

## Why is Data Integrity Important?

Protecting data integrity and ensuring data completeness is essential. The majority of companies cannot use compromised data. Protecting and maintaining the integrity of the data has become more and more important as firms gather more and more data. Without accuracy and great integrity, your data is worthless. The following list includes a few justifications for the significance of maintaining data integrity in an organization: 

**Data integrity provides accurate, trustworthy information:** 

Data integrity security controls employed by the organization ensure that the information and information systems cannot be accessed or modified in an unauthorized manner. Maintaining the data's integrity, comprehensiveness, and consistency guarantees that it is easily available to authorized users, that decision-making processes that depend on accurate data are improved, that fraud is prevented, and many other benefits.

**It helps in decision making:**

Data integrity is important because it helps ensure the accuracy of data, which in turn helps ensure that an organization’s decisions are based on accurate information. If an organization relies on inaccurate or unreliable data to make decisions, then those decisions will not be as effective as they could be.

**It helps in accessing data:**

Data Integrity is very important when it comes to requiring timely access to an organization's data that is accurate and free of errors. Data integrity is important as it guarantees and secures the searchability and traceability of your data to its original source.

**It prevents fraud and other illegal activities:**

Data integrity security controls in the form of audit trails prevent and deter organizational fraud and other illegal activities. These integrity verification controls maintain a record of data modification or deletion by keeping track of:

* Who accessed the data and why
* What changes were made to the data
* When were those changes made

Therefore by keeping this record, data integrity controls ensure that insiders or attackers are not able to commit illegal activities and that their actions are detected in a timely manner.

## Data Integrity in a Database

Data that is saved in a database, data mart, or another type of data architecture within an organization is very important in terms of its completeness, correctness, and consistency. Data that has a complete, comprehensive structure with the right data types is said to have integrity and is very valuable to the organization. The values of the data are standardized using a data model and/or data type.  Data integrity is a required security measure in several database software applications. These integrity controls are employed in a variety of ways, including replication, locking mechanisms, error checking and validation, and more. Three types of data integrity services are typically offered by a database software:

### Semantic Integrity

A semantic integrity mechanism ensures that structural and semantic rules are followed. These rules address procedures that could negatively affect the structure of the database as well as data types, logical values, uniqueness requirements, and other topics. The database software's semantic integrity rules make sure that the data entered in a row reflects the desired or permitted value for that row. Semantic integrity is breached, for instance, if a database row requires a user to provide a value of the data type string but a user enters an integer value and it is accepted.

### Refrential Integrity

A database is said to have referential integrity if each of its foreign keys matches a primary key that already exists in the system. A database is made up of various tables, each with its own set of rows and columns. A column or group of columns, known as a primary key in a table uniquely identifies each row of the table. The foreign key of a relational database table is a column or a group of columns that connect the data in two separate tables. It serves as a cross-reference between the tables, connecting them by mentioning the primary key of another table. The database software's referential integrity verification procedures ensure that no foreign key relates to an invalid primary key or a null value.

### Entity Integrity

Entity integrity assures that the tuples in the database are uniquely identified by primary key values. In a relational database, a tuple includes all of the data for a single record. In order to understand the concept of entity integrity, consider an example. Let us suppose that a database contains client contact information and the table fields include categories such as name, social security number, phone number, and email address An illustration of a tuple for that database could be: John Doe 123-45-6789 111-222-3333 jondoe@example.com XYZ. Now let us suppose the primary key is the social security numbers of the customers, in which case, no two customers could have the same social security number. For the sake of entity integrity, every tuple must contain only one primary key. If it does not have a primary key, it cannot be correctly referenced by the database.

## Data Integrity Preservation and Verification Controls

This section goes over some of the data integrity preservation and verification controls that can be employed by the organization. Some of these controls are given below:

### Hashing Algorithms

An organization can employ hashing algorithms to make sure that data is not changed in an unauthorized way while it is being transmitted over a network to its destination. A hashing algorithm is a one-way cryptographic hash function that takes input or data that can be of any length and produces a string that is of a specific or fixed length. This fixed length value is also known as the hash value. The hashing algorithm is not a secret—it is publicly known. The secrecy of the one-way hashing function is its “one-wayness.” The function is run in only one direction and not in the other direction.

In order to understand the how hashing function works to verify the data's integrity let us consider the following example. For example, if John wants to send a message to Kate and he wants to ensure the message does not get altered in an unauthorized fashion while it is being transmitted, he would calculate a hash value for the message and append it to the message itself. When Kate receives the message, she performs the same hashing function John used and then compares her result with the hash value sent with the message. If the two values are the same, Kate can be sure the message was not altered during transmission. If the two values are different, Kate knows the message was altered, either intentionally or unintentionally, and she discards the message.

### Access Controls

Access controls are security measures that enforce the proper security measures based on the classification of the media/information and limit who can access each piece of information to only those people defined by the owner of that data. Access controls include physical controls (such as locked doors, drawers, cabinets, or safes), technical controls ( access and authorization control of any automated system), and administrative controls (the actual rules for who is supposed to do what to each piece of information).

By making sure that only appropriate and authorized individuals are able to access and modify sensitive data, access controls can aid in maintaining the integrity of that data within an organization. It might be difficult for companies to have a clear understanding of who has access to data and what they are doing with it if there isn't such a robust solution in place.

### Transmission cyclic redundancy check (CRC) functions

An error-detection code called a CRC is employed to check the data's accuracy and completeness. Cyclic Redundancy check codes are similar to checksums and are appended at the end of the data that is to be transmitted over the network to the destination. This data is converted into bits before being transmitted over the network. However, during the transmission, interference from the surrounding signals on the network can cause these bits to become corrupted or lost. These corrupted bits can result in the receiver receiving incorrect data, which is the root cause of errors. The three primary methods for finding errors in data frames are parity check, checksum, and cyclic redundancy check  (CRC).

Whether or not an error occurred in the frame that was transferred over the network is determined by error detection algorithms. To detect faults, the sender must send some additional bits in addition to the data bits. The receiver makes the necessary checks using the extra redundant bits. Before the message is transmitted to the top levels, if the data is error-free, the extra bits are eliminated. CRC functions are therefore used to verify the integrity of the data that was delivered over the network by ensuring that the data that was received at the destination is accurate, complete, and free from errors.

### Input validation Controls

The techniques used in applications for comparing the input received by the application to a standard set within the application are known as input validation mechanisms. It i imperative to validate the integrity of the data and the source from which the input is being accepted by the application. This is particularly important if the source of the data is an end user, an unidentified source, another application, or a third party. Application developers must integrate necessary and appropriate security controls into the application that verify and validate the input data. Data validation must be done on a regular basis to prevent corruption of data processes.

### Establishing Audit Trails
Any activity involving the operating system, applications, or user actions is included in an audit trail, which is a series of events that must be logged on a computer. A database or file audit trail must contain a permanent record of all data in the system, including all modifications that have been performed. Transparency regarding all transactions and user interactions, including what users are doing, what kinds of documents they are viewing, and who they exchange files and documents with, is provided through audit logs and trials. Data from several sources, including event logs, database queries, system events, and more, should be included in an audit trail. In order to examine this data on a regular basis, the organization must define clear roles and responsibilities depending upon the system's complexity and the purpose for which the system is used. 

### Data Backup

The term "data backup" refers to a group of security measures that enable an organization to duplicate its original data in a different location, enabling it to retrieve that data in the event of data loss or corruption. By guaranteeing that a company has backup copies of its data in case the integrity of the primary data is compromised, data backups preserve the integrity of its critical data.

## Conclusion

Data integrity is a critical component of an organization's overall data security. Given that numerous businesses throughout the world are gathering enormous volumes of data, it is crucial to maintain the accuracy and dependability of the data through various controls that have been covered in this article. This will not only guarantee that the data is safe from unauthorized change or corruption, but it will also guarantee that the organization is compliant with relevant security laws and regulations.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::