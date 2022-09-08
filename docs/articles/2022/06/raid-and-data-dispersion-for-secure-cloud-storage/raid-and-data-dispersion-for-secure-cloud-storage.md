:orphan:
(raid-and-data-dispersion-for-secure-cloud-storage)=
# RAID and Data Dispersion for Secure Cloud Storage
 

Resilient data protection systems are important as they protect stored data from corruption and loss. In a cloud-based storage cluster, data is stored on multiple servers, this makes it vulnerable to data loss if one or more of the servers fails. A resilient data protection system ensures that stored data is safe and can be accessed in case of a server failure.

In a cloud-based storage cluster, there are two fundamental approaches to data protection:

- RAID (redundant array of independent disks)
- and data dispersion.

These two strategies for data security are very related to each other and offer a standard amount of strength and stability. While the physical and/or logical infrastructure may be slightly influenced by negative events such as disruptions and threats, most of the data would not be gone forever.

## Redundant array of independent disks (RAID)

### Striping

Most RAID systems keep all data over many drives using a technique known as striping. This enables more efficient data recovery since when one of the drives dies, the missing data may be completed by the other drives.

There are various degrees of speed, redundancy, and integrity in certain RAID systems, depending on the demands of the owner.

### What is a parity bit?

A parity bit's aim is to give an easy mechanism to check for mistakes afterward.

### What is erasure coding?

Erasure coding involves dividing a block of data into several pieces (data chunks) and generating extra parts (parity blocks) for data recovery afterward.

## Data dispersion

### Bit Splitting

A related approach is data dispersion, in which data is split into "chunks" that are encrypted with parity bits and afterward transferred to multiple disks in the cloud ensemble. Parity bits and erasure coding enable the retrieval of partial data (stored on a single "drive" or device) by reconstructing the lost data from the rest of the data and the parity bits/erasure code.
Data dispersion is analogous to establishing a RAID array in a cloud infrastructure.

It also secures your data; if your information is scattered, it is not exposed when the investigator examines the machine searching for another tenant's data.

**What is Secret sharing made simple (SSMS)?**

SSMS is a bit-splitting approach that consists of three stages:

- encryption,
- information dissemination,
- and dividing the encryption key.

Because the pieces are signed and dispersed to many cloud vendors, decryption is impossible without both randomly picked material and encryption key shards.

## Benefits of data dispersion

Data dispersion has several advantages.

- Based on the encryption setting, fractional loss of data will not lead to inaccessibility of the whole data set; the lost piece can be retrieved using the parity bits/erasure coding from the other components in the cluster.
- Another advantage is additional protection from theft: when a single device storing dispersed information is stolen from the cloud data center or exploited by a malicious mechanism, the pieces of information on that device will be meaningless or useless to the criminal because they will be unintelligible out of context.

## Summary

We all want to store our data securely in the cloud. Furthermore we want to apply resilient methods for data storage in the cloud to ensure the ability to restore and resume operations. In this blog, we have covered two methods which we can utilize to achieve this goal: RAID and data dispersion.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**