:orphan:
(secure-data-destruction)=

# Secure Data Destruction 

Today, the secure handling of data is more important than ever – as a security professional it’s critical to understand that this extends beyond just creation and use. Secure data destruction is a critical process that ensures sensitive information doesn't fall into the wrong hands after it's no longer needed. In this article, we’ll take a look at secure data destruction, including various methods, cloud considerations, legal requirements, and the formulation of data destruction policies.

 

## What is secure data destruction? 

Data destruction is a topic you may never have really considered – after all, as IT professionals we often focus most of our effort on (securely) gathering, storing and working with data, however, it’s now more important than ever that we consider what happens to data when it’s no longer required. Legislation, such as the GDPR, imposes a responsibility on organisations to delete data which is no longer needed, while at the same time, there are legal reasons (such as limiting the scope of possible e-discovery processes) which can also compel an organisation to dispose of data which is no longer useful. 

It's hopefully obvious that data cannot simply be deleted, or thrown away (if stored on physical media) – rather, we use secure data destruction processes to ensure that the information has been rendered totally unretrievable. 

 

## Methods of Destruction

Secure data destruction can be achieved via a range of methods – some are more appropriate for one type of media or another, whereas sometimes the decision is based on cost or the sensitivity of data. Some common choices include:

### Burning

Incineration is a highly effective method for destroying data either recorded on paper or stored on physical storage media, like optical discs. This method needs little explanation except to mention that it’s critical the media is reduced fully to ashes to prevent readable fragments from remaining. This method leaves no chance for data recovery, making it a reliable choice for completely obliterating sensitive information.

### Shredding

Industrial-grade shredders can transform physical storage media into tiny, irreparable fragments. This method applies to a wide range of materials, from paper and CDs to hard drives, rendering the data they contain beyond reconstruction. While this is one of the most effective options the required equipment can be very expensive, meaning it’s out of reach for many smaller companies. By contrast, many data centres have shredders on-site to perform disposal of old drives without ever leaving the building. Specialised third-party companies also exist that can shred drives or media for a fee, usually providing the contracting party with a certificate of destruction or even video proof. 

### Pulping

In this process, storage media undergoes mechanical breakdown, transforming them into a pulp-like substance. Pulping is most appropriate for materials like paper, rendering them unreadable and (as a bonus) suitable for recycling.

### Pulverizing

Similar to shredding, pulverizing subjects storage media to intense mechanical force, turning them into minuscule particles. This method ensures data obliteration, with the added benefit of making reconstruction virtually impossible. In theory, one can pulverise a drive with a hammer and enough time, however for the job to be done “properly” the components need to be reduced down to very small parts indeed – hence this approach wouldn’t usually meet the bar from a regulator perspective. 

### Degaussing

Suitable for magnetic media like hard drives and magnetic tapes, degaussing employs powerful magnetic fields to demagnetize the storage media, thereby erasing the data stored on them. Once degaussed, the media can no longer store or transmit information.

### Third-Party Solutions

Entrusting data destruction to professional services ensures compliance with industry standards and regulations. Certified data destruction vendors offer secure disposal services that adhere to rigorous protocols, guaranteeing the irrecoverability of sensitive data. These experts utilize a combination of physical destruction methods, ensuring optimal security – this introduces additional cost but is often a better option when low volumes of destruction are required. 

 

## Data Destruction in the Cloud

Secure data destruction in cloud environments introduces unique challenges due to the nature of shared infrastructure and virtualization technologies. Traditional methods of physical destruction are not applicable, making digital techniques essential for rendering data unrecoverable. 

The primary method of data destruction in a cloud environment is Cryptoshredding. A prominent method is Cryptoshredding, which employs encryption to make data indecipherable. Cryptoshredding involves generating a unique encryption key for each piece of data. When data needs to be destroyed, its associated encryption key is discarded, effectively rendering the data unintelligible. This method ensures that even if remnants of data are left within the cloud environment, they are useless without the corresponding key for decryption. Cryptoshredding aligns with the dynamic nature of cloud environments and is particularly effective for safeguarding data in shared storage infrastructures.

As an alternative, Cloud providers often implement secure deletion protocols that overwrite storage space with random data, erasing traces of the original data. This practice is particularly relevant when individual files or resources need to be removed while ensuring that residual fragments are overwritten and irretrievable.

In addition, while not directly a removal technique, isolating data within distinct virtual environments or containers helps ensure that data deletion is comprehensive. By segregating data, cloud providers can direct secure deletion processes to specific segments of the infrastructure, reducing the risk of residual data being left behind.

*Tip: When opting for a deletion service offered by a cloud service provider, ensure that the chosen mechanism is compliant with any relevant regulations or compliance standards that apply to your data!* 

 

## Approaches Not Recommended for Secure Data Destruction

While secure data destruction methods aim to render data irretrievable, some approaches are not recommended due to their potential shortcomings:

**Formatting or Deleting** - Simply formatting a storage device or deleting files does not ensure data eradication. Basic deletion methods usually leave recoverable remnants (often the whole file!) on the media, making it vulnerable to data recovery tools.

**Physical Destruction without Verification** - Physical destruction without proper verification leaves room for error. Simply breaking or smashing storage devices might not guarantee complete destruction, and fragments could still potentially contain recoverable data.

**Overwriting with a Single Pass -** Overwriting data with a single pass of random data may not be sufficient to thwart sophisticated data recovery techniques. Multiple passes with random data are more effective in making recovery unfeasible.

**Insecure Third-Party Services** - Relying on uncertified or untrusted third-party services for data destruction can lead to security risks. Ensure that any third-party data destruction services adhere to industry standards and compliance requirements.

**Incomplete Cloud Deletion** - Deleting files within cloud environments without proper data isolation and secure deletion protocols can leave residual data fragments. Always follow the cloud provider's recommended secure deletion procedures.

 

## Secure Overwriting for Data Destruction

Overwriting data with random or specific patterns is a widely used method for secure data destruction. When done correctly, this technique ensures that the original data becomes irrecoverable. This being said secure overwriting requires *multiple* passes with randomized patterns, making it exceptionally challenging for data recovery tools to reconstruct the original content. There is debate about the number of passes and specific approaches required to ensure that overwriting is fully effective – usually, you will use an approach which is considered acceptable by whichever governance standard is in place for your organisation. Two examples of guidance include: 

### NIST Special Publication 800-88

NIST outlines recommendations for secure data overwriting, emphasizing the importance of multiple passes with randomized patterns. The publication categorizes data sensitivity levels into three categories:

1. **Clear**: Data that is overwritten using organization-defined methods.
2. **Purge**: Data that is overwritten with a predefined pattern or a random pattern, rendering the original data irretrievable. The number of passes depends on the storage media type and the level of assurance required.
3. **Destroy**: Complete physical destruction of the storage media, ensuring that data recovery is impossible.

### DoD Standard 5220.22-M

The DoD standard prescribes a three-pass method for secure overwriting:

- **Pass 1**: Overwrite all addressable locations with a binary zero (0x00) pattern.
- **Pass 2**: Overwrite all addressable locations with a binary one (0xFF) pattern.
- **Pass 3**: Overwrite all addressable locations with a random pattern.

This method is recommended for media that will be reused within the organization but not for media that will be released from its control.

 

## Data Destruction - Legal Requirements

As mentioned above, various legislations m*andate* proper data destruction practices to protect privacy, prevent data breaches, and ensure compliance. Notable regulations to be aware of include:

- **General Data Protection Regulation (GDPR)**: The GDPR, applicable to European Union member states and beyond, requires organizations to erase personal data when it's no longer needed for its original purpose. Article 17 of the GDPR, known as the "right to erasure" or "right to be forgotten," empowers individuals to request the deletion of their personal data.
- **Health Insurance Portability and Accountability Act (HIPAA)**: HIPAA mandates secure data destruction in the healthcare industry. Healthcare providers and organizations are required to ensure that electronic protected health information (ePHI) is destroyed in a way that it cannot be reconstructed.
- **Payment Card Industry Data Security Standard (PCI DSS)**: PCI DSS sets standards for secure payment transactions. Requirement 9.10 of PCI DSS stipulates the secure disposal of media containing cardholder data when no longer needed for business or legal reasons.
- **California Consumer Privacy Act (CCPA)**: The CCPA grants California residents the right to request the deletion of their personal information held by businesses. Organizations covered by the CCPA must comply with deletion requests and ensure secure data destruction.

This is far from an exhaustive list but gives a sense of the way in which modern regulations emphasize the importance of secure data destruction in various industries - reinforcing the need for organizations to implement comprehensive data disposal policies and practices to safeguard sensitive information and maintain legal compliance.


## Data Destruction Policies

As part of legal compliance, as well as to ensure procedures are followed in a predictable way, it’s essential for companies to formulate and follow detailed data destruction policies. These policies outline procedures, methods, and timelines for secure data disposal. They ensure consistency across an organization, from determining which data to destroy to specifying how different types of media should be handled.

## Final Words

Secure data destruction is an integral aspect of data lifecycle management. Whether by physical means like burning and shredding or through advanced methods like degaussing and third-party solutions, rendering data unrecoverable safeguards against unauthorized access. Today, it’s more important than ever to treat data in a secure way right the way through to destruction – data destruction policies aligned to relevant regulatory standards help an organisation achieve just that. 

 

 
