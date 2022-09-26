:orphan:
(get-the-evidence-you-need-with-forensic-images)=

# Get the Evidence you need with Forensic Images

A forensic image is an image created by a digital forensic examiner during the process of investigating a potential crime. This image is an exact replica of the original data, and can be used to identify and analyze digital evidence.

## Using an Analogy

Analogies are powerful because they help us to understand and explain complex ideas by relating them to something that is more familiar.

In this blog post, we will explore the concept of ‘forensic image’ using a cookbook as an analogy.

Let’s assume that the cookbook has 10 recipes. You want to share some recipes with your friends: Alice, Bob and Jane. Alice would like to have a copy of recipe number 3, Bob would like to have a copy of recipes 4, 6, 7 and Jane would like to have a copy of the whole cookbook. You wish to retain your cookbook and not lend it, so you proceed to make copies of the cookbook as requested by your friends. For the purpose of this discussion, let’s assume the copy is being made using a photocopier.

The cookbook with the various recipes resembles a hard disk with various partitions.

## Introducing forensic images

During an investigation, after acquiring volatile data from a target machine, the investigator proceeds to analyze data from the hard disk. It is always recommended to make a copy of data on the hard disk and analyze the copied data. This is to ensure that actual data on the hard disk remains intact throughout the investigation. This can be likened to you retaining your cookbook and making copies for your friends.

In some cases, only specific partitions are copied from the hard disk of the target computer, while in others, a copy of the complete hard disk is made. Two of your friends require only specific recipes while the third wishes to have a copy of the whole cookbook.

The data copied from a hard disk is referred to as a forensic image. The copying process is formally called as acquisition. Making a copy of files from a target hard disk during a forensic investigation is referred to as acquisition of a forensic image.

## Types of forensic images

Consider a hard disk with three partitions _C:_, _D:_ and _E:_. The complete hard disk is referred to as physical volume and the individual partitions are referred to as logical volumes.

When a copy of the complete hard disk inclusive of all partitions is made, it is referred to as a _physical image_. The copy process is called _physical acquisition_.

When a copy of a specific partition is made, it is referred to as a _logical image_. The copy process is called _logical acquisition_.

## How to acquire a forensic image?

In reality, acquisition of a forensic image is more than just a ‘copy’ process. Various standards and procedures need to be followed by a forensic investigator during acquisition.

When you make a copy of the recipes using a photocopier, you will ensure that the cookbook remains intact without damage. Likewise, when acquiring a forensic image from a hard disk, in order to ensure that data on it remains the same, ‘write blockers’ are used to prevent any writes to it. A write blocker could be a hardware or software tool.

There are various commercial and free tools to assist in the acquisition of a forensic image.

During an investigation in an enterprise environment, given the large capacity of storage devices, only files relevant to the investigation will be acquired in some situations. This activity is referred to as _triage_.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
