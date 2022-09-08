:orphan:
(track-your-configurations-with-a-version-control-system-vcs)=
# Track Your Configurations With a Version Control System (VCS)
 

A version control system (VCS) is a mechanism in which modifications to a file (or collection of files) are typically logged so that they may be recalled at any time.

## Why we need a Version Control System?

There are several advantages to adopting VCS for a task as follows:

### Cooperation

At any time, anybody or everyone on the team can collaborate on any project file. There is no doubt about where the most current edition of a file or the entire project is. A version control system is at a shared, central location.

### Effective Version Storage

Maintaining a version of a file or a whole work upon changing things is a necessary practice, so without a VCS, it becomes difficult, time-consuming, and error-prone.

We may save the full project and provide the names of the versions using a VCS. In a `README` section, we may additionally describe the projects and what changes have been made in the latest revision versus the prior one.

### Recovering Previous Versions

When you make a mistake with your current code, you may easily restore the modifications in a matter of minutes.

## Various forms of Version Control Systems

Version Control Systems are classified into several categories.

### Local VCS

All changes to a file in a local VCS are stored on the local computer, which has a database that contains any modifications to a document under revision control, such as the revision control system (RCS).

### Centralized VCS

We can cooperate with the other Devs on various machines using a centralized version control system. Therefore, for these VCS, we require a single server that has all of the versions of files. Users take a look at or check contents via a single central server, such as Subversion (SVN).

### Distributed VCS

In a decentralized VCS, the user can check the most recent version of the file. The client may also replicate the entire repository. As a result, if any of the servers fails, the user repositories may be transferred back to the server to recover them. Git is one example of this which we will dedicate another blog for explanation of basic _Git_.

## Summary

Upon completing this blog, now you know the general aspects and benefits of a Version Control System. If you want to keep track of every modification to the configuration file, VCS is the way to go.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**