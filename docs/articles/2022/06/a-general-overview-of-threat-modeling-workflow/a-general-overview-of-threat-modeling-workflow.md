:orphan:
(a-general-overview-of-threat-modeling-workflow)=
# A General Overview of Threat Modeling Workflow


The threat modeling activity has a consistent plan that may be broken down into many basic elements. In this blog post, we are going to give a basic outline of a threat modeling process.

## A Broad Perspective on Threat Modeling

The fundamental workflow of threat modeling is as follows:

- **Identifying elements:** As a first step, you should start the process of threat modeling by indicating the elements in your network. Evaluate the present and associated factors, data repositories, external sources, as well as agents to the system you are evaluating. You should additionally collect information about the factors you specified, such as metadata. Examine the security features and settings that each item allows or provides. You should also look for apparent flaws, such as an element that exposes a web server through HTTP. Although we will cover it in detail in future blog posts, to give a side note, an element is a conventional form that symbolizes a process or operational unit inside the system under consideration.

- **Decide on the flow:** Continue with determining the flows between the items. Decide how information travels between the objects you specified during the item identification process. Following, for each flow, document metadata such as protocols, data categorization, and sensitivity.

- **Determine assets:** Next, identify assets of interest. Describe any important or noteworthy assets owned by the objects or conveyed by the processes found during the flow evaluation stage. Assets might be either inner data like configurations or external data like user input.

- **Spotting weaknesses:** Now it’s time to spot vulnerabilities of the system. Analyze how the properties of the system objects and processes may affect the confidentiality, integrity, and availability of the assets defined in the previous stage. In this phase, you are specifically searching for infractions of security practices.

- **Recognizing the threats:** To assess how probable each weakness is to be abused, and also which poses a risk to the network, you must correlate weaknesses against the system's resources with malicious attackers.

- **Assess exploitability:** In this phase, you should decide the degree of manipulability. Determine the pathways an adversary may travel across the network to damage resources. This basically implies that in the final stage, you must determine how an opponent may leverage a flaw discovered in the system during the weakness spotting process.

## Conclusion

Threat modeling is an ongoing process that is based on the security knowledge of the teams performing the exercise. Upon completion of this blog page, now you have a basic understanding of this ever-changing and critical activity in the most basic terms.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::