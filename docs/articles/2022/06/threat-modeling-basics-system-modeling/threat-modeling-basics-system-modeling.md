:orphan:
(threat-modeling-basics-system-modeling)=
# Threat Modeling Basics: System Modeling
 
In this blog post, we are going to explain what is system modeling and why it is an essential part of threat modeling. Let’s start by defining what is threat modeling.

## What is system modeling?

As we already learned in a [previous blog post](a-general-overview-of-threat-modeling-workflow), threat modeling detects problems before they occur and predicts risks before they occur. So what do we mean by modeling? Modeling is a technique for abstracting or representing a system, its elements, and its relationships.

System modeling is the first step in the threat modeling technique. The data collected from the system model is used as a feed for the threat modeling exercise.

## Importance of system modeling

To guarantee that our system analysis would be both feasible and successful, we must limit the complexities and volume of data to be considered during assessment while maintaining an adequate amount of information. Abstracting a system helps a lot for this purpose. It is easier and less expensive to modify the model and its elements rather than to alter established infrastructures or application code.

With system modeling, we illustrate change on a conceptual, smaller size rather than jumping into production immediately, to think properly about what's ahead, or to determine what materials and frameworks could be required.

Using a model assists us to comprehend the complexities and minute details of the product and production operation. Before we build our products, we must model them, expose them to theoretical stress, and analyze how that will affect them. This allows us to target weaknesses efficiently.

Now let’s look at different modeling types.

## System Modeling Types

When developing a system model you can benefit from the following model types:

- Data flow diagrams (DFDs): DFDs illustrate the movement of data across parts of the system as well as the attributes of each element and stream. DFDs are the most often used system models in threat modeling and are inherently enabled by many graphics applications.

- Fishbone diagrams: These cause-and-effect diagrams are also known as Ishikawa diagrams, and they depict the associations between an output and the fundamental underlying cause that allowed such an impact to happen.

- Process flow diagrams (PFDs): PFDs depicts the operational flow of the system parts via activities.

- Sequence diagrams: Sequence diagrams are based on the Unified Modeling Language (UML) and they illustrate and show the relationships of various parts of your system in an ordered form.

Since they enable you to comprehend the status of your system across time, sequence diagrams may aid in the identification of risks. With the help of sequence diagrams, you can also examine the system's attributes, as well as any hypotheses or predictions related to your system.

- Attack trees: Attack trees represent the stages along a route that an adversary could take in an attack.

## Conclusion

As we have learned from the blog page, you can utilize system models to have a better understanding of our design’s practicality, vulnerabilities, and current operational status. These system-modeling tools can help you notice changes which are vital to discover and avoid any vulnerabilities. You can update your security posture by modifying your system design and evaluating hypotheses. Employ a model type that is best suitable for you.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::