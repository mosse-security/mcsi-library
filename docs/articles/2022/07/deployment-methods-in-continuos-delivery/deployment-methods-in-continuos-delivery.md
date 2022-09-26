:orphan:
(deployment-methods-in-continuos-delivery)=
# Deployment Methods in Continuos Delivery
 
In this blog post, we are going to learn some CD strategies that are employed in DevOps frameworks.

## Deployment Methods in DevOps environments

Engineers can push code to production environments in a variety of methods. Many programs operate a group of servers, with each server running a different version of the program. Let's take a quick look at these methods.

- **Complete Deployment:** A full deployment modifies all versions of the updated code simultaneously. This was a popular approach among waterfall-methodology teams. In other circumstances, such as with a single server executing a monolithic program, it is still the sole choice. Other deployment options are often chosen because they limit the danger of exposing malfunctioning code by allowing a quick switch back to previously working code. Furthermore, complete deployment may result in service downtime.

- **Rolling Deployment:** A rolling deployment upgrades all systems progressively over time.
  Rolling deployments provide the benefit of exposing just a portion of customers to the risk of problematic code. In this scenario, assuming a balanced user distribution, just 10% of users were introduced to the initial implementation. Furthermore, a rolling rollout is often feasible without causing service delays.

- **Blue-green deployment:** A blue-green deployment is an implementation technique or methodology that uses two workflows to minimise interruption. It supports rollback with near-zero downtime. The main idea behind a blue-green deployment is to transfer traffic from one setting to another. The environments will be similar and run the same program, but the versions will vary.

- **Canary deployment:** A canary deployment technique involves incrementally deploying apps or services to a group of consumers. When this subset of users begins using an existing application, essential software metrics are gathered and evaluated to determine if the latest iteration is ready to be rolled out to all users at full scale or requires to be rolled back for debugging. In workloads, every architecture is upgraded in incremental steps.

- **Recreate deployment:** We halt the earlier version of an application before releasing the current one with this implementation method. For this rollout, service disruption is anticipated, and a full reset cycle is performed.

- **A/B testing deployment:** A/B testing is a configuration in which we execute different iterations of the same application/services in the same environment simultaneously for testing reasons. This method entails diverting a fraction of users' traffic to a new feature or functionality, collecting data and insights, and comparing this to the previous iteration. The judgment call will upgrade the entire infrastructure with the selected version of the application/services after analyzing the input.

**Test your knowledge**

Assume engineers decide to publish a code but do not initially direct any traffic to it. Engineers route a modest amount of traffic to the implementation once it has been deployed. As time passes, they see that no issues have been discovered, and they decide to direct additional traffic to the implementation.

- What type of deployment would it be?

:::{seealso}
Want to learn practical DevSecOps skills? Enroll in [MDSO - Certified DevSecOps Engineer](https://www.mosse-institute.com/certifications/mdso-certified-devsecops-engineer.html)
:::