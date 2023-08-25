:orphan:
(serverless-architecture)=

# Serverless Architecture

Serverless architecture is a modern approach to building and deploying applications in which  the responsibility of managing servers is shifted from the developer to the cloud provider. In a serverless setup, developers focus solely on writing code to implement specific functions or services, without needing to worry about server provisioning, scaling, or maintenance. If the term is new to you it’s important to remember that “Serverless” is a bit misleading – there ­*are* still servers involved, but they’re wholly maintained and managed by the cloud provider, so the product becomes “serverless” from the perspective of the customer.



## How Serverless Architecture Works

In serverless architecture, applications are broken down into smaller units called functions. These functions are designed to perform specific tasks or processes. When a function is triggered by an event, such as an HTTP request or a database update, the cloud provider automatically allocates the necessary resources to execute that function. Once the function's task is complete, the resources are released, making the architecture highly dynamic and efficient.



## Understanding Serverless Architecture and the Role of Servers

As mentioned above, it's important to clarify that despite the term "serverless," serverless architecture *doesn't* eliminate servers entirely. Instead, it shifts the responsibility of managing servers from the developer to the cloud provider. In a serverless setup, developers don't need to concern themselves with provisioning, maintaining, or scaling servers – rather, the cloud provider dynamically manages the underlying infrastructure to ensure optimal performance and scalability. “Serverless” therefore really just means that the complexity of server management is abstracted away from the developer. With a service like AWS Lambda or Azure functions, a developer only needs to specify the version of the language they need to run (for example, Python 3.10), provide the code, and the provider does the rest. 

This abstraction allows developers to solely focus on writing code for their application's specific functions, while the cloud provider handles the orchestration and allocation of server resources as needed. This distinction is crucial in understanding the efficiency and convenience that serverless architecture (and cloud native design in general) offers, enabling developers to create and deploy applications without getting bogged down in the intricacies of server management.

 

## Why Use Serverless Architecture

There are several key benefits to using serverless architecture:

- **Cost Efficiency:** With serverless, you only pay for the actual computing resources used during function execution, rather than maintaining and paying for idle servers. Serverless functions are often billed down to the microsecond of execution time.

- **Scalability:** Serverless platforms can automatically scale functions to handle varying workloads, ensuring optimal performance during peak times without manual intervention.

- **Reduced Management:** Developers can focus on coding and business logic, as the cloud provider manages infrastructure maintenance, updates, and security patches. This can be a major advantage for small teams who may not have operations staff capable of properly (and securely) managing servers. 

- **Rapid Development:** Serverless allows for quicker development cycles, as you can deploy individual functions without deploying an entire application.

- **Improved Debugging:** When application functionality is spit into individual functions, it’s easier to debug and detect issues with aspects which are not working as expected. 

- **Excellent integration with cloud products:** Even if your main production application workloads do not require or are not compatible with the serverless approach, functions can be a fantastic way to perform small management tasks within the cloud itself – they typically have excellent integration with other products offered by a cloud platform (see below example).

  

## When Not to Use Serverless Architecture

As always, while serverless architecture offers numerous benefits, there are also situations where serverless computing is not the best choice, these include:

- **Long-Running Processes:** Serverless functions are optimized for short-lived tasks. Applications with functions requiring extended execution times might face limitations.
- **Consistent Workloads:** If your application consistently demands high computing resources, a traditional server-based approach could be more cost-effective.
- **Resource-Intensive Tasks:** Applications with tasks demanding substantial memory or processing power might face limitations within the confines of serverless environments.
- **Security / Regulatory requirements:** Depending on the regulatory framework which an organisation operates in, or their internal policies, it may be necessary to use isolated hardware even within a cloud environment – serverless environments may not support this. 

## Serverless Function Cost Structure

The cost structure for serverless functions is typically based on usage and consumption, aligning with the "pay-as-you-go" cloud computing model made so popular by the cloud. Instead of paying for fixed server capacity, you're charged based on the actual resources your functions consume during execution. Key factors that influence the cost include the number of times a function is triggered, the amount of memory allocated to each function, and the execution time.

When a function is triggered, the cloud provider allocates memory and processing power as needed. The total cost is calculated by combining the duration of execution (measured in milliseconds) and the memory allocated to the function. Functions that execute quickly with lower memory usage will generally incur lower costs. However, functions with higher memory and longer execution times will have higher associated costs - in most cases, serverless functions work out cheaper, but it's important to compare options, especially for complex processes. 

Keep in mind that some cloud providers offer free tiers that include a certain number of monthly executions and compute time for serverless functions. This can be beneficial for applications with low usage or for testing purposes. It's important to carefully consider the pricing model of the chosen cloud provider and analyse your application's usage patterns to estimate potential costs accurately. 

*Tip: Both AWS and Azure offer a free allowance for serverless functions, so we'd encourage you to sign up for an account and give them a try!* 



## Examples of Serverless Architecture Products 

Like most things in the cloud, “Serverless” products end up being an umbrella term – each cloud platform has their own specific solution. Some to be aware of are: 

- **AWS Lambda:** AWS Lambda lets you run code in response to events and triggers. It supports multiple programming languages and integrates well with other AWS services like Amazon S3, DynamoDB, and API Gateway.
- **Azure Functions:** Azure Functions offers event-driven, serverless compute. You can build functions using C#, F#, Node.js, Python, and more. It's tightly integrated with Azure services like Azure Blob Storage and Azure Cosmos DB.
- **Google Cloud Platform (GCP):** Google Cloud Functions lets you build serverless functions that automatically scale based on demand. GCP's Cloud Pub/Sub and Cloud Storage services can be integrated with functions to create event-driven applications in a serverless manner.
- **Oracle Cloud Infrastructure (OCI):** Oracle Functions provides serverless compute with support for multiple languages. It can be combined with OCI Object Storage and other services to create serverless solutions. Additionally, Oracle API Gateway allows you to expose serverless functions as APIs.

 

## A Serverless Example: Lambda Function for Hashing Files in S3

Below is an example of an AWS Lambda function written in Python that calculates the hash of files uploaded to an S3 bucket and saves the hash values to a file in the same bucket. This is the kind of short, repetitive function which an organisation may need to be done automatically when, in this case, a file is uploaded. Having a hash for the file is a great way to verify that it has not been changed, a common regulatory or governance requirement. It’s an ideal sort of use for a serverless function.

```python
import hashlib
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    
    # Get the bucket name and object key from the S3 event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Calculate the hash of the uploaded file
    hash_object = hashlib.sha256()
    
    # Retrieve the file from S3 in chunks to handle large files
    chunk_size = 4096
    response = s3.get_object(Bucket=bucket, Key=key)
    
    for chunk in iter(lambda: response['Body'].read(chunk_size), b''):
        hash_object.update(chunk)
    
    file_hash = hash_object.hexdigest()
    
    # Save the hash value to a file in the same bucket
    hash_file_key = key + '.hash'
    s3.put_object(Bucket=bucket, Key=hash_file_key, Body=file_hash)
    
    return {
        'statusCode': 200,
        'body': 'Hash calculated and saved successfully!'
    }
```



Here, when a new file is uploaded, the Lambda function is triggered by an S3 event. It uses the `hashlib` library to calculate the SHA-256 hash of the file's content.

The function begins by extracting the bucket name and object key from the event. It then iterates through the file's content in manageable chunks, updating the hash object with each chunk. This chunked approach allows the function to handle files of varying sizes efficiently.

Once the hash value is calculated, the function appends the ".hash" extension to the original file's key and uploads a new object containing the hash value to the same S3 bucket. This hash file serves as a record of the computed hash for future verification.

Finally, the function returns a simple response indicating the success of the hash calculation and storage process and quits. This short piece of code spins up, runs incredibly quickly, and shuts down without a developer ever needing to touch a server. 

# Final Words

Serverless architecture offers an efficient and cost-effective way to develop and deploy applications. By abstracting away server management, developers can focus on writing code that addresses specific business needs. However, it's important to evaluate the suitability of serverless for your application's requirements before going ahead with a deployment, especially when dealing with long-running or resource-intensive tasks. AWS Lambda and Azure Functions, along with related services, provide powerful tools for implementing serverless solutions.

 
