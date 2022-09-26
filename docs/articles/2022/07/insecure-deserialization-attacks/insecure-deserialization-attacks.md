:orphan:
(insecure-deserialization-attacks)=
# Insecure Deserialization Attacks
 
The insecure deserialization vulnerability is a major security flaw. The successful exploitation of this security flaw opens the door for the execution of high severity attacks including RCE (remote code execution) attacks, Denial of Service attacks, Authentication Bypass, Injection attacks and much more. The definitions as well as the basics of serialization and deserialization are covered in the opening paragraphs of this article. It then goes into the fundamentals of insecure deserialization vulnerability, how this attack is carried out, and the preventive approaches that can be employed to mitigate the risk posed by insecure deserialization attacks.

## What is meant by Serialization and Deserialization?

Serialization is the process of converting an object into a format that can be stored in a certain location  (such as a disk or database) for later use or that can be transferred over a network. The format of the resulting serialized data can be in the binary format or it can be in the form of structured text such as JSON, XML, YAML, etc. The objective of object serialization is to preserve the attributes of the objects and their respective values so that these objects can be easily restored and reconstructed at a later time. 

Deserialization is the reverse of the Serialization process. Deserialization refers to the process of utilizing the previously serialized data such as the bytes that were transferred over the network, data from the output (stdout) stream, output from the file stream, etc., and getting it processed back into the object in its original form with the same attributes. The underlying web server of the web application then takes this object and utilizes it in the same way that it uses any other object.

Serializing and deserializing objects is a relatively typical practice for web applications. This is why the serialization and deserialization processes are utilized by many of the processes found in back-end programming languages used in web applications. The serialization and deserialization process is supported by a number of programming languages, including Python, PHP, Ruby, and Java. When implemented correctly, serialization and deserialization processes are quite secure and not a reason for concern.

The problem arises when these processes are not implemented securely without proper user input validation and sanitization is when these processes can be exploited to carry out more sophisticated attacks. In order to carry out this attack, an attacker uses one of the various customizable deserialization techniques offered by programming languages to control the program flow on the target with the help of malicious code injected into the serialized data. These programming languages automatically assume that all input data supplied to the web application is secure by default. Therefore, the serialization/deserialization formats in these programming languages accept all serialized data without proper validation. It, therefore, allows for the inclusion of this malicious data into the object that gets deserialized on the web server.

## What is Insecure Deserialization Vulnerability?

Insecure Deserialization vulnerability occurs when a web application accepts the data from user input without proper validation. It then uses this data to deserialize objects in an unsecured manner. Using this security flaw an attacker can inject malicious code into the serialized data which then gets deserialized by the web server and therefore results in the execution of this malicious code. Insecure deserialization allows the attacker to change the attributes of the object than what was expected by the web application and get it successfully deserialized on the server side of the website. Due to this reason, insecure deserialization attacks are sometimes referred to as objection injection attacks. This kind of attack although kind of difficult to execute can be highly devastating for the web application. The successful execution of this attack in some cases also allows the attacker to get hold of sensitive or confidential data stored on the web server. 

Deserialization-based attacks result in the execution of malicious code even before the object gets deserialized on the web server. Therefore, even if the serialized object data modification results in an exception when it is deserialized, it still allows the attacker to carry out this attack successfully. Additionally, the input validation checks that the application developers set in place when developing the application are carried out after the deserialization takes place. These checks, therefore, do not effectively shield against deserialization-based attacks.

Insecure deserialization may also occur due to the dependency of the web application on a number of different third-party software libraries, which in turn may be dependent on further libraries. This creates a chain of complex dependencies for the web application and makes it very hard to manage and secure these libraries. It, therefore, allows the attacker to utilize different classes, create their instances, and manipulate them to pass malicious data into the web application.

## How does the Insecure Deserialization attack occur?

As mentioned earlier, different programming languages contain libraries that allow the developers to implement serialization and deserialization processes. For the sake of simplicity, we will be reviewing and utilizing the libraries available in Python for this purpose. In order to understand how the serialization attack works in python, let us first review and understand the module and its function used for serialization and deserialization:

**Python pickle module:**

The [pickle](https://docs.python.org/3/library/pickle.html) module in Python contains a set of different functions that allows the developers of web applications to serialize and deserialize objects that are based on the Python Structure. The pickle module allows the Python object to be converted into a stream of bytes. It also allows the conversion of this byte stream back into the Python object. 

**pickle.dumps function:**

The pickle.dumps function is a part of the pickle module and is used to convert as well as return the object as a stream of bytes.

**pickle.loads function:**

The pickle.loads function is a part of the pickle module and is used to return the reconstituted object hierarchy of the pickled representation data of an object. 

**Deserialization-based attack demonstration using python:**

This section will demonstrate how the pickle library in Python can be utilized to carry out the deserialization-based attack. In order to understand this attack, let us consider the following block of code:

```
import os
import _pickle

# This class contains the exploit code for the attack
class Attack(object):
    def __reduce__(self):
        return (os.system, ('dir',))

# This function serializes the instantiated object
def serialization_function():
    serialized_data = _pickle.dumps(Attack())
    return serialized_data

# This function deserializes the bytes that are passed as an argument
def deserialization_function(serialized_data):
    return _pickle.loads(serialized_data)

if __name__ == '__main__':
    object_bytes = serialization_function()
    deserialization_function(object_bytes)
```
The `__reduce()__ ` method in python takes no arguments and returns a string or a tuple in the form `return (function, arguments) `. The Python programming language allows objects to declare how they should be pickled utilizing the reduce method. This method takes no argument and returns either a string or a tuple. When returning a tuple, the tuple will dictate how the object will be reconstructed during deserialization. The os module in Python provides functions for interacting with the underlying operating system. The os.system() function takes a command in the string format as an argument and executes that command in a subshell.

The Attack class contains a single method that uses the reduce method to convert a system command i.e. dir (that lists files and folders in the current directory) and returns it as a tuple. 

The serialization_fuction() instantiates the attack class and serializes the resulting object using the pickle.dumps function. The serialized data will be in the following format:

`b'\x80\x03cnt\nsystem\nq\x00X\x03\x00\x00\x00dirq\x01\x85q\x02Rq\x03.'`

The deserialization_funtion() takes the serialized form of the object in bytes and converts it into the original form using the pickle.loads function. It ultimately results in the execution of the system command.

The code given in the above example is a very simple case of an attacker utilizing insecure deserialization to execute the system commands. The attacker can also execute sophisticated attacks such as leveraging reverse shells to gain a greater hold on the remote target.

## Impact of the Insecure Deserialization attack

Insecure Deserialization attacks can have a severe impact on the web application. The attacker can utilize the deserialization-based vulnerability to carry out a series of devastating attacks. Some of the attacks that can be carried out exploiting this vulnerability are given as follows:

**DOS (Denial of Service) Attacks:** An attacker can exploit this vulnerability to crash the critical services running on the web server. It can also be used to completely compromise or bring down the underlying web server of the web application.

**Authentication Bypass Attacks:** An attacker can utilize this vulnerability to bypass the authentication mechanisms of a web application. It can allow the attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently. 

**Remote Code Execution:** This vulnerability can be used by an attacker to run malicious code on a remote machine. For instance, if the web application doesn't have input validation and sanitization mechanisms, an attacker can inject malware into the serialized data, which will subsequently be deserialized on the web server.

**SQL injection Attack:** The underlying server's programming language interpreter can be manipulated by an attacker using this vulnerability to inject malicious data that can allow them to access data without authorization or execute unauthorized actions.

**Privilege Escalation:** This vulnerability allows an attacker to compromise the accounts belonging to privileged users, which he can then leverage to elevate his access rights on the target. In order to get administrative rights on the target, an attacker alters the serialized object and tampers with the data. For example, the attacker can use the session cookie belonging to a normal user and utilize this vulnerability to takeover an admin account on the web application.

**Information disclosure and modification of the data:** An attacker can exploit this vulnerability to gain access to the sensitive or confidential information stored on the web server such as web configuration files, user passwords, confidential customer information, and much more. Additionally, the attacker can exploit this vulnerability to modify or delete important files or information that is stored on the web server.

## Preventive techniques to mitigate Insecure deserialization threats

This section goes over some of the recommended techniques to prevent the exploitation of insecure deserialization vulnerabilities in a web application:

**Input validation:**
Rejecting user input outright is one of the best ways to protect against attacks that can be performed exploited by insecure deserialization. In many instances, the disadvantages outweigh the advantages due to the potentially high severity of exploits it could enable and the difficulty in preventing them. This may not be possible, however, when creating some web applications. For this purpose, the application developers should employ a variety of security controls to validate user input especially if the application accepts input from untrusted sources. Input from the user can be checked in a variety of methods, including the following:

* Implement a whitelist (a list of allowed items) to restrict and limit deserialization to a small list of allowed classes. However, in some cases, an attacker can easily circumvent these whitelists with the help of automated tools. Therefore, the application developers should not solely rely on whitelist-based controls to prevent deserialization-based attacks. The best strategy is to apply several controls in a layered manner to prevent deserialization-based attacks.

*  To verify the integrity of the data and to prevent data manipulation or the creation of hostile objects, implement digital signatures and other integrity verification security mechanisms. To prevent this kind of attack, certain tests must be performed before starting the deserialization process takes place.

**Implement language-agnostic serialization formats:**

Avoid using the deserialization formats used by programming languages to lower the risk posed by deserialization attacks. It is recommended to utilise language-independent, data-only formats like XML, JSON, or YAML instead for serialization and deserialization. This will prevent the attackers from exploiting the deserialization logic to carry out their attacks successfully.

**Employ SCA (Software Composition Analysis) tools:**

In order to reduce the risk of insecure deserialization attacks that are caused due to the dependency of the web application on external software libraries, employ SCA(software composition analysis) tools. The usage of these tools will ensure that all the third-party code that the application depends on, is secure and therefore minimizes the risk due to the introduction of third-party software libraries.

**Run the deserialization code in low-privileged environments:**

In order to reduce the impact and the damage caused due to the exploitation of insecure deserialization vulnerability, the developers can design the web application in such a way that runs the deserialization code in a low-privileged environment if it is possible. This will prevent the sensitive or critical assets from being compromised that the privileged accounts have access to or prevent the attackers from performing any actions that only privileged users are authorized to perform.

**Log Deserialization Failures:**

Security controls that log deserialization failures and exceptions, such as when the incoming type is not the anticipated type or the deserialization throws exceptions, must be installed in the web application. This will aid the application's ability to thwart any efforts to insecurely deserialize data.

**Monitor Deserialization Activities:**

In order to avoid deserialization-based attacks, it is important to configure network and web application firewalls to restrict or block any suspicious network connections. The application must also contain sufficient controls to monitor incoming and outgoing network connectivity from containers or servers that deserialize data. Additionally, the application must monitor repeated deserialization attempts by a user and flag or block those users that are constantly attempting to deserialize data.

**Carry Out Thorough Web application security testing:**

The web application must be thoroughly tested for any vulnerabilities that can lead to deserialization-based attacks. This includes using both SAST (Static Application Security Testing) tools to test the application's code for any vulnerabilities as well as using DAST (Dynamic Application Security Testing) tools to test the application in the running state for insecure deserialization.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::