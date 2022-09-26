:orphan:
(input-validation-for-greater-security)=

# Input Validation for Greater Security

When developing online apps that accept any sort of user input, you must ensure that input validation is performed. To begin with, you should never allow a user to include script the input field. However, this does not totally fix the problem; an attacker still has numerous smart alternatives at his or her disposal. Input validation is a must when developing a secure application. One of the most common causes of application vulnerabilities is a lack of or inappropriate usage of input validation. All information obtained from a client should be handled as unreliable and checked before further processing. Many developers utilize server-side programming to meet this need. Otherwise, the user may send harmful input to a program that can exploit a flaw.

## What is input validation

When you engage with software, you frequently send data to the program in the form of _input_. Developers frequently anticipate that these numbers will fall within specific boundaries. For example, if the programmer requests you to enter your age, the application expects an integer value. However, if you enter a value outside a range or another type (like text, which is also referred to as a string), the software may allow you to manipulate the underlying system.

- Input validation ensures that the values you enter meet the programmer's expectations. If it doesn't, the application will not treat the number as age and will instead notify you of the input expectations.

- You should also define your variables and never use strings directly in a script or text. While dealing with scripts, always scan to find and eliminate any "escape" characters in your preference of script language.

## Preventing input validation-connected attacks

At a minimum, data input validation should examine data for the following criteria:

### Range

A limit check assures that the data falls inside a specific range. A limit check is a sort of input validation in which the code checks to ensure that a number falls within a specified range.
The ideal way is to decide what kind of input you would accept and then evaluate the input to ensure that it meets that pattern. If you have a text box where users may enter their age, you should specify a range (such as 1–100). Any other information should be classified by your application as invalid.

### Length, format, type

The length ensures that the length of incoming data does not go beyond a predefined number of characters. Format verifies that data is received in the specified format. And type ensures that the data received is in the format requested. If your program is expecting an integer value, your code should not process a string input.

### Character Check

Input validation may also search for unusual characters, such as quotation marks within a text field, that might signal an attack. In some circumstances, the input validation method can alter the input to replace dangerous character sequences with safe values. This is referred to as "escaping input." If text must be used in a script, scan it to find and eliminate any "escape" characters that the script language may understand.

### Server-side input validation

Attackers can evade client-side input validation. They can intercept data even after the validation process is completed on the client-side, inject malicious code and send it to the web application.

Validation of input should always take place on the server-side of the communication. Any code transmitted to the user's browser is susceptible to modification by the user and hence readily avoided.

## Conclusion

Implementing appropriate input validation is the greatest defense against input validation-connected assaults. You can develop your program to take input utilizing a variety of elements other than text fields( such as cookies, and HTTP headers).

As a result, you should perform adequate input validation whenever you receive data in the application before any process.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::
