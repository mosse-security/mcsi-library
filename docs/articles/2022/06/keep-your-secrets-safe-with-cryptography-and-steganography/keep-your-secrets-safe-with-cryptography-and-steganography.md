:orphan:
(keep-your-secrets-safe-with-cryptography-and-steganography)=
# Keep Your Secrets Safe With Cryptography and Steganography
  

There are different kind of forms of covert communication that involve the use of any medium to hide something. Cryptography and steganography are often used together to conceal crucial data. Both have nearly the same aim at their heart, which is to safeguard a message or information from third parties. They do, however, safeguard the information via a completely different approach.

## Cryptography and Steganography Overview

Cryptography converts data into ciphertext, which is incomprehensible without a decryption key. 
If someone intercepted this encrypted message, they would immediately notice that encryption had been used. Steganography, on the other hand, does not alter the format of the data; rather, it hides the 
message's presence.

The steganography technique is used by cybercriminals to disguise stolen data or malicious code in photographs, audio files, and other media. Cybercriminals have figured out ways to disguise data such as sensitive information or malicious software in photographs, audio files, computer server messages, and other formats. Occasionally, the disguised data is equipped with encryption using certain cryptographic techniques.

Cryptography is already discussed thoroughly in the ["Introduction to Cryptography and Block Cipher Modes”](introduction-to-cryptography-and-block-cipher-modes) article post on MCSI Library. Therefore, here we will discuss more about steganography.

Steganography is a method of concealing secret data within a non-secret file or message to
prevent detection; the secret data is then extracted at its destination. Steganography can be used in 
conjunction with encryption to further conceal or safeguard data.
Steganography's goal is to conceal and deceive. It is a type of covert communication in which 
messages are hidden using any media. It isn't cryptography because it doesn't encrypt data or require the usage of a key. Instead, it's a type of data concealment that can be done in a variety of ways.

## Steganography types and methods
Steganography is classified into five forms based on the nature of the cover item (the physical 
object in which hidden data is embedded): 
- Text steganography
- Image steganography
- Video steganography
- Audio steganography
- Network steganography

### Text steganography

Text steganography is the practice of concealing information within text files. It entails changing 
the format of existing text, changing words within a text, generating random character sequences, or 
generating readable texts using context-free grammar.

### Image steganography

Image steganography is the practice of concealing data by using the cover object as the image. 
Images are a popular cover source in digital steganography because the digital representation of an image contains a large number of bits. There are numerous methods for concealing information within an image.

### Audio steganography

Audio steganography embeds the secret message in an audio signal, which changes the binary 
sequence of the corresponding audio file in audio steganography. Hiding secret messages in digital sound is a much more difficult process than, say, image steganography.
  
### Video Steganography

Video Steganography allows us to conceal data in digital video formats. The benefit of this type is 
that a large amount of data can be hidden inside, as well as the fact that it is a moving stream of images and sounds. Consider this a hybrid of Image and Audio Steganography.

### Network Steganography

Network Steganography (Protocol Steganography) is the technique of embedding information 
within network control protocols used in data transmission such as TCP, UDP, and ICMP, among others. Steganography can be used in some covert channels found in the OSI model. For example, you can hide 
information in the header of a TCP/IP packet in some optional fields.

## Steganography misuse

Steganography was created to allow for secure communication. However, criminals and terrorist 
organizations are taking advantage of this. The Stegano/Astrum exploit kit, for example, embeds malicious code inside the RGBA transparency value of each pixel of PNG banner ads. The malicious code was extracted when the ads were loaded, and the user was redirected to the exploit kit lgrammarg page. Furthermore, the discharge team created advertisements that contained code that launched brute force 
attacks against users' home WiFi routers.


Understanding how to conceal data steganography and prevent that data from being misused can 
thus be extremely beneficial for both attack and defense. Protecting against it is becoming more difficult as threat actors become more innovative and creative. Steganographic attacks are difficult to detect because they arrive as zero-day threats, making detection difficult for antivirus and next-generation antivirus tools that rely on threat intelligence and signature databases.


Assume that the size of an image file is unusually large. In that case, it could indicate that the 
image contains steganography. Furthermore, because encryption and obfuscation are easier to detect at endpoints, corporations should try to detect these parts of their systems. Companies should educate employees about image files that can contain malicious code, implement internet filtering for secure browsing, and keep up with the latest security patches. A reliable host-based anti-malware solution will identify and detects hidden malicious code and their loaders provided with these procedures. 
Furthermore, network tracking may aid in the detection of new steganographically delivered malicious code or outbound stolen data.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::