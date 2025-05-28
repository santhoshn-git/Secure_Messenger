# Secure_Messenger
# A Cryptography Project

# Chapter 1 : Introduction
# Problem Statement
In the evolving landscape of cybersecurity, ensuring the confidentiality and integrity of digital communications is paramount. Traditional encryption algorithms like DES (Data Encryption Standard) have shown vulnerabilities over time, especially with the advent of quantum computing. This project addresses the need for robust encryption mechanisms by integrating both classical and post-quantum cryptographic algorithms. Specifically, it employs:
●	Kyber1024: A post-quantum Key Encapsulation Mechanism (KEM) designed to be secure against quantum attacks.

●	AES-256-CBC: A widely adopted symmetric encryption algorithm known for its strength and efficiency.

●	DES-CBC: An older symmetric encryption standard included for comparative analysis.

The primary objective is to establish a secure communication channel that can withstand both classical and quantum computational threats, ensuring the safe transmission of text and voice messages.

# Motivation
The motivation behind this project stems from the increasing threats posed by quantum computing to classical encryption algorithms. As quantum computers become more capable, they threaten to break widely used encryption methods, compromising data security. By integrating Kyber1024, a post-quantum algorithm, with established symmetric encryption techniques like AES and DES, this project aims to explore a hybrid approach to secure communications, ensuring resilience against both current and future cryptographic attacks.
 
Aspects of the Chosen Algorithms
Kyber1024
●	Type: Post-quantum Key Encapsulation Mechanism (KEM).
●	Security Basis: Relies on the hardness of the Module Learning With Errors (MLWE) problem, making it resistant to quantum attacks.
●	Features:
○	IND-CCA2 secure.
○	Efficient key generation and encapsulation/decapsulation processes.
○	Selected by NIST for standardization in post-quantum cryptography.

AES-256-CBC
●	Type: Symmetric block cipher.
●	Key Size: 256 bits.
●	Block Size: 128 bits.
●	Mode of Operation: Cipher Block Chaining (CBC).
●	Features:
○	High security and performance.
○	Widely adopted in various security protocols and standards.
 
DES-CBC
●	Type: Symmetric block cipher.
●	Key Size: 56 bits (effective).
●	Block Size: 64 bits.
●	Mode of Operation: Cipher Block Chaining (CBC).
●	Features:
○	Historically significant but now considered insecure due to its short key length.
○	Included in this project for comparative analysis purposes.
 
# Chapter 2 : Methodology

Implementation Steps
1.	User Input:
○	Prompt the sender to input their name.
○	Prompt the receiver to input their name.
○	Prompt the sender to enter the message to be encrypted.

2.	Key Generation using Kyber1024:
○	Generate a public and private key pair.
○	Encapsulate a shared secret using the public key.
○	Decapsulate the shared secret using the private key.
○	Verify that both parties have derived the same shared secret.

3.	Text Message Encryption and Decryption:
○	AES-256-CBC:
■	Generate a random Initialization Vector (IV).
■	Encrypt the plaintext message using the shared secret and IV.
■	Decrypt the ciphertext using the shared secret and IV.
○	DES-CBC:
■	Derive a DES key from the shared secret.
■	Generate a random IV.
 
■	Encrypt the plaintext message using the DES key and IV.
■	Decrypt the ciphertext using the DES key and IV.
4.	Voice Message Handling:
○	Prompt the user to input the path to the voice message file.
○	Read the voice message file into a buffer.
○	AES-256-CBC:
■	Generate a random IV.
■	Encrypt the voice data using the shared secret and IV.
■	Decrypt the ciphertext using the shared secret and IV.
■	Save the encrypted and decrypted files.
○	DES-CBC:
■	Derive a DES key from the shared secret.
■	Generate a random IV.
■	Encrypt the voice data using the DES key and IV.
■	Decrypt the ciphertext using the DES key and IV.
■	Save the encrypted and decrypted files.

5.	Performance Analysis:
○	Measure the time taken for encryption and decryption processes.
○	Calculate throughput and other relevant metrics.
○	Display the analysis results.
 
6.	Output Summary:
○	Display sender and receiver information.
○	Display original message.
○	Display ciphertexts and IVs in hexadecimal format.
○	Present performance analysis for each encryption method.
7.	Optional Decryption Display:
○	Prompt the user to choose whether to display decrypted messages.
○	If yes, display decrypted text and indicate saved decrypted voice files.
8.	Cleanup:
○	Free all dynamically allocated memory.
○	Release cryptographic resources
 
# Chapter 3 : Results and Discussion

Figure 1: Initial User Input Prompts

![Picture1](https://github.com/user-attachments/assets/ed12d8d6-231f-4707-8db5-28c865225d13)



This screenshot shows the initial prompts asking for the sender's name, the receiver's name, and the message to be encrypted. The user has entered "John", "Alice", and "This is a secret message." respectively.


Figure 2: Kyber Key Exchange Success Message
![image](https://github.com/user-attachments/assets/4dc9176a-d772-4336-9a7d-c95347de199f)



After the Kyber key encapsulation mechanism (KEM) completes successfully, this message confirms that a shared secret has been established between the sender and receiver.


Figure 3: Voice Message File Input
![image](https://github.com/user-attachments/assets/25edf2c4-54dd-4f35-b1fc-c9799f4fb3ba)



The program prompts for the path to a voice message file. The user has entered "my_voice.wav", and the program confirms that the file has been loaded along with its size in bytes (represented by XXXXXX).
 
Figure 4: Output Summary - Text Message Encryption Details

![image](https://github.com/user-attachments/assets/ce46d346-8e0c-4787-84dd-afa6d73f2bd7)


This section of the output summarizes the original message, sender, receiver, and the hexadecimal representation of the ciphertext and Initialization Vector (IV) generated by both AES and DES encryption for the text message.

Figure 5: Analysis of Encryption and Decryption Times (Text)
![image](https://github.com/user-attachments/assets/528ebd45-af58-4251-a46c-cbfb82f68ca1)

Similar to the text analysis, this section provides the encryption and decryption analysis for the voice message using AES-256-CBC and DES-CBC, including key length, ciphertext size, time taken, and throughput. 
# Final view of the Project:

# SecureMesssenger:

 ![image](https://github.com/user-attachments/assets/3ae80b7b-90c3-4708-889b-62f10204597f)


# Encrypted & Decrypted voice file:
 
![image](https://github.com/user-attachments/assets/47d758f9-4b65-45e5-ab21-b22e494eea24)


# Chapter 4 : Conclusion and Future Work

This project successfully demonstrates a hybrid cryptographic approach combining post-quantum and classical encryption algorithms to secure both text and voice communications. The integration of Kyber1024 ensures resilience against quantum
attacks by securely establishing shared secrets, while AES-256-CBC provides robust symmetric encryption for data confidentiality. Although DES-CBC is included for
comparative purposes, its vulnerabilities highlight the importance of transitioning to more secure algorithms.
Performance analysis indicates that AES-256-CBC offers efficient encryption and decryption processes suitable for practical applications. The project's modular design allows for flexibility in handling different data types, showcasing the versatility of the implemented cryptographic methods.

Future Work

●	Integration of Authentication Mechanisms: Implementing digital signatures or Message Authentication Codes (MACs) to ensure data integrity and authenticity.

●	Exploration of Other Post-Quantum Algorithms: Evaluating other NIST-recommended post-quantum algorithms for key exchange and encryption.

●	Development of a Graphical User Interface (GUI): Creating a user-friendly interface to enhance usability and accessibility.

●	Optimization for Real-Time Applications: Refining the system for real-time communication scenarios, such as live voice or video calls.

