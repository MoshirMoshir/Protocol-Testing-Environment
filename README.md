# **Protocol Testing Environment (PTE)**

## **Overview**
The **Protocol Testing Environment (PTE)** is a Python-based testing environment created to evaluate and benchmark a variety of encryption and authentication protocols commonly used in text-messaging systems. By simulating these protocols in a controlled environment, the project aims to analyze the performance, strengths, and weaknesses of each method.

---

## **Purpose**
The purpose of this repository is to assit my reasearch project that investigates the security flaws inherent in **Short Message Service (SMS)** and explores potential methods for improving its security. The ubiquity of SMS, particularly among Android users, makes it an attractive target for malicious actors. **Key issues include:**
- The absence of **end-to-end encryption**, leaving SMS vulnerable to spoofing and interception.
- Metadata exposure, such as sender and recipient information, which can leak sensitive details.

Given the increasing sophistication of cyber threats, this project highlights the **urgent need for robust security measures** tailored specifically to SMS, as opposed to proprietary solutions like Apple’s iMessage. By addressing current SMS vulnerabilities and proposing new mechanisms, this project aims to strengthen the security framework of SMS for Android users and anyone who relies on this form of communication.

---

## **Approach**
Due to my limitations in accessing proper APIs to directly simulate SMS messaging (subscriptions, ugh), the PTE simulates secure messaging within a program by:
1. **Implementing and testing encryption and authentication protocols** over text data.
2. **Benchmarking each protocol** to analyze their performance in terms of encryption speed, decryption speed, and overall efficiency.
3. Proposing enhancements for **fragmentation**, **metadata obfuscation**, and other SMS-specific challenges.

---

## **Implemented Protocols**

### **Encryption**
- **AES-CBC (Cipher Block Chaining):**
  - Symmetric encryption method for confidentiality.
  - Commonly used in secure file storage systems.

- **AES-GCM (Galois/Counter Mode):**
  - Symmetric encryption with built-in authentication.
  - Used in modern communication systems like RCS and HTTPS.

- **ChaCha20-Poly1305:**
  - A high-performance symmetric encryption algorithm.
  - Used in TLS 1.3 and secure protocols like WireGuard.

### **Key Exchange**
- **RSA:**
  - Asymmetric encryption for secure key exchange or message encryption.
  - A widely adopted cryptographic method.

- **ECDH (Elliptic Curve Diffie-Hellman):**
  - Efficient key exchange using elliptic curve cryptography.
  - Common in modern secure messaging systems.

- **Ephemeral ECDH:**
  - A forward-secrecy mechanism that generates unique session keys for each exchange.
  - Used in Signal Protocol and TLS 1.3.

### **Authentication**
- **HMAC (Hash-Based Message Authentication Code):**
  - Ensures message integrity and authenticity.
  - Lightweight and efficient for secure messaging.

- **ECDSA (Elliptic Curve Digital Signature Algorithm):**
  - Verifies the authenticity of messages using digital signatures.
  - Lightweight and secure, widely used in secure protocols.

### **SMS-Specific Challenges**
- **Message Fragmentation:**
  - Splits encrypted messages exceeding SMS length limits (160 characters) into smaller fragments for transport.
  - Reassembles fragments at the recipient’s end to restore the original message.

- **Metadata Obfuscation:**
  - Encrypts metadata (e.g., sender, recipient, timestamp) to prevent leakage of sensitive information.
  - Simulates the "sealed sender" feature used in Signal Protocol.

---

## **Features**
- **Benchmarking:** 
  - Analyze and compare the encryption/decryption speed and efficiency of different protocols.
- **Protocol Simulation:**
  - Simulates secure messaging workflows to validate proposed security solutions.
- **SMS Challenges Addressed:**
  - Handles message fragmentation and metadata protection for real-world SMS scenarios.

---

## **How to Use**
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/protocol-testing-environment.git
   cd protocol-testing-environment
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the main script:
   ```bash
   python main.py
   ```

4. Review the outputs to compare the performance and implementation details of each protocol.

---

## **Conclusion**

The Protocol Testing Environment (PTE) demonstrates a robust framework for benchmarking encryption and authentication protocols, providing insights into their performance and suitability for secure SMS messaging systems. The results highlight the following key takeaways:

### **Performance Analysis**
1. **Symmetric Encryption:**
   - **AES-CBC** and **AES-GCM** both showcase exceptional encryption and decryption speeds. However, AES-GCM outperforms AES-CBC due to its built-in authentication, making it ideal for modern secure messaging protocols.
   - **ChaCha20-Poly1305** delivers comparable speeds to AES-GCM, with slightly better performance, making it a strong alternative for environments without hardware acceleration for AES.

2. **Asymmetric Encryption:**
   - **RSA** demonstrates significantly slower decryption times compared to encryption, highlighting its computational intensity, particularly for larger keys. This limits its use to secure key exchange rather than direct encryption.
   - **ECDH** and **Ephemeral ECDH** offer lightweight, efficient key exchange mechanisms. Ephemeral ECDH introduces forward secrecy without compromising performance, a critical feature for modern secure messaging.

3. **Authentication:**
   - **HMAC** is the fastest protocol, delivering negligible overhead, making it ideal for message integrity checks.
   - **ECDSA** is slower than HMAC but provides a secure mechanism for message authentication, with reasonable performance for signing and verifying messages.

### **SMS-Specific Challenges**
1. **Message Fragmentation:**
   - Successfully handled encrypted messages exceeding the SMS 160-character limit by splitting and reassembling fragments. This ensures compatibility with SMS infrastructure while maintaining the integrity of encrypted data.
   
2. **Metadata Obfuscation:**
   - Simulated encryption of SMS metadata (e.g., sender, recipient, and timestamp) was achieved with AES-GCM, demonstrating its feasibility for protecting sensitive metadata. This approach mirrors real-world solutions like the "sealed sender" feature in Signal.

### **Key Findings**
- **Best Overall Protocol for SMS:** AES-GCM strikes a balance between performance, security, and ease of implementation, making it highly suitable for secure SMS systems.
- **Asymmetric Key Exchange:** ECDH, particularly with ephemeral keys, is the most efficient and secure solution for establishing shared secrets.
- **Authentication Efficiency:** HMAC is ideal for lightweight integrity checks, while ECDSA provides robust digital signatures for message authentication when needed.

### **Recommendations**
1. **Protocol Selection:**
   - Implement AES-GCM or ChaCha20-Poly1305 for message encryption, depending on hardware capabilities.
   - Use Ephemeral ECDH for secure key exchange and forward secrecy.

2. **SMS Infrastructure Enhancements:**
   - Support fragmentation and reassembly mechanisms natively in SMS infrastructure to handle encrypted payloads efficiently.
   - Incorporate metadata obfuscation techniques to prevent sensitive information leakage.

3. **Future Considerations:**
   - Explore lightweight cryptographic algorithms for constrained environments (e.g., IoT devices).
   - Investigate seamless integration of secure protocols into real-world SMS systems via APIs.

By addressing these challenges and leveraging the findings, SMS systems can evolve to provide a secure and reliable communication framework, ensuring user privacy and protection against modern threats. This work lays a strong foundation for future advancements in SMS security.
