# Supported Encoding/Decoding - Encryption/Decryption Options:

* **Binary** to **ASCII**
* **ASCII** to **Binary**
* **Hexadecimal** to **ASCII**
* **ASCII** to **Hexadecimal**
* **Base64** to **ASCII**
* **ASCII** to **Base64**
* **Base58** to **ASCII**
* **ASCII** to **Base58**
* **ROT13** to **ASCII**
* **ASCII** to **ROT13**
* **Offset** to **ASCII**
* **ASCII** to **Offset**
* **RSA** to **ASCII**
* **ASCII** to **RSA**
* **AES** to **ASCII**
* **ASCII** to **AES**
* **3DES** to **ASCII**
* **ASCII** to **3DES**
<br>

1. **ASCII (American Standard Code for Information Interchange):**
   - **Definition:** ASCII is a character encoding standard that represents text in computers.
   - **Representation:** In ASCII, each character is represented by a unique 7-bit or 8-bit binary number. This includes letters, digits, punctuation, and control characters. For example, the ASCII code for the letter 'A' is 65.

2. **Binary:**
   - **Definition:** Binary is a base-2 numeral system using only two digits, 0 and 1.
   - **Representation:** In computers, data is often stored and processed in binary. Each digit is a binary digit or "bit," and a sequence of 8 bits is called a "byte." Binary is fundamental to computing and digital electronics.

3. **Hexadecimal:**
   - **Definition:** Hexadecimal is a base-16 numeral system.
   - **Representation:** Hexadecimal uses 16 digits: 0-9 and A-F, where A stands for 10, B for 11, and so on. It is often used in computing for more concise representation of binary data. For example, the binary number `10110110` is represented as `B6` in hexadecimal.

4. **Base64:**
   - **Definition:** Base64 is a binary-to-text encoding scheme.
   - **Encoding Process:** It converts binary data into a text format using a set of 64 characters. Each group of 6 bits in the binary data is represented by a character in the Base64 character set.
   - **Usage:** Commonly used for encoding binary data in formats that expect text, such as email attachments or data transmitted over the internet.

5. **Base58:**
   - **Definition:** Base58 is a binary-to-text encoding scheme similar to Base64 but designed to avoid visually ambiguous characters.
   - **Character Set:** It uses a character set of 58 characters, excluding characters that might be confused in certain fonts, such as 0 (zero), O (uppercase letter), I (uppercase letter), and l (lowercase letter).
   - **Usage:** Commonly used in Bitcoin and other cryptocurrency-related applications for encoding addresses and private keys.

6. **ROT13 (Rotate by 13 places):**
   - **Definition:** ROT13 is a simple letter substitution cipher that rotates characters by 13 positions in the alphabet.
   - **Usage:** Often used for obfuscation or as a basic form of encryption. It's a symmetric cipher, meaning applying ROT13 twice results in the original text.

7. **Offset Encoding:**
   - **Definition:** Offset encoding involves shifting each letter in the alphabet by a certain offset value.
   - **Encoding Process:** Each letter is replaced by the letter at a fixed number of positions down or up the alphabet. For example, with an offset of 3, 'A' becomes 'D,' 'B' becomes 'E,' and so on.
   - **Usage:** Similar to ROT13, offset encoding can be used for basic encryption or obfuscation.

8. **RSA (Rivest–Shamir–Adleman):**
   - **Definition:** RSA is a widely used public-key cryptosystem for secure data transmission.
   - **Key Pairs:** It involves two keys, a public key for encryption and a private key for decryption. The keys are mathematically related but computationally infeasible to derive one from the other.
   - **Usage:** RSA is commonly used for secure communication, digital signatures, and encryption of data.

9. **AES (Advanced Encryption Standard):**
   - **Definition:** AES is a symmetric encryption algorithm widely adopted as a standard by the U.S. government.
   - **Key Lengths:** AES supports key lengths of 128, 192, or 256 bits.
   - **Usage:** AES is widely used for securing sensitive data in various applications, including file encryption, secure communications, and data storage.

1. **3DES (Triple DES or TDEA):**
   - **Definition:** 3DES is a symmetric encryption algorithm that applies the Data Encryption Standard (DES) algorithm three times to each data block.
   - **Key Length:** It can use either a 112-bit or 168-bit key. Despite its name, 3DES provides a key length equivalent to its keying option (e.g., 168 bits for a 168-bit key).
   - **Usage:** 3DES was designed to provide a transition from the original DES, which had become vulnerable due to its small key size. While 3DES is more secure, modern applications often prefer AES for better performance and security.

***These encoding and encryption techniques serve various purposes in computing, from fundamental data representation to securing communication and ensuring data privacy. Their usage depends on specific requirements and the nature of the data being handled.***

*In summary:*

- **ASCII:** A character encoding standard using 7 or 8 bits to represent characters.

- **Binary:** A base-2 numeral system using 0 and 1 to represent numbers and data in computing.

- **Hexadecimal:** A base-16 numeral system using digits 0-9 and A-F.

- **Base64:** A binary-to-text encoding scheme using a set of 64 characters.

- **Base58:** Used for encoding binary data into a text format with a reduced character set, avoiding characters that could be visually confused.

- **ROT13:** A simple letter substitution cipher rotating characters by 13 positions.

- **Offset:** Used for encoding shifts each letter by a fixed number of positions in the alphabet.

- **RSA:** A public-key cryptosystem that uses a pair of keys (public and private) for secure data transmission and digital signatures.

- **AES:** A symmetric encryption algorithm widely used for securing data through encryption and decryption using a shared secret key.

- **3DES** A symmetric encryption algorithm that applies the DES algorithm three times for increased security compared to the original DES.

***Each of these plays a crucial role in different areas of security and data encoding, and their usage depends on specific requirements and use cases.***

![image](https://github.com/isPique/Data-Converter/assets/139041426/3fee119c-6cb7-483e-b6a5-d390ebde302f)
