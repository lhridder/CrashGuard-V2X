# TODO  
- real pubkey.  
- certificate validity check.  
- geen fake certificate maar echte certificates maken.  

# CrashGuard V2X  
creating C-ITS V2X communication using WAVE standard (IEEE 1609.2). Includes:
- ASN.1 formatting
- Public Key Infrastructure
- Hashing
- Symmetrical encryption
- ECDSA (p-256) key generation  

...using **Python**  

# Python Demo - WAVE encoding
1. V2X payload  
2. Hashing  
3. Signing  
4. ToBeSignedData / tbs_data  
5. SignedData  
6. ASN.1 encoding  
7. (Optioneel) encryption  
8. EncryptedData  
9. Ieee1609Dot2Data  

![img1](encode_model.jpg)  

# Python Demo - WAVE decoding  
1. Ontvang bericht  
2. Decode Ieee1609Dot2Data  
3. Decode content type  
4. Decrypt encrypted data  

# Scalability & key management  
## Hierarchy:  
- **Root CA:** ultimate trusted authority.  
- **Enrollment CA:** issues long-term enrollment certificates to vehicles.  
- **Pseudonym CA:** issues short-term certificates (pseudonyms) for vehicles.  
- **Misbehaviour Authority:** receives reports of misbehaving vehicles and can revoke certificates.  

# Python / MicroPython Demo's  
- Main demo (python)  
- M5StickC plus 2 (microPython)  
- EV3 (microPython)  
- ESP32-C3 PICO (microPython)  