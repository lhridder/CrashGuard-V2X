from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import decoder
from asn1 import RecipientInfo, EncryptedData, Ieee1609Dot2Data
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    # --- 1. Read message ---
    with open("IEEE python Chris/signed_msg.txt", "rb") as f:
        encoded_msg = f.read()

    # --- 2. Decode top-level structure ---
    ieee_msg, _ = decoder.decode(encoded_msg, asn1Spec=Ieee1609Dot2Data())  # ASN.1 decoding

    demoLog("Ieee1609Dot2Data", ieee_msg)

    # --- 3. Decode EncryptedData section ---
    enc_data_bytes = bytes(ieee_msg['content'])
    enc_data, _ = decoder.decode(enc_data_bytes, asn1Spec=EncryptedData())  # ASN.1 decoding

    ciphertext = bytes(enc_data['ciphertext'])
    nonce = bytes(enc_data['nonce'])
    ccm_tag = bytes(enc_data['ccmTag'])

    demoLog("EncryptedData", enc_data)

    # --- 4. Combine ciphertext + ccm_tag ---
    ciphertext_and_tag = ciphertext + ccm_tag
    
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()
    aesccm = AESCCM(GROUP_KEY, tag_length=16)

    try:
        plaintext = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        demoLog("plaintext", plaintext)
    except Exception as e:
        demoLog("plaintext failed", e)

if __name__ == "__main__":
    os.system('cls')
    decode_message()