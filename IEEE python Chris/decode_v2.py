from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import encoder, decoder
from asn1 import EnvelopedData, Ieee1609Dot2Data, SignedData
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import time
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    # --- Read message ---
    with open("IEEE python Chris/signed_msg.txt", "rb") as f:
        encoded_msg = f.read()

    # --- Decode top-level structure ---
    ieee_msg, _ = decoder.decode(encoded_msg, asn1Spec=Ieee1609Dot2Data())  # ASN.1 decoding

    demoLog("Ieee1609Dot2Data", ieee_msg)

    content_type = int(ieee_msg['contentType'])
    content_bytes = bytes(ieee_msg['content'])

    # --- Verwerk contentType ---
    if content_type == 0:   # unsecureData
        payload = content_bytes
        demoLog("Unsecure payload", payload)

    elif content_type == 1: # signedData
        signed_data, _ = decoder.decode(content_bytes, asn1Spec=SignedData())
        demoLog("SignedData", signed_data)
        
        # --- TODO generation time verification ---
        tbs = signed_data['tbsData']
        header = tbs['headerInfo']
        verify_time(header)

        # --- TODO signature verification ---
        with open("keys/sender_public_key.pem", "rb") as f:
            SENDER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

        verify_signature(signed_data, SENDER_PUBLIC_KEY)

    elif content_type == 2: # encryptedData
        enc_data, _ = decoder.decode(content_bytes)
        ciphertext = bytes(enc_data['ciphertext'])
        nonce = bytes(enc_data['nonce'])
        ccm_tag = bytes(enc_data['ccmTag'])
        ciphertext_and_tag = ciphertext + ccm_tag

        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        aesccm = AESCCM(GROUP_KEY, tag_length=16)

        try:
            payload = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
            demoLog("Decrypted payload", payload)
        except Exception as e:
            demoLog("Decryption failed", e)
    
    elif content_type == 3: # envelopedData
        enveloped, _ = decoder.decode(content_bytes, asn1Spec=EnvelopedData())
        ciphertext = bytes(enveloped['encryptedContent'])
        nonce = bytes(enveloped['nonce'])
        ccm_tag = bytes(enveloped['ccmTag'])
        ciphertext_and_tag = ciphertext + ccm_tag

        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        aesccm = AESCCM(GROUP_KEY, tag_length=16)

        try:
            signed_bytes = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
            demoLog("Decrypted SignedData bytes", signed_bytes)
        except Exception as e:
            demoLog("AES-CCM decryption failed", e)
            return
        
        signed_data, _ = decoder.decode(signed_bytes, asn1Spec=SignedData())
        demoLog("SignedData", signed_data)

        # --- TODO generation time verification ---
        tbs = signed_data['tbsData']
        header = tbs['headerInfo']
        verify_time(header)

        # --- TODO signature verification ---
        with open("keys/sender_public_key.pem", "rb") as f:
            SENDER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

        verify_signature(signed_data, SENDER_PUBLIC_KEY)

    else:
        raise ValueError("Unknown contentType")

# --- generation time verification ---
def verify_time(header) -> bool:
    generation_time = int(header['generationTime'])
    expiry_time = int(header['expiryTime'])

    current_time = int(time.time() * 1_000_000)

    if current_time < generation_time:
        demoLog("GenerationTime Check", "Message is from the future!")
        return False
    elif current_time > expiry_time:
        demoLog("GenerationTime Check", "Message expired!")
        return False
    demoLog("GenerationTime Check", "passed")
    return True

# --- signature verification ---
def verify_signature(signed_data, public_key) -> bool:
    raw_sig = bytes(signed_data['signatureValue'])

    if len(raw_sig) != 64:
        raise ValueError("Invalid signature length")
    
    r = int.from_bytes(raw_sig[:32], 'big')
    s = int.from_bytes(raw_sig[32:], 'big')

    der_sig = encode_dss_signature(r, s)

    tbs = signed_data['tbsData']
    tbs_bytes = encoder.encode(tbs)

    try:
        public_key.verify(
            der_sig,
            tbs_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        demoLog("Signature Check", "passed")
        return True
    except Exception as e:
        demoLog("Signature Check", "failed")
        return False

if __name__ == "__main__":
    os.system('cls')
    decode_message()