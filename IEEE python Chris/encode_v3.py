from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from asn1 import HeaderInfo, ToBeSignedData, SignerInfo, SignedData, RecipientInfo, EncryptedData, Ieee1609Dot2Data, EnvelopedData
import time
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def getContentType() -> int:
    c = int(input("Select content type:\n0. unsecure\n1. signed\n2. encryted\n3. enveloped\n> "))
    return c

def encode_message(contentType:int = 0) -> None:
    
    # --- V2X payload ---
    payload = b"ik ben een pijlwagen"

    demoLog("V2X payload", payload)

    # --- Header ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20)
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 10_000_000)

    demoLog("HeaderInfo", header)

    # --- ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)

    demoLog("ToBeSignedData", tbs)

    # --- SignedData ---
    if contentType in (1, 3):   # signedData of envelopedData
        signer = SignerInfo()
        signer.setComponentByName('certID', 'pijlwagenCert01')          #TODO: real cert
        signer.setComponentByName('publicKey', b'placeholder_pubkey')   #TODO: real pubkey

        tbs_bytes = encoder.encode(tbs) # ASN.1 encoding

        # signing
        with open("keys/sender_private_key.pem", "rb") as f:
            SENDER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

        # signature
        signature = SENDER_PRIVATE_KEY.sign(
            tbs_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        # DER -> raw r||s
        r, s = decode_dss_signature(signature)
        raw_signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

        signed_data = SignedData()
        signed_data.setComponentByName('tbsData', tbs)
        signed_data.setComponentByName('signerInfo', signer)
        signed_data.setComponentByName('signatureValue', raw_signature)

        demoLog("SignedData", signed_data)

    # --- Content afhankelijk van contentType ---
    if contentType == 0:    # unsecureData
        content_bytes = payload

    elif contentType == 1:  # signedData
        
        content_bytes = encoder.encode(signed_data)

    elif contentType == 2:  # encryptedData
        # AES-CCM encryptie van payload
        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        NONCE = os.urandom(13)
        aesccm = AESCCM(GROUP_KEY, tag_length=16)
        ciphertext_and_tag = aesccm.encrypt(NONCE, payload, associated_data=None)
        ciphertext = ciphertext_and_tag[:-16]
        ccm_tag = ciphertext_and_tag[-16:]

        demoLog("ciphertext", ciphertext)

        # EncryptedData ASN.1
        recipient = RecipientInfo()
        recipient.setComponentByName('recipientID', 'group_01')     #TODO: real group
        recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
        recipients_seq.append(recipient)

        enc_data = EncryptedData()
        enc_data.setComponentByName('recipients', recipients_seq)
        enc_data.setComponentByName('ciphertext', ciphertext)
        enc_data.setComponentByName('nonce', NONCE)
        enc_data.setComponentByName('ccmTag', ccm_tag)

        content_bytes = encoder.encode(enc_data)    # ASN.1 encoding

    elif contentType == 3:  # envelopedData
        signed_bytes = encoder.encode(signed_data)

        # AES-CCM encryptie van SignedData
        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        NONCE = os.urandom(13)
        aesccm = AESCCM(GROUP_KEY, tag_length=16)
        ciphertext_and_tag = aesccm.encrypt(NONCE, signed_bytes, associated_data=None)
        ciphertext = ciphertext_and_tag[:-16]
        ccm_tag = ciphertext_and_tag[-16:]

        # EnvelopedData ASN.1
        recipient = RecipientInfo()
        recipient.setComponentByName('recipientID', 'group_01')     #TODO: real group
        recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
        recipients_seq.append(recipient)

        enveloped = EnvelopedData()
        enveloped.setComponentByName('recipients', recipients_seq)
        enveloped.setComponentByName('encryptedContent', ciphertext)
        enveloped.setComponentByName('nonce', NONCE)
        enveloped.setComponentByName('ccmTag', ccm_tag)

        content_bytes = encoder.encode(enveloped)   # ASN.1 encoding

        demoLog("EnvelopedData", enveloped)
    
    else:
        raise ValueError("Invalid contentType")

    # --- Ieee1609Dot2Data ---
    ieee_msg = Ieee1609Dot2Data()
    ieee_msg.setComponentByName('protocolVersion', 3)
    ieee_msg.setComponentByName('contentType', contentType)
    ieee_msg.setComponentByName('content', content_bytes)

    final_bytes = encoder.encode(ieee_msg)

    demoLog("Ieee1609Dot2Data", ieee_msg)

    # --- Send message ---
    with open("IEEE python Chris/signed_msg.txt", "wb") as f:
        f.write(final_bytes)

if __name__ == "__main__":
    os.system('cls')
    encode_message(getContentType())