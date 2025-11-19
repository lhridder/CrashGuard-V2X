from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from asn1 import HeaderInfo, ToBeSignedData, SignerInfo, SignedData, RecipientInfo, EncryptedData, Ieee1609Dot2Data
import time
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def encode_message() -> None:
    
    # --- 1. V2X payload ---
    payload = b"ik ben een pijlwagen"

    demoLog("V2X payload", payload)

    # --- 2. Header ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20)
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 1_000_000)

    demoLog("HeaderInfo", header)

    # --- 3. ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)

    demoLog("ToBeSignedData", tbs)

    # --- 4. SignedData ---
    signer = SignerInfo()
    signer.setComponentByName('certID', 'pijlwagenCert01')
    signer.setComponentByName('publicKey', b'placeholder_pubkey')

    signed_data = SignedData()
    signed_data.setComponentByName('tbsData', tbs)
    signed_data.setComponentByName('signerInfo', signer)
    signed_data.setComponentByName('signatureValue', b'placeholder_signature')

    demoLog("SignedData", signed_data)
    
    # --- 5. Encryption ---
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()
    NONCE = os.urandom(13)

    aesccm = AESCCM(GROUP_KEY, tag_length=16)
    ciphertext_and_tag = aesccm.encrypt(NONCE, payload, associated_data=None)
    ciphertext = ciphertext_and_tag[:-16]
    ccm_tag = ciphertext_and_tag[-16:]

    demoLog("ciphertext", ciphertext)

    # --- 6. EncryptedData ---
    recipient = RecipientInfo()
    recipient.setComponentByName('recipientID', 'group_01')

    recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
    recipients_seq.append(recipient)

    enc_data = EncryptedData()
    enc_data.setComponentByName('recipients', recipients_seq)
    enc_data.setComponentByName('ciphertext', ciphertext)
    enc_data.setComponentByName('nonce', NONCE)
    enc_data.setComponentByName('ccmTag', ccm_tag)

    encoded_encrypted_data = encoder.encode(enc_data)   # ASN.1 encoding

    demoLog("EncryptedData", enc_data)

    # --- 7. Ieee1609Dot2Data ---
    ieee_data_encrypted = Ieee1609Dot2Data()
    ieee_data_encrypted.setComponentByName('protocolVersion', 3)
    ieee_data_encrypted.setComponentByName('contentType', 2) # encryptedData
    ieee_data_encrypted.setComponentByName('content', encoded_encrypted_data)

    final_message = encoder.encode(ieee_data_encrypted) # ASN.1 encoding

    demoLog("Ieee1609Dot2Data", ieee_data_encrypted)

    # --- 8. Send message ---
    with open("IEEE python Chris/signed_msg.txt", "wb") as f:
        f.write(final_message)

if __name__ == "__main__":
    os.system('cls')
    encode_message()