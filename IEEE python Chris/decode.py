"""
Apart script voor de reciever om te decoden. Stappen zijn:
1. Ontvang bericht
2. Decode Ieee1609Dot2Data
3. Decode content type
4. Decrypt encrypted data
"""

from pyasn1.codec.der import decoder
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import os

# ASN.1 classes van encode.py hergebruiken
from encode import Ieee1609Dot2Data, EncryptedData, SignedData

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    os.system('cls')

    # 1. bericht ontvangen (in dit geval txt)
    with open("IEEE python Chris/signed_msg.txt", "rb") as f:
        final_message = f.read()

    demoLog("Message", final_message)

    # 2. Decode Ieee1609Dot2Data
    decoded_ieee, rest = decoder.decode(final_message, asn1Spec=Ieee1609Dot2Data())
    content_type = int(decoded_ieee.getComponentByName("contentType"))
    content_asn1 = decoded_ieee.getComponentByName("content")
    content_bytes = bytes(content_asn1)
    demoLog("Inner Raw Content", content_bytes)

    # 3. Decode content type
    if content_type == 1:  # signedData
        signed_data, _ = decoder.decode(content_bytes, asn1Spec=SignedData())
        tbs = signed_data.getComponentByName("tbsData")
        signer = signed_data.getComponentByName("signerInfo")
        signature = bytes(signed_data.getComponentByName("signatureValue"))

        payload = bytes(tbs.getComponentByName("payload"))
        cert_id = str(signer.getComponentByName("certID"))
        pubkey_bytes = bytes(signer.getComponentByName("publicKey"))

        demoLog("SignedData - Payload", payload)
        demoLog("SignedData - CertID", cert_id)
        demoLog("SignedData - PubKey", pubkey_bytes.hex())
        demoLog("SignedData - Signature", signature.hex())

    elif content_type == 2:  # encryptedData
        enc_data, _ = decoder.decode(content_bytes, asn1Spec=EncryptedData())
        recipients = enc_data.getComponentByName("recipients")
        recipient0 = recipients.getComponentByPosition(0)
        recipient_id = str(recipient0.getComponentByName("recipientID"))
        eph_pub_bytes = bytes(recipient0.getComponentByName("ephemeralKey"))
        ciphertext = bytes(enc_data.getComponentByName("ciphertext"))
        nonce = bytes(enc_data.getComponentByName("nonce"))
        ccm_tag = bytes(enc_data.getComponentByName("ccmTag"))

        demoLog("EncryptedData - RecipientID", recipient_id)
        demoLog("EncryptedData - EphemeralPub", eph_pub_bytes.hex())
        demoLog("EncryptedData - Ciphertext", ciphertext.hex())
        demoLog("EncryptedData - Nonce", nonce.hex())
        demoLog("EncryptedData - CCM Tag", ccm_tag.hex())
    
    # 4. Decrypt encrypted data
    with open("IEEE python Chris/receiver_private_key.pem", "rb") as f:     # get receiver private key
        receiver_private_key = load_pem_private_key(f.read(), password=None)
        
    ephemeral_pub = load_der_public_key(eph_pub_bytes)
    shared_secret = receiver_private_key.exchange(ec.ECDH(), ephemeral_pub)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=None)
    aes_key = ckdf.derive(shared_secret)
    aesccm = AESCCM(aes_key, tag_length=16)
    full_ciphertext = ciphertext + ccm_tag  # combine ciphertext + tag

    plaintext = aesccm.decrypt(nonce, full_ciphertext, associated_data=None)
    demoLog("Decrypted Payload", plaintext)

if __name__ == "__main__":
    decode_message()