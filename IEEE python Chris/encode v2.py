from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.type import univ, char, namedtype, namedval
from pyasn1.codec.der import encoder
import time
import os

# HeaderInfo (ASN.1)
class HeaderInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', univ.Integer()),
        namedtype.NamedType('generationTime', univ.Integer()),
        namedtype.NamedType('expiryTime', univ.Integer())
    )

# ToBeSignedData (ASN.1)
class ToBeSignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', univ.OctetString()),
        namedtype.NamedType('headerInfo', HeaderInfo())
    )

# SignerInfo (ASN.1)
class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certID', char.UTF8String()),
        namedtype.NamedType('publicKey', univ.OctetString())
    )

# SignedData (ASN.1)
class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsData', ToBeSignedData()),
        namedtype.NamedType('signerInfo', SignerInfo()),
        namedtype.NamedType('signatureValue', univ.OctetString())
    )

# RecipientInfo (ASN.1)
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipientID', char.UTF8String()),
        namedtype.NamedType('ephemeralKey', univ.OctetString())
    )

# Encrypted Data (ASN.1)
class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', univ.SequenceOf(componentType=RecipientInfo())),
        namedtype.NamedType('ciphertext', univ.OctetString()),
        namedtype.NamedType('nonce', univ.OctetString()),
        namedtype.NamedType('ccmTag', univ.OctetString())
    )

# Ieee1609Dot2Data (ASN.1)
class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', univ.Integer()),
        namedtype.NamedType('contentType', univ.Enumerated(
            namedValues=namedval.NamedValues(
                ('unsecureData', 0),
                ('signedData', 1),
                ('encryptedData', 2)
            )
        )),
        namedtype.NamedType('content', univ.OctetString())
    )

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def encode_message() -> None:
    
    # welke data is nodig?
    with open("keys/sender_private_key.pem", "rb") as f:
        SENDER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

    with open("keys/receiver_public_key.pem", "rb") as f:
        RECEIVER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())
    
    EPHEMERAL_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
    EPHEMERAL_PUBLIC_KEY = EPHEMERAL_PRIVATE_KEY.public_key()
    NONCE = os.urandom(13)
    GENERATION_TIME = int(time.time() * 1_000_000)

    # 1. V2X payload
    payload = b"ik ben een pijlwagen"
    demoLog("V2X payload", payload)

    # 2. Hashing 3. Signing
    der_signature = SENDER_PRIVATE_KEY.sign(
        payload,
        ec.ECDSA(hashes.SHA256())
    )

    r, s = decode_dss_signature(der_signature)  # DER -> raw r||s volgens IEEE 1609.2
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    raw_signature = r_bytes + s_bytes
    demoLog("Signing: raw signature", raw_signature)

    # 4. ToBeSignedData
    header = HeaderInfo()
    header.setComponentByName('psid', 0x20) # willekeurige psid voor test
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 1_000_000) # +1 seconde

    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)

    public_bytes = SENDER_PRIVATE_KEY.public_key().public_bytes(       # public key naar bytes voor ASN.1
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    demoLog("ToBeSignedData", tbs)

    # 5. SignedData
    signer = SignerInfo()
    signer.setComponentByName('certID', 'testCert01')   # willekeurige certificate voor test
    signer.setComponentByName('publicKey', univ.OctetString(public_bytes))

    signed_data = SignedData()
    signed_data.setComponentByName('tbsData', tbs)
    signed_data.setComponentByName('signerInfo', signer)
    signed_data.setComponentByName('signatureValue', raw_signature)

    demoLog("SignedData", signed_data)

    # 6. ASN.1 encoding
    # al gedaan in stap 4 en 5 zelf

    # 7. (Optioneel) encryption -> ik gebruik AES-CCM via KDF (SHA-256)
    demoLog("Encryption: ephermeral key", EPHEMERAL_PUBLIC_KEY.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex())

    shared_secret = EPHEMERAL_PRIVATE_KEY.exchange(ec.ECDH(), RECEIVER_PUBLIC_KEY)      # shared secret is ephemeral key exchange met receiver public key

    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=None)
    aes_key = ckdf.derive(shared_secret)

    aesccm = AESCCM(aes_key, tag_length=16)

    ciphertext_and_tag = aesccm.encrypt(NONCE, payload, associated_data=None)
    ciphertext = ciphertext_and_tag[:-16]
    ccm_tag = ciphertext_and_tag[-16:]

    demoLog("Encryption: ciphertext", ciphertext.hex())
    demoLog("Encryptio: CCM Tag", ccm_tag.hex())

    # 8. EncryptedData
    ephemeral_pub_bytes = EPHEMERAL_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    recipient = RecipientInfo()
    recipient.setComponentByName('recipientID', 'receiver01')   # test vehicle voor demo
    recipient.setComponentByName('ephemeralKey', ephemeral_pub_bytes)

    recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
    recipients_seq.append(recipient)

    enc_data = EncryptedData()
    enc_data.setComponentByName('recipients', recipients_seq)
    enc_data.setComponentByName('ciphertext', ciphertext)
    enc_data.setComponentByName('nonce', NONCE)
    enc_data.setComponentByName('ccmTag', ccm_tag)

    encoded_encrypted_data = encoder.encode(enc_data)
    demoLog("Encrypted Data", encoded_encrypted_data.hex())

    # 9. Ieee1609Dot2Data
    ieee_data_encrypted = Ieee1609Dot2Data()
    ieee_data_encrypted.setComponentByName('protocolVersion', 3)
    ieee_data_encrypted.setComponentByName('contentType', 2)   # 2 = encryptedData
    ieee_data_encrypted.setComponentByName('content', encoded_encrypted_data)

    final_message_signed = encoder.encode(ieee_data_encrypted)
    demoLog("Final", final_message_signed.hex())

    # final message exporteren voor decoding
    with open("IEEE python Chris/signed_msg.txt", "wb") as f:
        f.write(final_message_signed)

if __name__ == "__main__":
    os.system('cls')
    encode_message()