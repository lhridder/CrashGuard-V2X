"""
Het maken van code werkt beter voor het begrijpen dan alleen een onderzoek in een word document. Hier werk ik alle stappen uit:
1. V2X payload
2. Hashing
3. Signing
4. ToBeSignedData / tbs_data
5. SignedData
6. ASN.1 encoding
7. (Optioneel) encryption
8. EncryptedData
9. Ieee1609Dot2Data
"""

from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import time
from pyasn1.type import univ, char, namedtype, tag, useful
from pyasn1.codec.der import decoder
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

def demoLog(step:str, output:str) -> None:
    print(f"[\033[36m{step}\033[0m] {output}")
os.system('cls')

# 1. V2X payload
payload = b"ik ben een pijlwagen"   # byte array van message
demoLog("V2X payload", payload)

# 2. Hashing
digest = sha256(payload).digest()
demoLog("Hashing", digest)

# 3. Signing
private_key = ec.generate_private_key(ec.SECP256R1())   # maak private key ECDSA (p-256)
demoLog("Signign: private key", private_key)

der_signature = private_key.sign(   # sign payload met ECDSA en private key (niet digest!)
    payload,
    ec.ECDSA(hashes.SHA256())       # signing functie geeft zelf hashing functie mee (SHA256)
)

r, s = decode_dss_signature(der_signature)  # DER -> raw r||s volgens IEEE 1609.2
r_bytes = r.to_bytes(32, byteorder="big")
s_bytes = s.to_bytes(32, byteorder="big")
raw_signature = r_bytes + s_bytes
demoLog("Signing: raw signature", raw_signature)

# 4. ToBeSignedData
generation_time = int(time.time() * 1_000_000)

header = HeaderInfo()
header.setComponentByName('psid', 0x20) # willekeurige psid voor test
header.setComponentByName('generationTime', generation_time)
header.setComponentByName('expiryTime', generation_time + 1_000_000) # +1 seconde

tbs = ToBeSignedData()
tbs.setComponentByName('payload', payload)
tbs.setComponentByName('headerInfo', header)

public_bytes = private_key.public_key().public_bytes(       # public key naar bytes voor ASN.1
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

signer = SignerInfo()
signer.setComponentByName('certID', 'testCert01')   # willekeurige certificate voor test
signer.setComponentByName('publicKey', univ.OctetString(public_bytes))

demoLog("ToBeSignedData", tbs)

# 5. SignedData
signed_data = SignedData()
signed_data.setComponentByName('tbsData', tbs)
signed_data.setComponentByName('signerInfo', signer)
signed_data.setComponentByName('signatureValue', raw_signature)

demoLog("SignedData", signed_data)

# 6. ASN.1 encoding
# al gedaan in stap 4 en 5 zelf

# 7. (Optioneel) encryption -> ik gebruik AES-CCM via KDF (SHA-256)
"""
1. zender genereert ephemeral EC key pair
2. berekent shared secret via ECDH met public key van ontvanger
3. afleiden van AES-CCM sleutel via KDF (SHA256)
4. versleutel payload met AES-CCM
5. verzend ciphertext, nonce, tag + ephemeral public key naar ontvanger
"""
receiver_private_key = ec.generate_private_key(ec.SECP256R1())
receiver_public_key = receiver_private_key.public_key()

ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
ephemeral_public_key = ephemeral_private_key.public_key()

shared_secret = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key)

ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=None)
aes_key = ckdf.derive(shared_secret)

aesccm = AESCCM(aes_key, tag_length=16)
nonce = os.urandom(13)
ciphertext = aesccm.encrypt(nonce, payload, associated_data=None)

demoLog("Encryption", ephemeral_public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex())

# 8. EncryptedData


# 9. Ieee1609Dot2Data