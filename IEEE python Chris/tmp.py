from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import time
from pyasn1.type import univ, char, namedtype, tag, useful
from pyasn1.codec.der import decoder

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

def demoLog(step:str, output:str) -> None:
    print(f"[\033[36m{step}\033[0m] {output}")

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

# 4. ToBeSignedData opbouwen -> NOG NIET VOLGENS ASN.1!
generation_time = int(time.time() * 1_000_000)
tbs_data = {
    "payload": payload,
    "headerInfo": {
        "psid": 0x20,       # willekeurige psid voor test
        "generationTime": generation_time,
        "expiryTime": generation_time + 1_000_000       # +1 seconde
    }
}
demoLog("ToBeSignedData", tbs_data)

# 5. SignedData -> NOG NIET VOLGENS ASN.1!
signed_data = {
    "ToBeSignedData": tbs_data,
    "signerInfo": {
        "certID": "testCert01",     # willekeurige certificate voor test
        "publicKey": private_key.public_key()
    },
    "signatureValue": raw_signature
}
demoLog("SignedData", signed_data)

#...