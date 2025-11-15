from pyasn1.codec.der import decoder
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import sys

# ASN.1 classes van encode.py hergebruiken
from encode import Ieee1609Dot2Data, EncryptedData, SignedData

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    # 1. bericht ontvangen (in dit geval txt)
    with open ("IEEE python Chris/signed_msg.txt", "r") as f:
        final_message = f.read()

    demoLog("Message", final_message)

if __name__ == "__main__":
    decode_message()