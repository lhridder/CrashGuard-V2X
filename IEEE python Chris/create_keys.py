"""
Klein bestandje voor het maken van de keys.
In praktijk worden deze van te voren gemaakt en in de zender en ontvanger bewaart.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def createKey() -> None:
    sender_private_key = ec.generate_private_key(ec.SECP256R1())   # maak private key ECDSA (p-256)

    with open("IEEE python Chris/sender_private_key.pem", "wb") as f:
        f.write(
            sender_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print("Sender key generated.")

    receiver_private_key = ec.generate_private_key(ec.SECP256R1())   # maak private key ECDSA (p-256)

    with open("IEEE python Chris/receiver_private_key.pem", "wb") as f:
        f.write(
            receiver_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print("Receiver key generated.")

if __name__ == "__main__":
    createKey()
