from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

def create_keys() -> None:
    
    # --- Create group key ---
    GROUP_KEY = os.urandom(16)

    # --- Save group key ---
    with open("keys/group_key.bin", "wb") as f:
        f.write(GROUP_KEY)
    print("GROUP_KEY aangemaakt.")

    # --- Sender Key Pair Generation and Saving ---
    sender_private_key = ec.generate_private_key(ec.SECP256R1())

    # Save Sender Private Key
    private_pem = sender_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("keys/sender_private_key.pem", "wb") as f:
        f.write(private_pem)

    # Save Sender Public Key (The part that needed fixing!)
    sender_public_key = sender_private_key.public_key()
    public_pem = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("keys/sender_public_key.pem", "wb") as f:
        f.write(public_pem)
    
    print("SENDER_KEYS aangemaakt.")

if __name__ == "__main__":
    os.system('cls')
    create_keys()