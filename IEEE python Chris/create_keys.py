import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def create_keys() -> None:
    """
    Generates an ECDSA (P-256) key pair for a sender and a receiver,
    and saves the private and public keys to the 'keys' directory in PEM format.
    """
    # --- Sender Key Pair Generation and Saving ---
    print("Generating sender key pair...")
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
    
    print("Sender key pair generated and saved.")

    # --- Receiver Key Pair Generation and Saving ---
    print("\nGenerating receiver key pair...")
    receiver_private_key = ec.generate_private_key(ec.SECP256R1())

    # Save Receiver Private Key
    private_pem = receiver_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("keys/receiver_private_key.pem", "wb") as f:
        f.write(private_pem)

    # Save Receiver Public Key (The part that needed fixing!)
    receiver_public_key = receiver_private_key.public_key()
    public_pem = receiver_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("keys/receiver_public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Receiver key pair generated and saved.")

if __name__ == "__main__":
    os.system('cls')
    create_keys()