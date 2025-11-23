from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from asn1 import EnvelopedData, Ieee1609Dot2Data, SignedData, EncryptedData
import socket
import decode


def decode_signed(msg) -> bool:
    # decode asn1 format
    signed_data, _ = decoder.decode(msg, asn1Spec=SignedData())
    print("IEEE signed data: " + str(msg))

    # pass header to time verification function
    header = signed_data['tbsData']['headerInfo']
    if not decode.verify_time(header):
        print("Time could not be verified")
        return False

    # TODO implement proper keystore
    with open("keys/sender_public_key.pem", "rb") as f:
        SENDER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

    # verify asn1 signature with public key
    if decode.verify_signature(signed_data, SENDER_PUBLIC_KEY):
        print("Signature was verified")
        return True
    else:
        print("Signature could not be verified")
        return False


def decode_encrypted(msg) -> bool:
    # decode asn1 format
    enc_data, _ = decoder.decode(msg, asn1Spec=EncryptedData())

    # extract nonce, ciphertext and ccm_tag
    nonce = bytes(enc_data['nonce'])
    ciphertext = bytes(enc_data['ciphertext'])
    ccm_tag = bytes(enc_data['ccmTag'])

    # format ciphertext and tag
    ciphertext_and_tag = ciphertext + ccm_tag

    # TODO implement proper keystore
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()
    aesccm = AESCCM(GROUP_KEY, tag_length=16)

    # decrypt ciphertext and tag with private key
    try:
        payload = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        print("Payload was decrypted: " + str(payload))
        return True
    except Exception as e:
        print("Decryption failed: " + str(e))
        return False


def decode_enveloped(msg) -> bool:
    # decode asn1 format
    enveloped, _ = decoder.decode(msg, asn1Spec=EnvelopedData())

    # extract nonce, ciphertext and ccm_tag
    nonce = bytes(enveloped['nonce'])
    ciphertext = bytes(enveloped['encryptedContent'])
    ccm_tag = bytes(enveloped['ccmTag'])

    # format ciphertext and tag
    ciphertext_and_tag = ciphertext + ccm_tag

    # TODO implement proper keystore
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()
    aesccm = AESCCM(GROUP_KEY, tag_length=16)

    try:
        signed_bytes = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        print("Signed bytes were decrypted: " + str(signed_bytes))
    except Exception as e:
        print("Decryption failed: " + str(e))
        return False

    # decode asn1 format
    signed_data, _ = decoder.decode(signed_bytes, asn1Spec=SignedData())
    print("Signed data: " + str(signed_data))

    # pass header to time verification function
    header = signed_data['tbsData']['headerInfo']
    if not decode.verify_time(header):
        print("Time could not be verified")
        return False

    # TODO implement proper keystore
    with open("keys/sender_public_key.pem", "rb") as f:
        SENDER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

    # verify asn1 signature with public key
    if decode.verify_signature(signed_data, SENDER_PUBLIC_KEY):
        print("Signature was verified")
        return True
    else:
        print("Signature could not be verified")
        return False


def decode_message(msg):
    # Decode IEEE1609 message
    ieee_msg, _ = decoder.decode(msg, asn1Spec=Ieee1609Dot2Data())  # ASN.1 decoding
    print("IEEE MSG to be decoded: " + str(ieee_msg))

    # extract contenttype and content from IEEE1609 message
    content_type = int(ieee_msg['contentType'])
    content_bytes = bytes(ieee_msg['content'])

    match content_type:
        case 0:  # unsecureData
            print("IEEE unsecured payload: " + str(content_bytes))

        case 1:  # signedData
            # TODO check
            decode_signed(content_bytes)

        case 2:  # encryptedData
            # TODO check
            decode_encrypted(content_bytes)

        case 3:  # envelopedData
            # TODO check
            decode_enveloped(content_bytes)

        case _:  # unknown
            print("Content_type " + str(content_type) + " unknown")


def startserver(host, port):
    print("Starting server on host " + str(host) + " and port " + str(port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print("New connection from " + str(addr))
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Received message: " + str(data))
            decode_message(data)


if __name__ == "__main__":
    print("Starting car application...")
    startserver("127.0.0.1", 5000)
