from pyasn1.type import univ, char, namedtype, namedval

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