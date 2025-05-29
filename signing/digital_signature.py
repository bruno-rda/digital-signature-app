from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from utils.helpers import sha_256

@dataclass
class Keys:
    private_pem: bytes
    public_pem_hex: str

@dataclass
class SignatureData:
    document_hash_hex: str
    signature_hex: str

class DigitalSignature:    
    def generate_keys(self) -> Keys:
        raise NotImplementedError
    
    def _serialize_keys(
        self,
        private_key: bytes,
        public_key: bytes
    ) -> Keys:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return Keys(
            public_pem_hex=public_pem.hex(),
            private_pem=private_pem
        )
        
    def sign_document(
        self,
        private_pem: bytes,
        document: bytes,
    ) -> SignatureData:
        raise NotImplementedError
    
    def verify_signature(
        self,
        public_pem_hex: str,
        document: bytes,
        signature_hex: str
    ) -> bool:
        raise NotImplementedError


class RSA(DigitalSignature):
    def __init__(self, key_size=2048):
        super().__init__()
        self.key_size = key_size

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        public_key = private_key.public_key()

        return self._serialize_keys(
            private_key=private_key,
            public_key=public_key
        )
    
    def sign_document(
        self, 
        private_pem: bytes, 
        document: bytes
    ) -> SignatureData:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_pem, 
            password=None
        )

        document_hash = sha_256(document)
        signature = private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return SignatureData(
            document_hash_hex=document_hash.hex(),
            signature_hex=signature.hex()
        )
    
    def verify_signature(
        self,
        public_pem_hex: str,
        document: bytes,
        signature_hex: str
    ) -> bool:
        # Convert the public key and signature to bytes
        public_pem = bytes.fromhex(public_pem_hex)
        signature = bytes.fromhex(signature_hex)

        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_pem
        )

        # Verify the signature
        try:
            public_key.verify(
                signature,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class ECDSA(DigitalSignature):
    def __init__(self):
        super().__init__()

    def generate_keys(self):
        private_key = ec.generate_private_key(
            ec.SECP384R1()
        )
        public_key = private_key.public_key()

        return self._serialize_keys(
            private_key=private_key,
            public_key=public_key
        )

    def sign_document(
        self, 
        private_pem: bytes, 
        document: bytes
    ) -> SignatureData:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_pem, 
            password=None
        )

        document_hash = sha_256(document)
        signature = private_key.sign(
            document_hash,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        return SignatureData(
            document_hash_hex=document_hash.hex(),
            signature_hex=signature.hex()
        )
    
    def verify_signature(
        self,
        public_pem_hex: str,
        document: bytes,
        signature_hex: str
    ) -> bool:
        # Convert the public key to bytes
        public_pem = bytes.fromhex(public_pem_hex)
        signature = bytes.fromhex(signature_hex)

        # Load the public key
        public_key = serialization.load_pem_public_key(public_pem)
        
        try:
            public_key.verify(
                signature,
                document,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        
SUPPORTED_KEY_ALGORITHMS = {
    'RSA': RSA, 
    'ECDSA': ECDSA
}