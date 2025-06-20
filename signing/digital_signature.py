from dataclasses import dataclass
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
    def _generate_key_pair(self):
        '''Generate a private/public key pair.'''
        raise NotImplementedError
    
    def _sign_hash(self, private_key, document_hash: bytes) -> bytes:
        '''Sign a document hash using the private key.'''
        raise NotImplementedError
    
    def _verify_hash_signature(
        self, 
        public_key, 
        document_hash: bytes, 
        signature: bytes
    ) -> bool:
        '''Verify a signature against a document hash.'''
        raise NotImplementedError
    
    def generate_keys(self) -> Keys:
        private_key, public_key = self._generate_key_pair()
        return self._serialize_keys(private_key, public_key)
    
    def _serialize_keys(self, private_key, public_key) -> Keys:
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
    
    def _load_private_key(self, private_pem: bytes):
        return serialization.load_pem_private_key(
            private_pem, 
            password=None
        )
    
    def _load_public_key(self, public_pem_hex: str):
        public_pem = bytes.fromhex(public_pem_hex)
        return serialization.load_pem_public_key(public_pem)
    
    def sign_document(
        self,
        private_pem: bytes,
        document: bytes,
    ) -> SignatureData:
        private_key = self._load_private_key(private_pem)
        document_hash = sha_256(document)
        
        signature = self._sign_hash(private_key, document_hash)
        
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
        try:
            public_key = self._load_public_key(public_pem_hex)
            signature = bytes.fromhex(signature_hex)
            document_hash = sha_256(document)
            
            return self._verify_hash_signature(
                public_key, 
                document_hash, 
                signature
            )
        except ...:
            return False


class RSA(DigitalSignature):
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def _generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def _sign_hash(self, private_key, document_hash: bytes) -> bytes:
        return private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )
    
    def _verify_hash_signature(
        self, 
        public_key, 
        document_hash: bytes, 
        signature: bytes
    ) -> bool:
        try:
            public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                Prehashed(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


class ECDSA(DigitalSignature):
    def __init__(self, curve=None):
        self.curve = curve or ec.SECP384R1()

    def _generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def _sign_hash(self, private_key, document_hash: bytes) -> bytes:
        return private_key.sign(
            document_hash,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
    
    def _verify_hash_signature(
        self, 
        public_key, 
        document_hash: bytes, 
        signature: bytes
    ) -> bool:
        try:
            public_key.verify(
                signature,
                document_hash,
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            return True
        except InvalidSignature:
            return False
        
SUPPORTED_KEY_ALGORITHMS = {
    'RSA': RSA, 
    'ECDSA': ECDSA
}