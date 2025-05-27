import hashlib

def sha_256(bytes_: bytes) -> bytes:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(bytes_)
    return sha256_hash.digest()