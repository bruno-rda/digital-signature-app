import os
from pymongo import MongoClient
from pydantic import BaseModel
from datetime import datetime
from db.auth import user_exists

client = MongoClient(os.getenv('MONGO_URI'))
db = client[os.getenv('MONGO_DB_NAME')]
collection = db['signatures']

class SignedDocument(BaseModel):
    username: str
    signed_at: float
    document_name: str
    document_hash_hex: str
    signature_hex: str
    key_id: str

    @property
    def signed_at_date(self) -> str:
        return datetime.fromtimestamp(
            self.signed_at
        ).strftime('%d-%m-%Y %H:%M:%S')
    
def save_signature(
    username: str,
    document_name: str,
    document_hash_hex: str,
    signature_hex: str,
    key_id: str
) -> bool:
    if not user_exists(username):
        raise Exception('User does not exist')

    try:
        signed_document = SignedDocument(
            username=username,
            signed_at=datetime.now().timestamp(),
            document_name=document_name,
            document_hash_hex=document_hash_hex,
            signature_hex=signature_hex,
            key_id=key_id
        )
        
        collection.insert_one(signed_document.model_dump())
        return True
    except Exception as e:
        raise Exception(f'Error saving signature: {e}')

def get_signatures(username: str) -> list[SignedDocument]:
    if not user_exists(username):
        raise Exception('User does not exist')
    
    signatures = collection.find({
        'username': username
    })

    return [
        SignedDocument(**signature) 
        for signature in signatures
    ]