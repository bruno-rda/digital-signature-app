import os
from pymongo import MongoClient
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime
from db.auth import user_exists

client = MongoClient(os.getenv('MONGO_URI'))
db = client[os.getenv('MONGO_DB_NAME')]
collection = db['userProfiles']

class PublicKey(BaseModel):
    public_pem_hex: str
    key_algorithm: Literal['rsa', 'ecdsa']
    created_at: float
    expired_at: Optional[float]

    @property
    def signed_at_date(self) -> str:
        return datetime.fromtimestamp(
            self.created_at
        ).strftime('%d-%m-%Y %H:%M:%S')

class UserInfo(BaseModel):
    username: str
    current_public_key: PublicKey
    legacy_public_keys: list[PublicKey]

def user_info_exists(username: str) -> bool:
    if not user_exists(username):
        raise Exception('User does not exist')
    
    return bool(
        collection.find_one({
            'username': username
        })
    )

def get_user_info(username: str) -> UserInfo:
    if not user_info_exists(username):
        raise Exception('User information not set')
    
    return UserInfo(
        **collection.find_one({
            'username': username
        })
    )

def get_public_key(username: str) -> PublicKey:
    if not user_info_exists(username):
        raise Exception('User information not set')
    
    # Find the users current public key
    user_info = get_user_info(username)
    public_key = user_info.current_public_key

    if not public_key:
        raise Exception('Public key not found')
    
    return public_key

def get_legacy_public_keys(username: str) -> list[PublicKey]:
    if not user_info_exists(username):
        raise Exception('User information not set')
    
    user_info = get_user_info(username)
    return user_info.legacy_public_keys

def set_public_key(
    username: str, 
    public_pem_hex: str,
    key_algorithm: Literal['rsa', 'ecdsa']
) -> bool:
    '''
    Sets the current public key for a user, and updates the
    legacy public keys if necessary.
    '''
    
    if not user_info_exists(username):
        # If the user does not exist, create a new user profile
        try:
            user_info = UserInfo(
                username=username,
                current_public_key=PublicKey(
                    public_pem_hex=public_pem_hex,
                    key_algorithm=key_algorithm,
                    created_at=datetime.now().timestamp(),
                    expired_at=None
                ),
                legacy_public_keys=[]
            )

            collection.insert_one(user_info.model_dump())
            return True
        except Exception as e:
            raise Exception(f'Failed to set public key. {str(e)}')
    else:
        # If the user exists, update the public key and move current to legacy
        try:
            # Get the user profile
            user_info = get_user_info(username)

            # Make previous key a legacy key
            prev_public_key = user_info.current_public_key
            prev_public_key.expired_at = datetime.now().timestamp()
            user_info.legacy_public_keys.append(prev_public_key)

            # Set the new key as the current key
            user_info.current_public_key = PublicKey(
                public_pem_hex=public_pem_hex,
                key_algorithm=key_algorithm,
                created_at=datetime.now().timestamp(),
                expired_at=None
            )

            # Update the user profile
            collection.update_one({
                'username': username
            }, {
                '$set': user_info.model_dump()
            })
            return True
        except Exception as e:
            raise Exception('Failed to set public key. ' + str(e))