import os
from uuid import uuid4
from pymongo import MongoClient
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime
from db.auth import user_exists

client = MongoClient(os.getenv('MONGO_URI'))
db = client[os.getenv('MONGO_DB_NAME')]
collection = db['userProfiles']

class PublicKey(BaseModel):
    id: str
    name: str
    public_pem_hex: str
    key_algorithm: Literal['RSA', 'ECDSA']
    created_at: float
    expired_at: Optional[float]
    is_active: bool

    @property
    def created_at_date(self) -> str:
        return datetime.fromtimestamp(
            self.created_at
        ).strftime('%d-%m-%Y %H:%M:%S')
    
    @property
    def expired_at_date(self) -> str:
        return datetime.fromtimestamp(
            self.expired_at
        ).strftime('%d-%m-%Y %H:%M:%S')

class UserInfo(BaseModel):
    username: str
    public_keys: list[PublicKey]

def user_info_exists(username: str) -> bool:
    if not user_exists(username):
        raise Exception('User does not exist')
    
    return bool(
        collection.find_one({
            'username': username
        })
    )

def get_user_keys(username: str) -> dict[str, PublicKey]:
    if not user_info_exists(username):
        return {}
    
    user_info = UserInfo(
        **collection.find_one({
            'username': username
        })
    )
    return {
        key.name: key
        for key in user_info.public_keys
    }

def add_public_key(
    username: str, 
    public_pem_hex: str,
    key_name: str,
    key_algorithm: Literal['RSA', 'ECDSA']
) -> bool:
    '''
    Sets the current public key for a user, and updates the
    legacy public keys if necessary.
    '''
    
    # Add user if they dont exist
    if not user_info_exists(username):
        # If the user does not exist, create a new user profile
        try:
            user_info = UserInfo(
                username=username,
                public_keys=[]
            )

            collection.insert_one(user_info.model_dump())
        except Exception as e:
            raise Exception(f'Failed to create user. {str(e)}')
    
    try:
        public_key = PublicKey(
            id=str(uuid4()),
            name=key_name,
            public_pem_hex=public_pem_hex,
            key_algorithm=key_algorithm,
            created_at=datetime.now().timestamp(),
            expired_at=None,
            is_active=True
        )
        
        user_keys = get_user_keys(username)
        public_keys = list(user_keys.values()) + [public_key]

        # Update the user profile
        collection.update_one(
            {'username': username}, 
            {'$set': {'public_keys': [key.model_dump() for key in public_keys]}}
        )
        return True
    except Exception as e:
        raise Exception('Failed to add public key. ' + str(e))
    
def rename_public_key(username: str, new_key_name: str, key_id: str):
    if not user_info_exists(username):
        raise Exception('User information is not set')
    
    result = collection.update_one(
        {
            'username': username,
            'public_keys.id': key_id
        },
        {'$set': {'public_keys.$.name': new_key_name}}
    )
    
    if not bool(result.matched_count):
        raise Exception('Key was not renamed')

def deactivate_public_key(username: str, key_id):
    if not user_info_exists(username):
        raise Exception('User information is not set')
    
    user = collection.find_one(
        {
            'username': username,
            'public_keys.id': key_id
        },
        {
            'public_keys': {
                '$elemMatch': {'id': key_id}
            },
        }
    )
    
    if not user['public_keys'][0]['is_active']:
        raise Exception('Key is already deactivated')

    result = collection.update_one(
        {
            'username': username,
            'public_keys.id': key_id
        },
        {
            '$set': {
                'public_keys.$.is_active': False,
                'public_keys.$.expired_at': datetime.now().timestamp(),
            }
        }
    )
    
    if not bool(result.matched_count):
        raise Exception('Key was not deactivated')
    

def delete_public_key(username: str, key_id: str):
    if not user_info_exists(username):
        raise Exception('User information is not set')
    
    result = collection.delete_one({
        'username': username,
        'public_keys.id': key_id
    })

    if not bool(result.deleted_count):
        raise Exception('Key was not deleted')