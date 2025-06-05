import os
from uuid import uuid4
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime
from supabase import create_client, Client

client: Client = create_client(
    supabase_url=os.getenv('SUPABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY')
)
table = client.table('public_keys')


class PublicKey(BaseModel):
    id: Optional[str] = None
    user_id: str
    name: str
    public_pem_hex: str
    key_algorithm: Literal['RSA', 'ECDSA']
    created_at: Optional[str] = None
    expired_at: Optional[str] = None
    is_active: bool

    @property
    def created_at_date(self) -> str:
        return (
            datetime
            .fromisoformat(
                self.created_at
            )
            .astimezone()
            .strftime("%Y-%m-%d %H:%M:%S")
        )
    
    @property
    def expired_at_date(self) -> str:
        return (
            datetime
            .fromisoformat(
                self.expired_at
            )
            .strftime("%Y-%m-%d %H:%M:%S")
        )

class UserInfo(BaseModel):
    user_id: str
    public_keys: list[PublicKey]


def get_user_keys(user_id: str) -> dict[str, PublicKey]:
    response = (
        table
        .select('*')
        .eq('user_id', user_id)
        .execute()
    )

    user_info = UserInfo(
        user_id=user_id,
        public_keys=[
            PublicKey(**key)
            for key in response.data
        ]
    )

    return {
        key.name: key
        for key in user_info.public_keys
    }

def add_public_key(
    user_id: str, 
    public_pem_hex: str,
    key_name: str,
    key_algorithm: Literal['RSA', 'ECDSA']
) -> bool:
    '''
    Sets the current public key for a user, and updates the
    legacy public keys if necessary.
    '''
    
    try:
        response = (
            table
            .select('*')
            .eq('user_id', user_id)
            .eq('key_algorithm', key_algorithm)
            .eq('is_active', True)
            .execute()
        )

        if len(response.data) > 0:
            raise Exception('You can only have one active key per algorithm')

        public_key = PublicKey(
            user_id=user_id,
            name=key_name,
            public_pem_hex=public_pem_hex,
            key_algorithm=key_algorithm,
            is_active=True
        )

        response = (
            table
            .insert(public_key.model_dump(exclude_none=True))
            .execute()
        )

        return bool(response.data)
    except Exception as e:
        raise Exception('Failed to add public key. ' + str(e))

def _is_key_active(user_id: str, key_id: str) -> bool:
    response = (
        table
        .select('*')
        .eq('user_id', user_id)
        .eq('id', key_id)
        .eq('is_active', True)
        .execute()
    )

    return bool(response.data)

def rename_public_key(user_id: str, new_key_name: str, key_id: str):
    if not _is_key_active(user_id, key_id):
        raise Exception('Deactivated keys cannot be renamed')
    
    response = (
        table
        .update({'name': new_key_name})
        .eq('user_id', user_id)
        .eq('id', key_id)
        .execute()
    )
    
    if not bool(response.data):
        raise Exception('Key was not renamed')

def deactivate_public_key(user_id: str, key_id: str, key_name: str):
    if not _is_key_active(user_id, key_id):
        raise Exception('Key is already deactivated')

    response = (
        table
        .update(
            {
                'is_active': False, 
                'expired_at': datetime.now().isoformat(),
                'name': f'INACTIVE_{key_name}'
            }
        )
        .eq('user_id', user_id)
        .eq('id', key_id)
        .execute()
    )

    if not bool(response.data):
        raise Exception('Key was not deactivated')