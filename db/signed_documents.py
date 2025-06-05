import os
from typing import Optional
from pydantic import BaseModel
from datetime import datetime
from supabase import create_client, Client

client: Client = create_client(
    supabase_url=os.getenv('SUPABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY')
)
table = client.table('signed_documents')


class SignedDocument(BaseModel):
    id: Optional[str] = None
    signed_at: Optional[str] = None
    document_name: str
    document_hash_hex: str
    signature_hex: str
    key_id: str

    @property
    def signed_at_date(self) -> str:
        return (
            datetime
            .fromisoformat(
                self.signed_at
            )
            .astimezone()
            .strftime("%Y-%m-%d %H:%M:%S")
        )
    
def save_signature(
    document_name: str,
    document_hash_hex: str,
    signature_hex: str,
    key_id: str
) -> bool:
    try:
        signed_document = SignedDocument(
            document_name=document_name,
            document_hash_hex=document_hash_hex,
            signature_hex=signature_hex,
            key_id=key_id
        )
        
        response = (
            table
            .insert(signed_document.model_dump(exclude_none=True))
            .execute()
        )

        return bool(response.data)
    except Exception as e:
        if e.code == '23505':
            raise Exception('Document already signed')

        raise Exception(f'Error saving signature: {e}')

def get_signatures(user_id: str) -> list[SignedDocument]:
    response = (
        table
        .select('*, public_keys(user_id)')
        .eq('public_keys.user_id', user_id)
        .execute()
    )

    return [
        SignedDocument(**signature) 
        for signature in response.data
    ]