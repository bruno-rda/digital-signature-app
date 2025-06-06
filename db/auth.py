import os
from supabase import create_client, Client

client: Client = create_client(
    supabase_url=os.getenv('SUPABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY')
)
table = client.table('user_profiles')

def set_username(user_id: str, username: str) -> bool:
    response = (
        table
        .insert({'user_id': user_id, 'username': username})
        .execute()
    )

    if bool(response.data):
        return True
    
    raise Exception(f'Failed to set username')

def is_valid_username(username: str) -> bool:
    length_restriction = 3 <= len(username) <= 16
    special_characters_restriction = all(
        char.isalnum() or char == '_' 
        for char in username
    )

    return length_restriction and special_characters_restriction

def get_username(user_id: str) -> str:
    response = (
        table
        .select('username')
        .eq('user_id', user_id)
        .execute()
    )

    if response.data:
        return response.data[0]['username']
    
    return ''

def get_all_usernames() -> dict[str, str]:
    response = (
        table
        .select('*')
        .execute()
    )
    
    return {
        user['username']: user['user_id']
        for user in response.data
    }