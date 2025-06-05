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

def sign_in() -> str:
    response = client.auth.sign_in_with_oauth(
        {'provider': 'google'}
    )
    
    return response.url

def exchange_code_for_session(auth_code: str) -> tuple[str, str]:
    response = client.auth.exchange_code_for_session(
        {'auth_code': auth_code}
    )
    
    if response:
        return (
            response.user.id,
            response.session.refresh_token
        )
    
    raise Exception('Failed to get user id from auth code')

def refresh_session(refresh_token: str):
    response = client.auth.refresh_session(refresh_token)
    
    if response:
        return response.user.id

def sign_out() -> None:
    client.auth.sign_out()