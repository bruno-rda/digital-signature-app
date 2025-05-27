import os
from pymongo import MongoClient
from utils.helpers import sha_256

client = MongoClient(os.getenv('MONGO_URI'))
print(os.getenv('MONGO_URI'))
print(os.getenv('MONGO_DB_NAME'))
db = client[os.getenv('MONGO_DB_NAME')]
collection = db['users']

def get_usernames() -> list[str]:
    return [user['username'] for user in collection.find()]

def user_exists(username: str) -> bool:
    return bool(
        collection.find_one({
            'username': username,
        })
    )

def signup_user(username: str, password: str):
    if user_exists(username):
        raise Exception('Username is taken')
    
    password_hash_hex = sha_256(password.encode('utf-8')).hex()

    # TODO: Add email verification
    collection.insert_one({
        'username': username,
        'password_hash_hex': password_hash_hex
    })

def login_user(username: str, password: str):
    if not user_exists(username):
        raise Exception('User does not exist')
    
    password_hash_hex = sha_256(password.encode('utf-8')).hex()

    user = collection.find_one({'username': username})
    if user['password_hash_hex'] != password_hash_hex:
        raise Exception('Invalid password')

def update_password(username: str, new_password: str):
    if not user_exists(username):
        raise Exception('User does not exist')
    
    new_password_hash_hex = sha_256(new_password.encode('utf-8')).hex()

    # TODO: Set new password hex
