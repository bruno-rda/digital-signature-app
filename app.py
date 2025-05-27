from dotenv import load_dotenv
load_dotenv()

import os
import streamlit as st
from signing.digital_signature import RSA, ECDSA
from db.auth import signup_user, login_user, get_usernames
from db.signatures import save_signature, get_signatures
from db.user_profile import (
    get_user_info,
    get_public_key,
    get_legacy_public_keys,
    set_public_key
)

# Define re-usable logic within the app
def reload_user_info():
    user_info = get_user_info(st.session_state.username)
    st.session_state.current_public_key = user_info.current_public_key

def generate_keys():
    match st.session_state.key_algorithm:
        case 'rsa':
            st.session_state.encryption_keys = RSA().generate_keys()
        case 'ecdsa':
            st.session_state.encryption_keys = ECDSA().generate_keys()

# Initialize the current page at authentication
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'authentication'

match st.session_state.current_page:
    case 'authentication':
        log_in, sign_up = st.tabs(['Log In', 'Sign Up'])

        with log_in:
            st.title('Log In')
            st.markdown('Log in to existing account')
            st.markdown("<br>", unsafe_allow_html=True)

            st.text_input(
                'Username',
                placeholder='Username',
                label_visibility='collapsed',
                key='login_username'
            )
            st.text_input(
                'Password',
                placeholder='Password', 
                label_visibility='collapsed',
                type='password',
                key='login_password'
            )

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button('Log In', use_container_width=True, type='primary'):
                try:
                    login_user(
                        st.session_state.login_username,
                        st.session_state.login_password
                    )
                    
                    # Set new vars
                    st.session_state.username = st.session_state.login_username
                    st.session_state.current_page = 'home'
                    reload_user_info() # Reload user info to get the current public key
                    
                    # Delete unnecessary vars
                    del st.session_state.login_username
                    del st.session_state.login_password

                    st.success('Logged In Successfully!')
                    st.rerun()
                except Exception as e:
                    st.error(f'Error: {e}')

        with sign_up:
            st.title('Sign Up')
            st.markdown('Create a new account')
            st.markdown('<br>', unsafe_allow_html=True)

            st.text_input(
                'Username',
                placeholder='Username',
                label_visibility='collapsed',
                key='signup_username'
            )
            st.text_input(
                'Password',
                placeholder='Password', 
                label_visibility='collapsed',
                type='password',
                key='signup_password'
            )

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button('Sign Up', use_container_width=True, type='primary'):
                try:
                    signup_user(
                        st.session_state.signup_username,
                        st.session_state.signup_password
                    )
                    # Set new vars
                    st.session_state.username = st.session_state.signup_username
                    st.session_state.key_algorithm = 'rsa' # Set default algorithm
                    st.session_state.current_page = 'download_key'
                    generate_keys()
                    
                    # Delete unnecessary vars
                    del st.session_state.signup_username
                    del st.session_state.signup_password

                    st.success('Account Created Succesfully!')
                    st.rerun()
                except Exception as e:
                    st.error(f'Error: {e}')

    case 'download_key':
        st.markdown(
            f'''
            # ⚠️ Save Your Private {st.session_state.key_algorithm.upper()} Key Now
            ### **This is the only time you will be able to download your private key.**

            - Keep it **safe and secure**.
            - **Do not share** it with anyone.
            - If you lose this key, **you won’t be able to sign again** without generating a new one.
            - Generating a new key means **losing all your past signatures**.

            🔒 Treat your private key like a password — or even more carefully.
            <br>
            <br>
            ''',
            unsafe_allow_html=True
        )

        # Center the download button using columns
        col = st.columns([7, 5, 7])[1]

        with col:
            st.download_button(
                label='Download Private Key',
                data=st.session_state.encryption_keys.private_pem,
                file_name='private_key.cer',
                mime='application/x-cer-file',
                type='primary',
                use_container_width=True
            )
            
            continue_btn = st.button('Continue', use_container_width=True)
        
        if continue_btn:
            set_public_key(
                username=st.session_state.username,
                public_pem_hex=st.session_state.encryption_keys.public_pem_hex,
                key_algorithm=st.session_state.key_algorithm
            )

            reload_user_info() # Reload user info to get the current public key
            st.session_state.current_page = 'home'

            del st.session_state.encryption_keys
            st.rerun()

    case 'home':
        history, sign_document, verify_signature, settings = st.tabs(
            ['History', 'Sign', 'Verify', 'Settings']
        )

        with history:
            st.title('History')

            st.markdown(
                f'## All signatures made by **{st.session_state.username}**',
                unsafe_allow_html=True
            )

            with st.expander('Key Details'):
                current_public_key = st.session_state.current_public_key

                st.markdown(
                    f'**Key:** {current_public_key.public_pem_hex}<br>'
                    f'**Algorithm:** **{current_public_key.key_algorithm.upper()}**<br>'
                    f'**Valid since:** **{current_public_key.signed_at_date}**',
                    unsafe_allow_html=True
                )

            signed_documents = get_signatures(st.session_state.username)

            if not signed_documents:
                st.info('No signatures found for this user yet. Start signing documents to see them here!')
            else:
                for signed_document in signed_documents:
                    with st.container(border=True):
                        st.markdown(
                            f"<div style='text-align: right;'> <span style='color:gray'>{signed_document.signed_at_date}</span></div>",
                            unsafe_allow_html=True
                        )
                        st.markdown(f'### {signed_document.document_name}')
                        st.markdown(f'**Document Hash:** {signed_document.document_hash_hex}')
                        st.markdown(f'**Signature:** {signed_document.signature_hex}')

        with sign_document:
            st.title('Sign Document')
            st.markdown(
                '#### Sign a document with your private key <br>',
                unsafe_allow_html=True
            )

            st.file_uploader(
                'Upload a document', 
                type=['pdf', 'docx', 'txt'], 
                key='sign_document_file'
            )

            st.file_uploader(
                'Upload private key',
                type=['pem', 'cer'],
                key='sign_document_private_key'
            )

            if st.button('Sign Document', use_container_width=True, type='primary'):
                if not st.session_state.sign_document_file:
                    st.error('Please upload a document')
                elif not st.session_state.sign_document_private_key:
                    st.error('Please upload your private key')
                else:
                    try:
                        # Get the current public key
                        current_public_key = st.session_state.current_public_key
                        
                        # Read file buffers
                        document = st.session_state.sign_document_file.read()
                        private_pem = st.session_state.sign_document_private_key.read()

                        # Get the according digital signature algorithm
                        if current_public_key.key_algorithm == 'rsa':
                            digital_signature = RSA()
                        elif current_public_key.key_algorithm == 'ecdsa':
                            digital_signature = ECDSA()
                        
                        # Sign the document
                        signature_data = digital_signature.sign_document(
                            private_pem=private_pem,
                            document=document
                        )

                        # Save the signature to the database
                        save_signature(
                            username=st.session_state.username,
                            document_name=st.session_state.sign_document_file.name,
                            document_hash_hex=signature_data.document_hash_hex,
                            signature_hex=signature_data.signature_hex
                        )

                        st.success('Document signed successfully!')
                    except Exception as e:
                        st.error(f'Error: {e}')

        with verify_signature:
            st.title('Verify Signature')
            st.markdown(
                '#### Check if a document was signed by a specific person <br>',
                unsafe_allow_html=True
            )

            st.file_uploader(
                'Upload a document', 
                type=['pdf', 'docx', 'txt'], 
                key='verify_signature_document'
            )

            st.text_input(
                'Signature (hex)',
                key='verify_signature_signature'
            )

            st.selectbox(
                'Select a user',
                options=get_usernames(),
                key='verify_signature_user'
            )

            if st.button('Verify Signature', use_container_width=True, type='primary'):
                if not st.session_state.verify_signature_document:
                    st.error('Please upload a document')
                elif not st.session_state.verify_signature_signature:
                    st.error('Please input a signature')
                elif not st.session_state.verify_signature_user:
                    st.error('Please select a user')
                else:
                    # Get current public key and signature
                    signer_username = st.session_state.verify_signature_user
                    signer_public_key = get_public_key(signer_username)
                    signature_hex = st.session_state.verify_signature_signature
                    
                    # Read file buffers
                    document = st.session_state.verify_signature_document.read()

                    # Get the according digital signature algorithm
                    if signer_public_key.key_algorithm == 'rsa':
                        digital_signature = RSA()
                    elif signer_public_key.key_algorithm == 'ecdsa':
                        digital_signature = ECDSA()
                    
                    # Sign the document
                    signature_verified = digital_signature.verify_signature(
                        public_pem_hex=signer_public_key.public_pem_hex,
                        document=document,
                        signature_hex=signature_hex
                    )

                    if not signature_verified:
                        # Check if the signature is from a legacy public key
                        legacy_public_keys = get_legacy_public_keys(signer_username)

                        for legacy_public_key in legacy_public_keys:
                            # Get the according digital signature algorithm
                            if legacy_public_key.key_algorithm == 'rsa':
                                digital_signature = RSA()
                            elif legacy_public_key.key_algorithm == 'ecdsa':
                                digital_signature = ECDSA()

                            signature_verified = digital_signature.verify_signature(
                                public_pem_hex=legacy_public_key.public_pem_hex,
                                document=document,
                                signature_hex=signature_hex
                            )
                            
                            # If the signature is verified, break the loop
                            if signature_verified:
                                break

                    if signature_verified:
                        st.success(f'Document was signed by {signer_username}!')
                    else:
                        st.info(f'Document was not signed by {signer_username}!')

        with settings:
            st.title('Settings')

            rsa_regen_btn = st.button('Regenerate RSA Keys', type='secondary')
            ecdsa_regen_btn = st.button('Regenerate ECDSA Keys', type='secondary')
            
            if rsa_regen_btn:
                st.session_state.key_algorithm = 'rsa'
            elif ecdsa_regen_btn:
                st.session_state.key_algorithm = 'ecdsa'
            else:
                st.stop()

            st.session_state.current_page = 'download_key'
            generate_keys()
            st.rerun()