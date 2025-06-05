from dotenv import load_dotenv
load_dotenv()

import os
import time
import streamlit as st
from streamlit_cookies_controller import CookieController
from signing.digital_signature import SUPPORTED_KEY_ALGORITHMS
from db.auth import (
    set_username,
    is_valid_username,
    get_username,
    get_all_usernames, 
    sign_in, 
    refresh_session,
    sign_out, 
    exchange_code_for_session
)
from db.signed_documents import save_signature, get_signatures, SignedDocument
from db.public_keys import (
    get_user_keys,
    add_public_key,
    rename_public_key,
    deactivate_public_key,
    PublicKey
)

controller = CookieController()

# Define re-usable logic within the app
def reload_user_keys():
    st.session_state.user_keys = get_user_keys(user_id=st.session_state.user_id)

def reload_user_signatures():
    st.session_state.user_signatures = get_signatures(user_id=st.session_state.user_id)

def sign_in_process(user_id: str):
    st.session_state.user_id = user_id
                
    # Initialize user info
    st.session_state.user_keys = []
    st.session_state.user_signatures = []

    # Get the username for the user
    username = get_username(user_id)
    if username:
        st.session_state.current_page = 'home'
        st.session_state.username = username
        
        # Reload user info to get the keys and signatures
        reload_user_keys()
        reload_user_signatures()
    else:    
        st.session_state.current_page = 'set_username'
        st.session_state.username = ''

    st.rerun()

def generate_keys():
    st.session_state.encryption_keys = (
        SUPPORTED_KEY_ALGORITHMS[st.session_state.key_algorithm]().generate_keys()
    )

def render_signature_info(signed_document: SignedDocument):
    with st.container(border=True):
        st.markdown(
            f"<div style='text-align: right;'> <span style='color:gray'>{signed_document.signed_at_date}</span></div>",
            unsafe_allow_html=True
        )
        st.markdown(f'### {signed_document.document_name}')
        st.markdown(f'**Document Hash:** {signed_document.document_hash_hex}')
        st.markdown(f'**Signature:** {signed_document.signature_hex}')

def render_key_details(public_key: PublicKey):
    with st.expander(f'Key "{public_key.name}" Details'):
        expired_str = f'**Expired at:** {public_key.expired_at_date}' if not public_key.is_active else ''
        
        st.markdown(
            f'**Key:** {public_key.public_pem_hex}<br>'
            f'**Algorithm:** {public_key.key_algorithm}<br>'
            f'**Created at:** {public_key.created_at_date}<br>' +
            expired_str,
            unsafe_allow_html=True
        )

# Initialize the current page at authentication
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'try_cookies'

match st.session_state.current_page:
    case 'try_cookies':
        if refresh_token := controller.get('refresh_token'):
            try:
                user_id = refresh_session(refresh_token)
                if user_id: sign_in_process(user_id)
            except Exception as e:
                controller.remove('refresh_token')
        
        # If there are no cookies, they are still loading
        elif controller.getAll().keys():
            st.session_state.current_page = 'authentication'
            st.rerun()

    case 'authentication':
        st.session_state.redirect_url = None
        st.markdown(
            """
            <style>
            /* Center the button’s container and set a fixed width */
            div.stButton {
                width: 250px;       /* adjust as needed for desired button width */
                margin: 0 auto;     /* centers the container horizontally */
                margin-top: 200px; 
            }

            /* Style the button with flex so logo and text stay centered together */
            div.stButton > button {
                display: flex;
                align-items: center;
                justify-content: center;
                background-color: #ffffff;
                color: #444444;
                border: 1px solid #dddddd;
                height: 80px;       /* keep the same vertical height */
                width: 100%;        /* fill the 320px container */
                font-size: 22px;
                padding: 0;         /* remove extra padding */
            }

            /* Insert Google “G” logo before the button text */
            div.stButton > button::before {
                content: "";
                background-image: url('https://developers.google.com/identity/images/g-logo.png');
                background-repeat: no-repeat;
                background-size: 24px 24px;
                width: 24px;
                height: 24px;
                margin-right: 20px; /* space between logo and text */
                display: inline-block;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        # Render the single button; show a success message when clicked
        if st.button('Continue with Google'):
            st.session_state.redirect_url = sign_in()

            st.markdown(f'''
                <meta http-equiv="refresh" content="0; url={st.session_state.redirect_url}" />''', 
                unsafe_allow_html=True
            )

        if auth_code := st.query_params.get('code'):
            # Clear the auth code once its used
            st.query_params.clear()

            try:
                user_id, refresh_token = exchange_code_for_session(auth_code)
                controller.set('refresh_token', refresh_token)
                sign_in_process(user_id)
            except Exception as e:
                st.error(f'Error: {e}')

    case 'set_username':
        st.title('Set Username')
        st.markdown(
            '#### Set a username to identify yourself in the app',
            unsafe_allow_html=True
        )
        
        st.text_input(
            'Username',
            placeholder='Username',
            label_visibility='collapsed',
            key='selected_username'
        )
        
        if st.button('Set Username', use_container_width=True, type='primary'):
            if not st.session_state.selected_username:
                st.error('Please enter a username')
            elif not is_valid_username(st.session_state.selected_username):
                st.error('Username must be between 3 and 16 characters and can only contain letters, numbers, and underscores')
            else:
                try:
                    set_username(
                        user_id=st.session_state.user_id,
                        username=st.session_state.selected_username
                    )

                    st.session_state.current_page = 'home'
                    st.session_state.username = st.session_state.selected_username
                    del st.session_state.selected_username

                    st.rerun()
                except Exception as e:
                    st.error(f'Error: {e}')

    case 'home':
        st.sidebar.markdown('# Digital Signature App')

        page = st.sidebar.radio(
            'Sidebar', 
            [
                'Signature History', 
                'Sign Document', 
                'Verify Signature', 
                'Encryption Keys',
                'Logout'
            ],
            label_visibility='collapsed'
        )


        if page == 'Signature History':
            st.title('Signature History')

            st.markdown(
                f'#### All signatures made by **{st.session_state.username}**',
                unsafe_allow_html=True
            )

            if not st.session_state.user_keys:
                st.warning(
                    'You currently have no encryption keys\n\n'
                    'Go to tab "Encryption Keys / Create Key" to create a key', 
                    width='stretch'
                )
                st.stop()
            
            st.selectbox(
                'Select your encryption key',
                options=st.session_state.user_keys,
                key='selected_user_key'
            )

            key = st.session_state.user_keys[st.session_state.selected_user_key]
            render_key_details(key)

            signed_documents = [
                sig for sig in get_signatures(user_id=st.session_state.user_id)
                if sig.key_id == key.id
            ]

            if not signed_documents:
                st.info('No signatures found for this user yet. Start signing documents to see them here!')
            else:
                for signed_document in signed_documents:
                    render_signature_info(signed_document)


        elif page == 'Sign Document':
            st.title('Sign Document')
            st.markdown(
                '#### Use your private key to get a hexadecimal signature <br>',
                unsafe_allow_html=True
            )

            user_keys = st.session_state.user_keys

            if not any(
                user_keys[key_name].is_active
                for key_name in user_keys
            ):
                st.warning(
                    'You currently have no active encryption keys\n\n'
                    'Go to tab "Encryption Keys / Create Key" to create a key', 
                    width='stretch'
                )
                st.stop()

            st.file_uploader(
                'Upload a document', 
                type=['pdf', 'docx', 'txt'], 
                key='sign_document_file'
            )

            st.selectbox(
                'Select key',
                options=[
                    key_name 
                    for key_name in user_keys 
                    if user_keys[key_name].is_active
                ],
                key='sign_document_key_name'
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
                elif not st.session_state.sign_document_key_name:
                    st.error('Please select your encryption key')
                else:
                    try:
                        # Get the current public key
                        public_key = st.session_state.user_keys[st.session_state.sign_document_key_name]
                        
                        # Read file buffers
                        document = st.session_state.sign_document_file.read()
                        private_pem = st.session_state.sign_document_private_key.read()
                        
                        # Get the according digital signature algorithm
                        digital_signature = SUPPORTED_KEY_ALGORITHMS[public_key.key_algorithm]()
                        
                        # Sign the document
                        signature_data = digital_signature.sign_document(
                            private_pem=private_pem,
                            document=document
                        )

                        # Save the signature to the database
                        save_signature(
                            document_name=st.session_state.sign_document_file.name,
                            document_hash_hex=signature_data.document_hash_hex,
                            signature_hex=signature_data.signature_hex,
                            key_id=public_key.id
                        )

                        st.success('Document signed successfully!')
                    except Exception as e:
                        st.error(f'Error: {e}')

        elif page == 'Verify Signature':
            if 'all_usernames' not in st.session_state:
                st.session_state.all_usernames = get_all_usernames()

            st.title('Verify Signature')
            st.markdown(
                '#### Check if a document was signed by a specific user <br>',
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
                options=st.session_state.all_usernames,
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
                    signer_keys = get_user_keys(
                        user_id=st.session_state.all_usernames[signer_username]
                    )
                    signature_hex = st.session_state.verify_signature_signature
                    
                    # Read file buffers
                    document = st.session_state.verify_signature_document.read()
                    signature_verified = False

                    for key in signer_keys.values():
                        digital_signature = SUPPORTED_KEY_ALGORITHMS[key.key_algorithm]()
                        
                        signature_verified = digital_signature.verify_signature(
                            public_pem_hex=key.public_pem_hex,
                            document=document,
                            signature_hex=signature_hex
                        )

                        if signature_verified:
                            break

                    if signature_verified:
                        st.success(f'Document was signed by {signer_username}!')
                    else:
                        st.info(f'Document was not signed by {signer_username}!')

        elif page == 'Encryption Keys':
            st.title('Encryption Keys')

            create_key, manage_keys = st.tabs(['Create Key', 'Manage Keys'])

            with create_key:
                st.markdown(
                    '#### Create a new encryption key to sign documents <br>',
                    unsafe_allow_html=True
                )

                st.text_input(
                    'Key name',
                    placeholder='Key name',
                    label_visibility='collapsed',
                    key='selected_key_name'
                )

                st.selectbox(
                    'Select a key algorithm',
                    options=SUPPORTED_KEY_ALGORITHMS,
                    key='selected_key_algorithm'
                )
                
                st.session_state.key_name = st.session_state.selected_key_name
                st.session_state.key_algorithm = st.session_state.selected_key_algorithm


                if st.button(
                    f'Generate {st.session_state.key_algorithm} Keys', 
                    use_container_width=True,
                    type='primary'
                ):
                    if not st.session_state.key_name:
                        st.error('Assign a name to the key')
                    elif not st.session_state.selected_key_algorithm:
                        st.error('Select a key generation algorithm')
                    else:
                        st.session_state.current_page = 'download_key'
                        generate_keys()
                        st.rerun()
            
            with manage_keys:
                st.markdown(
                    '#### Edit or deactivate active encryption keys <br>',
                    unsafe_allow_html=True
                )
                user_keys = st.session_state.user_keys

                if not any(
                    user_keys[key_name].is_active
                    for key_name in user_keys
                ):
                    st.warning(
                        'You currently have no active encryption keys\n\n'
                        'Go to tab "Encryption Keys / Create Key" to create a key', 
                        width='stretch'
                    )
                    st.stop()

                st.selectbox(
                    'Select an encryption key',
                    options=[
                        key_name 
                        for key_name in user_keys 
                        if user_keys[key_name].is_active
                    ],
                    key='selected_user_key'
                )

                st.text_input(
                    'New key name',
                    placeholder='New key name',
                    label_visibility='collapsed',
                    key='selected_new_key_name'
                )

                key = st.session_state.user_keys[st.session_state.selected_user_key]

                c1, c2 = st.columns([10, 10])
                with c1: 
                    rename_btn = st.button('Rename', use_container_width=True)
                with c2: 
                    deactivate_btn = st.button(
                        'Deactivate', 
                        help='Deactivate the key to prevent it from being used to sign documents',
                        use_container_width=True,
                        type='primary'
                    )
                
                if rename_btn:
                    if not st.session_state.selected_new_key_name:
                        st.error('Please select a new name for the key')
                    else:
                        try:
                            rename_public_key(
                                user_id=st.session_state.user_id,
                                new_key_name=st.session_state.selected_new_key_name,
                                key_id=key.id
                            )

                            del st.session_state.selected_new_key_name
                            st.success('Key renamed succesfully!')
                            reload_user_keys()
                            st.session_state.selected_new_key_name = ''
                        
                            # Wait for re-render
                            time.sleep(2.5)
                            st.rerun()
                        except Exception as e:
                            st.error(f'Error: {e}')
                        

                elif deactivate_btn:
                    try:
                        deactivate_public_key(
                            user_id=st.session_state.user_id,
                            key_id=key.id,
                            key_name=key.name
                        )
                    
                        del st.session_state.selected_new_key_name
                        st.success('Key deactivated succesfully!')
                        reload_user_keys()
                        
                        # Wait for re-render
                        time.sleep(2.5)
                        st.rerun()
                    except Exception as e:
                        st.error(f'Error: {e}')
            
        elif page == 'Logout':
            try:
                sign_out()
                st.session_state.current_page = 'authentication'
                controller.remove('refresh_token')

                # Reset user info
                st.session_state.user_id = None
                st.session_state.username = None
                st.session_state.user_keys = []
                st.session_state.user_signatures = []
                st.rerun()
            except Exception as e:
                st.error(f'Error: {e}')
        
    case 'download_key':
        st.markdown(
            f'''
            # ⚠️ Save Your Private {st.session_state.key_algorithm} Key Now
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
        col = st.columns([5, 5, 5])[1]

        with col:
            st.download_button(
                label='Download Private Key',
                data=st.session_state.encryption_keys.private_pem,
                file_name=f'pk_{st.session_state.key_name.lower().replace(' ', '_')}.cer',
                mime='application/x-cer-file',
                type='primary',
                use_container_width=True
            )
            
            c1, c2 = st.columns([10, 10])
            with c1:
                cancel_btn = st.button('Abort', use_container_width=True)
            with c2:
                continue_btn = st.button(
                    'Save', 
                    use_container_width=True,
                    help='Save the public key to your account after downloading private key'
                )
        
        if continue_btn:
            add_public_key(
                user_id=st.session_state.user_id,
                public_pem_hex=st.session_state.encryption_keys.public_pem_hex,
                key_name=st.session_state.key_name,
                key_algorithm=st.session_state.key_algorithm
            )

            # Reload user info to get the new keys
            reload_user_keys()
            st.session_state.current_page = 'home'
            del st.session_state.encryption_keys
            st.rerun()
        
        if cancel_btn:
            st.session_state.current_page = 'home'
            del st.session_state.encryption_keys
            st.rerun()