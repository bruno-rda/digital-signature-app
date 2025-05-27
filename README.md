# Digital Signature Application

A secure and user-friendly digital signature application built with Python and Streamlit. This application allows users to create, manage, and verify digital signatures using either RSA or ECDSA algorithms.

## Features

- Secure user authentication system
- Digital signature creation and verification
- Support for both RSA and ECDSA algorithms
- Signature history tracking
- Key management and rotation
- Secure private key handling

## Prerequisites

- Python 3.x
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/bruno-rda/digital-signature-app.git
cd digital-signature-app
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
streamlit run app.py
```

2. Open your web browser and navigate to the URL shown in the terminal (typically http://localhost:8501)

3. Create an account or log in to an existing one

4. Follow the on-screen instructions to:
   - Generate and download your private key
   - Sign documents
   - Verify signatures
   - View your signature history
   - Manage your settings

## Security Features

- Private keys are generated locally and never stored on the server
- Secure key storage and management
- Support for key rotation and updates
- Document hash verification
- Secure authentication system

## Project Structure

```
digital-signature-app/
├── app.py              # Main application file
├── requirements.txt    # Project dependencies
├── db/                 # Database related code
├── signing/           # Digital signature implementation
└── utils/             # Utility functions
```

## Dependencies

The application uses several key Python packages:
- Streamlit for the web interface
- Cryptography for digital signature operations
- MongoDB for data storage
- Other utility packages as listed in requirements.txt


## Security Notice

- Keep your private key secure and never share it
- The private key is only available for download once during account creation
- If you lose your private key, you'll need to generate a new one, which will invalidate all previous signatures