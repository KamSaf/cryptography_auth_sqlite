## Description

Python library for authenticating and saving user data to SQLite database. Created for Cryptography classes.


## How to install (for Linux, macOS)

Create Python virtual environment, for example:

        virtualenv venv

Activate virtual environment:

        source venv/bin/activate

Run command for installing requirements when in ```src/``` directory

    pip install -r requirements.txt


## Functionalities

- function for saving user to database,
- function for authenticating user,
- function for changing user password,

- function for saving user to database using pbkdf2_hmac,
- function for authenticating user using pbkdf2_hmac,
- function for changing user password using pbkdf2_hmac,

## Used packages

- pytest


## Testing

While in src directory, run:

    python run_tests.py
    
