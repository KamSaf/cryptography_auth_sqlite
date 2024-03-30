import sqlite3
from utils.utils import create_table
from hashlib import pbkdf2_hmac
from os import urandom
import binascii
import utils.exception_types as AuthExceptions


class Auth:
    DEFAULT_DATABASE_PATH = "database.db"
    HASH_ITERATIONS = 500000
    MAX_LENGTH = 200

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path

    def authenticate(self, email: str, password_plain: str) -> bool:
        """
            Function for authenticating user credentials using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            --------------------------------------------
            email: str => user email (max. 200 characters)
            password_plain :str => user password (max. 200 characters)
        """
        if type(email) is not str or type(password_plain) is not str:
            raise AuthExceptions.InvalidDataType(AuthExceptions.InvalidDataType.message)
        if len(email) > Auth.MAX_LENGTH:
            raise AuthExceptions.EmailTooLong(AuthExceptions.EmailTooLong.message)
        if len(password_plain) > Auth.MAX_LENGTH:
            raise AuthExceptions.PasswordTooLong(AuthExceptions.PasswordTooLong.message)

        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            user_data = cursor.execute(f"SELECT password_hash, salt FROM user WHERE email='{email}'").fetchone()
            conn.close()
            if user_data:
                dk = pbkdf2_hmac(
                    hash_name='sha256',
                    password=password_plain.encode(),
                    salt=user_data[1].encode(),
                    iterations=Auth.HASH_ITERATIONS
                )
                return user_data[0] == dk.hex()
            return False
        except Exception as e:
            raise e

    def save_user(self, email: str, password_plain: str, password_confirm: str) -> None:
        """
            Function saving user data to the database using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            -----------------------------------------
            email: str => user email (max. 200 characters)
            password_plain :str => user password (max. 200 characters)
            password_confirm: str => user password confirmation (max. 200 characters)

        """
        if type(email) is not str or type(password_plain) is not str or type(password_confirm) is not str:
            raise AuthExceptions.InvalidDataType(AuthExceptions.InvalidDataType.message)
        if len(password_plain) > Auth.MAX_LENGTH:
            raise AuthExceptions.PasswordTooLong(AuthExceptions.PasswordTooLong.message)
        if len(email) > Auth.MAX_LENGTH:
            raise AuthExceptions.EmailTooLong(AuthExceptions.EmailTooLong.message)
        if password_confirm != password_plain:
            raise AuthExceptions.PasswordConfirmationFailed(AuthExceptions.PasswordConfirmationFailed.message)

        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            users_with_given_email = cursor.execute(f"SELECT * FROM user WHERE email='{email}'").fetchall()
            assert not users_with_given_email

            salt = binascii.hexlify(urandom(32))
            dk = pbkdf2_hmac(
                hash_name='sha256',
                password=password_plain.encode(),
                salt=salt,
                iterations=Auth.HASH_ITERATIONS
            )
            password_hash = dk.hex()
            cursor.execute(
                "INSERT INTO user VALUES (:email, :password_hash, :salt)",
                {'email': email, 'password_hash': password_hash, 'salt': salt.decode()}
            )
            conn.commit()
            conn.close()
        except Exception as e:
            raise e

    def change_password(self, email: str, new_password_plain: str, new_password_confirm: str) -> None:
        """
            Function for changing user password in the SQLite database and generating new salt
            using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            -----------------------------------------
            email: str => user email (max. 200 characters)
            new_password_plain: str => new password to be saved to the database (max. 200 characters)
            new_password_confirm: str => new password confirmation
        """
        if type(email) is not str or type(new_password_plain) is not str or type(new_password_confirm) is not str:
            raise AuthExceptions.InvalidDataType(AuthExceptions.InvalidDataType.message)
        if len(new_password_plain) > 200:
            raise AuthExceptions.PasswordTooLong(AuthExceptions.PasswordTooLong.message)
        if new_password_plain != new_password_confirm:
            raise AuthExceptions.PasswordConfirmationFailed(AuthExceptions.PasswordConfirmationFailed.message)

        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            new_salt = binascii.hexlify(urandom(32))
            dk = pbkdf2_hmac(
                hash_name='sha256',
                password=new_password_plain.encode(),
                salt=new_salt,
                iterations=Auth.HASH_ITERATIONS
            )
            new_password_hash = dk.hex()
            cursor.execute(
                "UPDATE user SET password_hash = :new_password_hash, salt = :new_salt WHERE email = :email",
                {'new_password_hash': new_password_hash, 'new_salt': new_salt.decode(), 'email': email}
            )
            conn.commit()
            conn.close()
        except Exception as e:
            raise e


if __name__ == "__main__":
    auth = Auth()
    auth.save_user(email='user_06@domain.com', password_plain='test_password', password_confirm='test_password')
    pass
