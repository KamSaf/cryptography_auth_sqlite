import sqlite3
from utils.utils import create_table, validate_data
from hashlib import pbkdf2_hmac
from os import urandom
import binascii


class Auth:
    DEFAULT_DATABASE_PATH = "database.db"
    HASH_ITERATIONS = 500000

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path

    def authenticate(self, email: str, password_plain: str) -> bool:
        """
            Function for authenticating user credentials using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            --------------------------------------------
            email: str => user email (max. 200 characters)
            password_plain :str => user password (8 - 200 characters long)
        """
        validate_data(email=email, password_plain=password_plain)
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
            password_plain :str => user password (8 - 200 characters long)
            password_confirm: str => user password confirmation (max. 200 characters long)

        """
        validate_data(email=email, password_plain=password_plain, password_confirm=password_confirm)
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

    def change_password(self, email: str, password_plain: str, password_confirm: str) -> None:
        """
            Function for changing user password in the SQLite database and generating new salt
            using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            -----------------------------------------
            email: str => user email (max. 200 characters)
            password_plain: str => new password to be saved to the database (8 - 200 characters long)
            password_confirm: str => new password confirmation (max. 200 characters long)
        """
        validate_data(email=email, password_plain=password_plain, password_confirm=password_confirm)
        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            new_salt = binascii.hexlify(urandom(32))
            dk = pbkdf2_hmac(
                hash_name='sha256',
                password=password_plain.encode(),
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
    pass
