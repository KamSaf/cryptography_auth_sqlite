import sqlite3
from utils.utils import create_table
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
            email: str => user email
            password_plain :str => user password
        """
        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            user_data = cursor.execute(f"SELECT password_hash, salt FROM user WHERE email='{email}'").fetchone()
            conn.close()
            dk = pbkdf2_hmac(
                hash_name='sha256',
                password=password_plain.encode(),
                salt=user_data[1].encode(),
                iterations=Auth.HASH_ITERATIONS
            )
            if user_data:
                return user_data[0] == dk.hex()
            return False
        except Exception as e:
            raise e

    def save_user(self, email: str, password_plain: str, password_confirm: str) -> bool:
        """
            Function saving user data to the database using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            -----------------------------------------
            email: str => user email
            password_plain :str => user password
            password_confirm: str => user password confirmation

        """
        assert password_confirm == password_plain
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
            return True
        except Exception as e:
            raise e

    def change_password(self, email: str, new_password_plain: str, new_password_confirm: str) -> bool:
        """
            Function for changing user password in the SQLite database and generating new salt
            using pbkdf2_hmac function and SHA256 algorithm

            Parameters:
            -----------------------------------------
            email: str => user email
            new_password_plain: str => new password to be saved to the database
            new_password_confirm: str => new password confirmation
        """
        assert new_password_plain == new_password_confirm
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
                {'new_password_hash': new_password_hash, 'new_salt': new_salt, 'email': email}
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            raise e


if __name__ == "__main__":
    pass
