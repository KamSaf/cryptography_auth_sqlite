import sqlite3
from utils.utils import create_table, hash_password, check_hash


class Auth:
    DEFAULT_DATABASE_PATH = "database.db"

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path

    def authenticate(self, email: str, password_plain: str) -> bool:
        """
            Function for authenticating user credentials using SHA256 algorithm

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
            if user_data:
                return check_hash(password_hash=user_data[0], password_plain=password_plain, salt=user_data[1])
            return False
        except Exception as e:
            raise e

    def save_user(self, email: str, password_plain: str, password_confirm: str) -> bool:
        """
            Function saving user data to the database using SHA256 algorithm

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
            password_hash, salt = hash_password(password_plain=password_plain)
            cursor = conn.cursor()
            users_with_given_email = cursor.execute(f"SELECT * FROM user WHERE email='{email}'").fetchall()
            assert not users_with_given_email

            cursor.execute(
                "INSERT INTO user VALUES (:email, :password_hash, :salt)",
                {'email': email, 'password_hash': password_hash, 'salt': salt}
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            raise e

    def change_password(self, email: str, new_password_plain: str, new_password_confirm: str) -> bool:
        """
            Function for changing user password in the SQLite database and generating new salt using SHA256 algorithm.

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
            new_password_hash, new_salt = hash_password(password_plain=new_password_plain)
            cursor.execute(
                'UPDATE user SET password_hash = :new_password_hash, salt = :new_salt WHERE email = :email',
                {'new_password_hash': new_password_hash, 'new_salt': new_salt, 'email': email}
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            raise e


if __name__ == "__main__":
    pass
