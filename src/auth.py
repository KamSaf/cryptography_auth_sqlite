import sqlite3
from utils.utils import create_table, hash_password, check_hash, validate_data


class Auth:
    DEFAULT_DATABASE_PATH = "database.db"

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path

    def authenticate(self, email: str, password_plain: str) -> bool:
        """
            Function for authenticating user credentials using SHA256 algorithm

            Parameters:
            --------------------------------------------
            email: str => user email (max. 200 characters long)
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
                return check_hash(password_hash=user_data[0], password_plain=password_plain, salt=user_data[1])
            return False
        except Exception as e:
            raise e

    def save_user(self, email: str, password_plain: str, password_confirm: str) -> None:
        """
            Function saving user data to the database using SHA256 algorithm

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
            password_hash, salt = hash_password(password_plain=password_plain)
            cursor = conn.cursor()
            users_with_given_email = cursor.execute(f"SELECT * FROM user WHERE email='{email}'").fetchall()
            if users_with_given_email:
                raise Exception("User with this email already exists")

            cursor.execute(
                "INSERT INTO user VALUES (:email, :password_hash, :salt)",
                {'email': email, 'password_hash': password_hash, 'salt': salt}
            )
            conn.commit()
            conn.close()
        except Exception as e:
            raise e

    def change_password(self, email: str, password_plain: str, password_confirm: str) -> None:
        """
            Function for changing user password in the SQLite database and generating new salt using SHA256 algorithm.

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
            new_password_hash, new_salt = hash_password(password_plain=password_plain)
            cursor.execute(
                'UPDATE user SET password_hash = :new_password_hash, salt = :new_salt WHERE email = :email',
                {'new_password_hash': new_password_hash, 'new_salt': new_salt, 'email': email}
            )
            conn.commit()
            conn.close()
        except Exception as e:
            raise e


if __name__ == "__main__":
    pass
