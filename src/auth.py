import sqlite3
from utils.utils import create_table, hash_password, check_hash


class Auth:
    DEFAULT_DATABASE_PATH = "database.db"

    def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
        self.database_path = database_path

    def authenticate(self, email: str, password_plain: str) -> bool:
        """
            Function for authenticating user credentials

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
            if user_data and len(user_data) == 1:
                return check_hash(password_hash=user_data[0], password_plain=password_plain, salt=user_data[1])
            return False
        except Exception as e:
            print(e)
            return True

    def save_user(self, email: str, password_plain: str, password_confirm: str) -> bool:
        """
            Function saving user data to the database

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
            cursor.execute("INSERT INTO user VALUES (:email, :password_hash, :salt)", {'email': email, 'password_hash': password_hash, 'salt': salt})
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(e)
            return False

    def change_password(self, email: str, new_password_plain: str, confirm_new_password: str) -> bool:
        """
            Function for changing user password in the SQLite database

            Parameters:
            -----------------------------------------
            email: str => user email
            new_password_plain: str => new password to be saved to the database
            confirm_new_password: str => new password confirmation
        """
        assert new_password_plain == confirm_new_password
        try:
            conn = sqlite3.connect(self.database_path)
            create_table(conn=conn)
            cursor = conn.cursor()
            salt = cursor.execute(f"SELECT salt FROM user WHERE email='{email}'").fetchone()[0]
            new_password_hash = hash_password(password_plain=new_password_plain, salt=salt)[0]
            print(new_password_hash)
            cursor.execute(
                'UPDATE user SET password_hash = :password_hash WHERE email = :email',
                {'password_hash': new_password_hash, 'email': email}
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(e)
            return False


if __name__ == "__main__":
    auth = Auth()
    pass
