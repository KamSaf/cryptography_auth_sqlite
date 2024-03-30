from auth_pbkdf2_hmac import Auth
import sqlite3
import os
import pytest
from hashlib import pbkdf2_hmac


class TestAuthPBKDF2:
    @pytest.fixture(scope="class")
    def temporary_database_path(self):
        DATABASE_PATH = 'testing_database.db'
        yield DATABASE_PATH
        os.remove(DATABASE_PATH)

    def test_save_user_pbkdf2_hmac(self, temporary_database_path):
        TEST_EMAIL = 'email@domain.com'
        TEST_PLAIN_PASSWORD = 'test_password'
        auth = Auth(database_path=temporary_database_path)
        auth.save_user(email=TEST_EMAIL, password_plain=TEST_PLAIN_PASSWORD, password_confirm=TEST_PLAIN_PASSWORD)
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        db_data = cursor.execute(
            "SELECT * FROM user WHERE email=:email", {'email': TEST_EMAIL}
        ).fetchone()
        cursor.execute("DELETE FROM user WHERE email=:email", {'email': TEST_EMAIL})
        connection.close()
        assert db_data
        assert len(db_data) == 3
        print(db_data)
        dk = pbkdf2_hmac(
            hash_name='sha256',
            password=TEST_PLAIN_PASSWORD.encode(),
            salt=db_data[2].encode(),
            iterations=Auth.HASH_ITERATIONS
        )
        assert dk.hex() == db_data[1]

    def test_authenticate_pbkdf2_hmac(self, temporary_database_path):
        TEST_HASH = 'b3a81e89b5e6d6cbb5bd941d72b9fff5f7d80c5d35dcf84d350063e60342afad'
        TEST_SALT = '2afe90cf5279ce08d15befa23fc45c0fd057d95f84e5b9acdb60ade2fd8b92bd'
        TEST_PLAIN_PASSWORD = 'test_password'
        TEST_EMAIL = 'user_06@domain.com'
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt text) """)
        cursor.execute(
            "INSERT INTO user VALUES (:email, :password_hash, :salt)",
            {'email': TEST_EMAIL, 'password_hash': TEST_HASH, 'salt': TEST_SALT}
        )
        connection.commit()
        auth = Auth(database_path=temporary_database_path)
        function_result = auth.authenticate(email=TEST_EMAIL, password_plain=TEST_PLAIN_PASSWORD)
        cursor.execute("DELETE FROM user WHERE email=:email", {'email': TEST_EMAIL})
        connection.close()
        assert function_result is True

    def test_authenticate_pbkdf2_hmac_wrong_email(self, temporary_database_path):
        TEST_HASH = 'b3a81e89b5e6d6cbb5bd941d72b9fff5f7d80c5d35dcf84d350063e60342afad'
        TEST_SALT = '2afe90cf5279ce08d15befa23fc45c0fd057d95f84e5b9acdb60ade2fd8b92bd'
        TEST_PLAIN_PASSWORD = 'test_password'
        TEST_EMAIL = 'user_07@domain.com'
        TEST_WRONG_EMAIL = 'wrong_email@domain.com'
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt text) """)
        cursor.execute(
            "INSERT INTO user VALUES (:email, :password_hash, :salt)",
            {'email': TEST_EMAIL, 'password_hash': TEST_HASH, 'salt': TEST_SALT}
        )
        connection.commit()
        auth = Auth(database_path=temporary_database_path)
        function_result = auth.authenticate(email=TEST_WRONG_EMAIL, password_plain=TEST_PLAIN_PASSWORD)
        cursor.execute("DELETE FROM user WHERE email=:email", {'email': TEST_EMAIL})
        connection.close()
        assert function_result is False

    def test_authenticate_pbkdf2_hmac_wrong_password(self, temporary_database_path):
        TEST_HASH = 'b3a81e89b5e6d6cbb5bd941d72b9fff5f7d80c5d35dcf84d350063e60342afad'
        TEST_SALT = '2afe90cf5279ce08d15befa23fc45c0fd057d95f84e5b9acdb60ade2fd8b92bd'
        TEST_EMAIL = 'user_09@domain.com'
        TEST_WRONG_PLAIN_PASSWORD = 'wrong_password'
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt text) """)

        cursor.execute(
            "INSERT INTO user VALUES (:email, :password_hash, :salt)",
            {'email': TEST_EMAIL, 'password_hash': TEST_HASH, 'salt': TEST_SALT}
        )
        connection.commit()
        auth = Auth(database_path=temporary_database_path)
        function_result = auth.authenticate(email=TEST_EMAIL, password_plain=TEST_WRONG_PLAIN_PASSWORD)
        cursor.execute("DELETE FROM user WHERE email=:email", {'email': TEST_EMAIL})
        connection.close()
        assert function_result is False

    def test_change_password_pbkdf2_hmac(self, temporary_database_path):
        TEST_HASH = 'b3a81e89b5e6d6cbb5bd941d72b9fff5f7d80c5d35dcf84d350063e60342afad'
        TEST_SALT = '2afe90cf5279ce08d15befa23fc45c0fd057d95f84e5b9acdb60ade2fd8b92bd'
        TEST_EMAIL = 'user_10@domain.com'
        TEST_NEW_PASSWORD = 'new_password'
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt text) """)
        cursor.execute(
            "INSERT INTO user VALUES (:email, :password_hash, :salt)",
            {'email': TEST_EMAIL, 'password_hash': TEST_HASH, 'salt': TEST_SALT}
        )
        connection.commit()
        auth = Auth(database_path=temporary_database_path)
        auth.change_password(email=TEST_EMAIL, password_plain=TEST_NEW_PASSWORD, password_confirm=TEST_NEW_PASSWORD)
        db_data = cursor.execute(
            "SELECT * FROM user WHERE email=:email", {'email': TEST_EMAIL}
        ).fetchone()
        connection.close()
        assert db_data is not None
        assert db_data[1] != TEST_HASH and db_data[2] != TEST_SALT

        dk = pbkdf2_hmac(
            hash_name='sha256',
            password=TEST_NEW_PASSWORD.encode(),
            salt=db_data[2].encode(),
            iterations=Auth.HASH_ITERATIONS
        )
        assert dk.hex() == db_data[1]
