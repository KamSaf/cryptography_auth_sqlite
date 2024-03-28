from auth import Auth
import sqlite3
import os
import pytest

from utils.utils import hash_password


class TestAuth:
    @pytest.fixture(scope="class")
    def temporary_database_path(self):
        DATABASE_PATH = 'testing_database.db'
        yield DATABASE_PATH
        os.remove(DATABASE_PATH)

    def test_save_user(self, temporary_database_path):
        TEST_EMAIL = 'email@domain.com'
        TEST_PLAIN_PASSWORD = 'test_password'
        auth = Auth(database_path=temporary_database_path)
        function_result = auth.save_user(
            email=TEST_EMAIL,
            password_plain=TEST_PLAIN_PASSWORD,
            password_confirm=TEST_PLAIN_PASSWORD
        )
        assert function_result is True

        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        db_data = cursor.execute(
            "SELECT * FROM user WHERE email=:email", {'email': TEST_EMAIL}
        ).fetchone()
        connection.close()
        assert db_data
        assert len(db_data) == 3

    def test_authenticate(self, temporary_database_path):
        TEST_HASH = '5997339435395abe0bedb8bc1bd257847b0ad9cb691700a308cb01f8b89ea308'
        TEST_SALT = 'vh+v?|HDjnCVggV-X0s,R3Ve<*ga@UW0?'
        TEST_PLAIN_PASSWORD = 'test_password'
        TEST_EMAIL = 'user_03@domain.com'
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

    def test_authenticate_wrong_email(self, temporary_database_path):
        TEST_HASH = '5997339435395abe0bedb8bc1bd257847b0ad9cb691700a308cb01f8b89ea308'
        TEST_SALT = 'vh+v?|HDjnCVggV-X0s,R3Ve<*ga@UW0?'
        TEST_PLAIN_PASSWORD = 'test_password'
        TEST_EMAIL = 'user_04@domain.com'
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

    def test_authenticate_wrong_password(self, temporary_database_path):
        TEST_HASH = '5997339435395abe0bedb8bc1bd257847b0ad9cb691700a308cb01f8b89ea308'
        TEST_SALT = 'vh+v?|HDjnCVggV-X0s,R3Ve<*ga@UW0?'
        TEST_EMAIL = 'user_04@domain.com'
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





    # def test_create_table(self, temporary_connection):
    #     create_table(temporary_connection)
    #     cursor = temporary_connection.cursor()
    #     table_name = cursor.execute(
    #         "SELECT name FROM sqlite_master WHERE type='table' AND name=:name",
    #         {'name': 'user'}
    #     ).fetchone()
    #     assert table_name is not None

    # def test_generate_salt(self):
    #     SALT_LENGTH = 32
    #     ASCII_CHARACTERS_BOUNDS = [33, 127]

    #     salt = generate_salt()
    #     assert len(salt) == SALT_LENGTH
    #     for char in salt:
    #         assert ASCII_CHARACTERS_BOUNDS[0] <= ord(char) <= ASCII_CHARACTERS_BOUNDS[1]

    # def test_hash_password(self):
    #     TEST_PLAIN_TEXT = 'test_password'
    #     function_result = hash_password(password_plain=TEST_PLAIN_TEXT)
    #     assert type(function_result) is tuple
    #     assert len(function_result) == 2
    #     assert type(function_result[0]) is str and type(function_result[1]) is str

    #     h = hashlib.sha256()
    #     h.update((TEST_PLAIN_TEXT + function_result[1]).encode())
    #     assert h.hexdigest() == function_result[0]

    # def test_check_hash(self):
    #     TEST_HASH = 'a449a179fe0d070c10f9af3fe84eac9befabbf669553c6813ccb93184714592c'
    #     TEST_SALT = 'Hh0kfc;UF5Z*ox%~JWu6&VOjw/2.J~Wt'
    #     TEST_PLAIN_TEXT = 'test_password'

    #     assert check_hash(password_hash=TEST_HASH, password_plain=TEST_PLAIN_TEXT, salt=TEST_SALT)
