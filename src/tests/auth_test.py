from auth import Auth
import sqlite3
import os
import pytest
import hashlib


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
        auth.save_user(email=TEST_EMAIL, password_plain=TEST_PLAIN_PASSWORD, password_confirm=TEST_PLAIN_PASSWORD)
        connection = sqlite3.connect(temporary_database_path)
        cursor = connection.cursor()
        db_data = cursor.execute(
            "SELECT * FROM user WHERE email=:email", {'email': TEST_EMAIL}
        ).fetchone()
        cursor.execute("DELETE FROM user WHERE email=:email", {'email': TEST_EMAIL})
        connection.close()
        assert db_data
        assert len(db_data) == 3 # SAVE USER ALE ZŁY ADRES ALBO HASŁO

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

    def test_change_password(self, temporary_database_path):
        TEST_HASH = '5997339435395abe0bedb8bc1bd257847b0ad9cb691700a308cb01f8b89ea308'
        TEST_SALT = 'vh+v?|HDjnCVggV-X0s,R3Ve<*ga@UW0?'
        TEST_EMAIL = 'user_04@domain.com'
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
        auth.change_password(email=TEST_EMAIL, new_password_plain=TEST_NEW_PASSWORD, new_password_confirm=TEST_NEW_PASSWORD)
        db_data = cursor.execute(
            "SELECT * FROM user WHERE email=:email", {'email': TEST_EMAIL}
        ).fetchone()
        connection.close()
        assert db_data is not None
        assert db_data[1] != TEST_HASH and db_data[2] != TEST_SALT
        h = hashlib.sha256()
        h.update((TEST_NEW_PASSWORD + db_data[2]).encode())
        assert h.hexdigest() == db_data[1]
