from utils.utils import create_table, generate_salt, hash_password, check_hash
import sqlite3
import os
import pytest
import hashlib


class TestUtils:
    @pytest.fixture(scope="module")
    def temporary_connection(self):
        DATABASE_PATH = 'testing_database.db'
        _connection = sqlite3.connect(DATABASE_PATH)
        yield _connection
        _connection.close()
        os.remove(DATABASE_PATH)

    def test_create_table(self, temporary_connection):
        create_table(temporary_connection)
        cursor = temporary_connection.cursor()
        table_name = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=:name",
            {'name': 'user'}
        ).fetchone()
        assert table_name is not None

    def test_generate_salt(self):
        SALT_LENGTH = 32
        ASCII_CHARACTERS_BOUNDS = [33, 127]

        salt = generate_salt()
        assert len(salt) == SALT_LENGTH
        for char in salt:
            assert ASCII_CHARACTERS_BOUNDS[0] <= ord(char) <= ASCII_CHARACTERS_BOUNDS[1]

    def test_hash_password(self):
        TEST_PLAIN_TEXT = 'test_password'
        function_result = hash_password(password_plain=TEST_PLAIN_TEXT)
        assert type(function_result) is tuple
        assert len(function_result) == 2
        assert type(function_result[0]) is str and type(function_result[1]) is str

        h = hashlib.sha256()
        h.update((TEST_PLAIN_TEXT + function_result[1]).encode())
        assert h.hexdigest() == function_result[0]

    def test_check_hash(self):
        TEST_HASH = 'a449a179fe0d070c10f9af3fe84eac9befabbf669553c6813ccb93184714592c'
        TEST_SALT = 'Hh0kfc;UF5Z*ox%~JWu6&VOjw/2.J~Wt'
        TEST_PLAIN_TEXT = 'test_password'

        assert check_hash(password_hash=TEST_HASH, password_plain=TEST_PLAIN_TEXT, salt=TEST_SALT)
