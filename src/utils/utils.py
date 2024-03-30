from sqlite3 import Connection
import random
import hashlib
import utils.exception_types as AuthExceptions


def create_table(conn: Connection) -> None:
    """
        Function creating users table in database if it doesn't exist

        Parameters
        -------------------------------------
            conn: Connection -> SQLite database connection
    """
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt text) """)
    conn.commit()


def generate_salt() -> str:
    """
        Function returning salt for hashing password

        Returns:
        --------------------------------------
        salt: str => randomly generated 32 characters long salt
    """
    ASCII_CHARACTERS_BOUNDS = [33, 127]
    SALT_DEFAULT_SIZE = 32

    salt = []
    for _ in range(SALT_DEFAULT_SIZE):
        x = random.randint(ASCII_CHARACTERS_BOUNDS[0], ASCII_CHARACTERS_BOUNDS[1])
        salt.append(chr(x))
    random.shuffle(salt)
    return ''.join(salt) 


def hash_password(password_plain: str) -> tuple[str, str]:
    """
        Function hashing password using SHA256 algorithm with randomly generated 32 characters long salt

        Parameters:
        ---------------------------------------
        password_plain: str => user plain text password to be hashed
    """
    salt = generate_salt()
    h = hashlib.sha256()
    h.update((password_plain + salt).encode())
    password_hash = h.hexdigest()
    return password_hash, salt


def check_hash(password_hash: str, password_plain: str, salt: str) -> bool:
    """
        Function checking whether given plain text passwords hash matches the one kept in database

        Parameters:
        --------------------------------------
        password_hash: str => user password hash retrieved from the database
        password_plain: str => plain text password to be verified
        salt: str => user password salt retrieved from the database
    """
    h = hashlib.sha256()
    h.update((password_plain + salt).encode())
    return password_hash == h.hexdigest()


def validate_data(email: str = '', password_plain: str = '', password_confirm: str = '') -> bool:
    """
        Function validating user data

        Parameters:
        --------------------------------------
        email: str => user email
        password_plain: str => plain text password
        password_confirmation: str => (optional) confirmation for given password
    """
    MAX_LENGTH = 200
    MIN_LENGTH = 8

    if not (email and password_plain) or (type(email) is not str or type(password_plain) is not str):
        raise AuthExceptions.InvalidDataType(AuthExceptions.InvalidDataType.message)

    if len(email) > MAX_LENGTH:
        raise AuthExceptions.ValueTooLong(AuthExceptions.ValueTooLong.message + 'email')

    if len(password_plain) > MAX_LENGTH:
        raise AuthExceptions.ValueTooLong(AuthExceptions.ValueTooLong.message + 'password')

    if len(password_plain) < MIN_LENGTH:
        raise AuthExceptions.ValueTooShort(AuthExceptions.ValueTooShort.message + 'password')

    if password_confirm and type(password_confirm) is not str:
        raise AuthExceptions.InvalidDataType(AuthExceptions.InvalidDataType.message + 'password_confirm')

    if password_confirm and len(password_confirm) > 200:
        raise AuthExceptions.ValueTooLong(AuthExceptions.ValueTooLong.message + 'password_confirm')       

    if password_confirm and password_plain != password_confirm:
        raise AuthExceptions.PasswordConfirmationFailed(AuthExceptions.PasswordConfirmationFailed.message)
    return True


if __name__ == "__main__":
    pass
