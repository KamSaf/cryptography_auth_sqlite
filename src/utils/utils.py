from sqlite3 import Connection
import random
import hashlib


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
	ASCII_CHARACTERS_BOUNDS = [33, 128]

	salt = []
	for _ in range(32):
		x = random.randint(	ASCII_CHARACTERS_BOUNDS[0], ASCII_CHARACTERS_BOUNDS[1])
		salt.append(chr(x))
	random.shuffle(salt)
	return ''.join(salt) 


def hash_password(password_plain: str, salt: str = '') -> tuple[str, str]:
	"""
		Function hashing password using SHA256 algorithm with given or randomly generated 32 characters long salt

		Parameters:
		---------------------------------------
		password_plain: str => user plain text password to be hashed
		salt: str (optional) => salt which is used to hash password (for checking hash)
	"""
	if not salt:
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



if __name__ ==  "__main__":
	pass
