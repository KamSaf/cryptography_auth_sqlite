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
	cursor.execute("""CREATE TABLE IF NOT EXISTS user(email text, password_hash text, salt real) """)
	print('created')
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
	for i in range(32):
		x = random.randint(	ASCII_CHARACTERS_BOUNDS[0], ASCII_CHARACTERS_BOUNDS[1])
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

if __name__ ==  "__main__":
	pass
