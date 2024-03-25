import sqlite3
from utils.utils import create_table, generate_salt, hash_password

DEFAULT_DATABASE_PATH = "../database.db"


class Auth:

	@staticmethod
	def authenticate(email: str, password_plain: str, password_confirm: str):
		"""
			Function for authenticating user credentials

			Parameters:
			--------------------------------------------
			email: str => user email
			password_plain :str => user password
			password_confirm: str => user password confirmation
		"""
		assert(password_confirm == password_plain)
		with sqlite3.connect(DEFAULT_DATABASE_PATH) as conn:
			create_table(conn=conn)
			salt = generate_salt()

			cursor = conn.cursor()
			cursor.execute("INSERT INTO user VALUES (:email, :password_hash, :salt)", {'email': email, 'password_hash': password_hash, 'salt': salt})
			conn.commit()
			conn.close()

	@staticmethod
	def save_user(email: str, password_plain: str, password_confirm: str) -> None:
		"""
			Function saving user data to the database

			Parameters:
			-----------------------------------------
			email: str => user email
			password_plain :str => user password
			password_confirm: str => user password confirmation

		"""
		assert(password_confirm == password_plain)
		with sqlite3.connect(DEFAULT_DATABASE_PATH) as conn:
			create_table(conn=conn)
			password_hash, salt = hash_password(password_plain=password_plain)
			cursor = conn.cursor()
			cursor.execute("INSERT INTO user VALUES (:email, :password_hash, :salt)", {'email': email, 'password_hash': password_hash, 'salt': salt})
			conn.commit()
			conn.close()

	@staticmethod
	def change_password():
		pass

	@staticmethod
	def remind_password():
		pass



if __name__ ==  "__main__":
	save_user(email='email@domain.com', password_plain='password', password_confirm='password')
	pass
