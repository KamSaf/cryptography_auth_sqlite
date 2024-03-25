import sqlite3
from utils.utils import create_table, hash_password, check_hash



class Auth:
	"""

	"""

	DEFAULT_DATABASE_PATH = "database.db"

	def __init__(self, database_path: str = DEFAULT_DATABASE_PATH):
		self.database_path = database_path


	def authenticate(self, email: str, password_plain: str):
		"""
			Function for authenticating user credentials

			Parameters:
			--------------------------------------------
			email: str => user email
			password_plain :str => user password
		"""
		conn = sqlite3.connect(self.database_path)
		create_table(conn=conn)
		cursor = conn.cursor()
		user_data = cursor.execute(f"SELECT password_hash, salt FROM user WHERE email='{email}'").fetchone()
		conn.close()
		return check_hash(password_hash=user_data[0], password_plain=password_plain, salt=user_data[1])


	def save_user(self, email: str, password_plain: str, password_confirm: str) -> None:
		"""
			Function saving user data to the database

			Parameters:
			-----------------------------------------
			email: str => user email
			password_plain :str => user password
			password_confirm: str => user password confirmation

		"""
		assert(password_confirm == password_plain)
		conn = sqlite3.connect(self.database_path)
		create_table(conn=conn)
		password_hash, salt = hash_password(password_plain=password_plain)
		cursor = conn.cursor()
		cursor.execute("INSERT INTO user VALUES (:email, :password_hash, :salt)", {'email': email, 'password_hash': password_hash, 'salt': salt})
		conn.commit()
		conn.close()


	def change_password(self):
		pass


	def remind_password(self):
		pass



if __name__ ==  "__main__":
	auth = Auth()
	print(auth.authenticate(email='email@domain.com', password_plain='password'))
	pass
