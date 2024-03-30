
class PasswordTooLong(Exception):
    message = "Password is too long"


class EmailTooLong(Exception):
    message = "Email is too long"


class InvalidDataType(Exception):
    message = "Invalid type of given parameter"


class PasswordConfirmationFailed(Exception):
    message = "Password and password confirmation must be the same"
