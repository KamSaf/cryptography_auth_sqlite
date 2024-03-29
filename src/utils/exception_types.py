
class PasswordTooLong(Exception):
    """Password is too long"""


class EmailTooLong(Exception):
    """Email is too long"""


class InvalidDataType(Exception):
    """Invalid type of given parameter"""


class PasswordConfirmationFailed(Exception):
    """Password and password confirmation must be the same"""
