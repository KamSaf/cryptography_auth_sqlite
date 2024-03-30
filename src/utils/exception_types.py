
class ValueTooLong(Exception):
    message = "Parameter length is too big: "


class ValueTooShort(Exception):
    message = "Parameter length is too small: "


class InvalidDataType(Exception):
    message = "Invalid type of given parameter: "


class PasswordConfirmationFailed(Exception):
    message = "Password and password confirmation must be the same"
