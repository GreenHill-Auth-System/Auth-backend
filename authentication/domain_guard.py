GREENHILL_DOMAIN = "@greenhillacademy.ac.ug"


def is_greenhill_email(email):
    if not email:
        return False

    return email.lower().endswith(GREENHILL_DOMAIN)