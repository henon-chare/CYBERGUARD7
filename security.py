from passlib.context import CryptContext

pwd = CryptContext(schemes=["bcrypt"])

def hash_password(password):
    return pwd.hash(password)

def verify_password(password, hash):
    return pwd.verify(password, hash)