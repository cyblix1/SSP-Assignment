import base64
import os
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import bcrypt
# password_provided = 'password'
# password = password_provided.encode()

# salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"

# kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
#                 length=32,
#                 salt=salt,
#                 iterations=100000,
#                 backend=default_backend())

# key = base64.urlsafe_b64encode(kdf.derive(password))

# email = 'nattzw@gmail.com'
# fernet = Fernet(key)
# encrypted = fernet.encrypt(email.encode())

# decrypted = fernet.decrypt(encrypted)
# print(decrypted.decode())

def hash(string_to_hash):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(string_to_hash.encode(),salt)
    return hashed


def check_hash(string_to_check,hashed):
    if bcrypt.checkpw(string_to_check.encode(),hashed):
        print('True')
    else:
        print('False')

email = 'nathanaeltzw@gmail.com'
email2 = "nathanaeltzw@gmail.com"
hash = hash(email)
hi = hash.decode()
check_hash(email2,hi.encode())

# list = ({'staff_id': 2, 'full_name': 'Nathanael Tan', 'email': 'gAAAAABi06v5nRFeaEwa7KqFpcjMCWCuz2IHxmr-Kvu5i8SMMLwOYs_Y6LnDCi_OP3wbFD6ijdX812jgvGvv89jiW-pSZdTRYoDZWEJRCVqWqqsOduV9nvk=', 'phone_no': '98994217', 'gender': 'F', 'hashed_pw': '$2b$12$7NTxWJVQIYHhvkHjSsyuVOg7tArgtHzZh4MNsAyaJNz5DfVXOU3cC', 'password_age': 30, 'description': 'aaaaaaaaa', 'date_created': datetime.datetime(2022, 7, 17, 6, 28, 9)}, {'staff_id': 3, 'full_name': 'John', 'email': 'gAAAAABi06wjiIhltMgeCt_cQPnf3HCp_SA6XmmflG1mwROhRXpbq-12rJkj59lJv1M5p69nIRHwJk3lxjVnBFfXM8vN0kJGkw==', 'phone_no': '98994217', 'gender': 'F', 'hashed_pw': '$2b$12$dnaSYRiXydhkZ6cq5x9v5.pkQ8m1v476FZQhhpkrgl/g/6kk/bp9i', 'password_age': 30, 'description': 'aaaaaa', 'date_created': datetime.datetime(2022, 7, 17, 6, 28, 51)})
# item = 'john'
# for staff in list:
#     if staff['full_name'] == 'John': 
#         break
# print(staff)