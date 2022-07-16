
import bcrypt


password = "bob"
salt =  bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode(),salt)
print(hashed)

password2 = "bob"
if bcrypt.checkpw(password2.encode(),hashed):
    print("matched")
else:
    print("failed")
