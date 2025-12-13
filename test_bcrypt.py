import bcrypt

pw = b"password123"
h = bcrypt.hashpw(pw, bcrypt.gensalt())
print("new hash:", h)
print("check new hash:", bcrypt.checkpw(pw, h))

