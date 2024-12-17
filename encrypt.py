

key = ''
with open('myTopSecretKey.key', 'rb') as file:
    key = file.read()


data = ''
with open('toBeSecret.txt', 'rb') as file:
    data = file.read()

#
from cryptography.fernet import Fernet

f = Fernet(key)

encryptedData = f.encrypt(data)



with open('myTopSecretInfo.txt', 'wb') as file:
    file.write(encryptedData)