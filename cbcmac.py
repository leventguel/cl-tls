from Cryptodome.Cipher import AES

key = bytes(range(16))
message = bytes(range(32))
iv = bytes(16)

cipher = AES.new(key, AES.MODE_CBC, iv)
mac = cipher.encrypt(message)[-16:]
print(mac.hex())
