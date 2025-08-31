from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
msg = b""

c = CMAC(algorithms.AES(key))
c.update(msg)
print(c.finalize().hex())
