import requests
import time
import json
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


data = {"name":"John", "age":31, "city":"New York"}

class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

encrypto = AESCipher("1234567890123456")

for key, value in data.items():
    
    data[key] = encrypto.encrypt(str(value))

http_proxy = "http://127.0.0.1:8080"


proxyDict = {
    "http": http_proxy
}


try:
    while True:
        req = requests.post("http://localhost:8000", json=data, proxies=proxyDict)
        time.sleep(5)
        print(req.json())

except KeyboardInterrupt:
        print("Interrupted!")
