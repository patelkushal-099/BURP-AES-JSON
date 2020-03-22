import sys
from base64 import b64encode, b64decode

import json
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

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

def main():
    if len(sys.argv) != 3:
        print("invalid arguments - usage: crypto.py encrypt|decrypt payload")
        sys.exit(2)

    Ekey = "1234567890123456"

    # read argument 2, it must be encrypt or decrypt
    action = sys.argv[1]
    payload = sys.argv[2]

    payload = json.loads(payload)

    encryptor = AESCipher(Ekey)

    if action == "encrypt":

        for key, value in payload.items():

            payload[key] = encryptor.encrypt(str(value)).decode("utf-8")
        
        payload = json.dumps(payload)

        print(payload, end='')

    else:

        for key, value in payload.items():

            payload[key] = encryptor.decrypt(str(value))
            
        payload = json.dumps(payload)

        print(payload, end='')


if __name__ == "__main__":
    main()


