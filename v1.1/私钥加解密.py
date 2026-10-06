from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.cobblestone import Cobblestone256Decryptor, Cobblestone256Encryptor
import os
from PyQt6.QtWidgets import QInputDialog
from cryptography.exceptions import InvalidTag
from PyQt6.QtWidgets import QLineEdit
class passwordError(Exception):
    pass

def dusi_jie(f):
    if os.path.getsize(f.name)==14344+64:

        return f.read(64),f.read()
    if os.path.getsize(f.name)==14464+64:
        k=f.read(64)
        s=f.read()
        tis="私钥已加密，请输入密码："
        while True:
            password, ok = QInputDialog.getText(None,"密码验证", tis, QLineEdit.EchoMode.Password)
            if not ok:
                raise passwordError
            try:
                kdf = Argon2id(salt=s[:32],length=32+32+12,iterations=4,lanes=4,memory_cost=512 * 1024,ad=None,secret=None)
                key = kdf.derive(password.encode())
                m=wdjm_(key,s[32:],s[:32])
                return k,m
            except InvalidTag:
                tis="密码错误，请重新输入："
    raise ValueError

def dusi_jia(f):
    f.seek(64,0)
    if os.path.getsize(f.name)==14344+64:
        a=f.read(32)
        b=f.read(128)
        return a,b
    if os.path.getsize(f.name)==14464+64:
        s=f.read()
        tis="私钥已加密，请输入密码："
        while True:
            password, ok = QInputDialog.getText(None,"密码验证", tis, QLineEdit.EchoMode.Password)
            if not ok:
                raise passwordError
            try:
                kdf = Argon2id(salt=s[:32],length=32+32+12,iterations=4,lanes=4,memory_cost=512 * 1024,ad=None,secret=None)
                key = kdf.derive(password.encode())
                m=wdjm_(key,s[32:],s[:32])
                return m[:32],m[32:32+128]
            except InvalidTag:
                tis="密码错误，请重新输入："
    raise ValueError
def wdjm_(key,s,salt):
    k=Cobblestone256Decryptor(key[:32],salt)
    m=k.update(s)
    m+=k.finalize()

    k=ChaCha20Poly1305(key[32:32+32])
    return k.decrypt(key[32+32:32+32+12],m,salt)


def wdjm(key,m,salt):
    k=ChaCha20Poly1305(key[32:32+32])
    s=k.encrypt(key[32+32:32+32+12],m,salt)
    k=Cobblestone256Encryptor(key[:32],salt)
    s=k.update(s)
    s+=k.finalize()
    return s
    

def jiamisi(key:str,si):
    key=key.encode()
    salt = os.urandom(32)
    kdf = Argon2id(
    salt=salt,
    length=32+32+12,
    iterations=4,
    lanes=4,
    memory_cost=512 * 1024,
    ad=None,
    secret=None,
    )
    key = kdf.derive(key)

    s=wdjm(key,si,salt)
    return salt+s