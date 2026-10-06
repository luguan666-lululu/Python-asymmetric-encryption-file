from cryptography.hazmat.primitives.asymmetric import mlkem,mldsa
from pathvalidate import is_valid_filename
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSAMuHasher
from cryptography.exceptions import InvalidTag,InvalidSignature,UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher,  modes,algorithms
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.cobblestone import Cobblestone256Decryptor, Cobblestone256Encryptor
import math
from fractions import Fraction
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from hashlib import sha3_512 as sha3
import os
import secrets
from PyQt6 import QtCore, QtGui, QtWidgets,uic
from PyQt6.QtWidgets import QInputDialog
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QFileDialog,QMessageBox,QWidget,QVBoxLayout
from pqcrypto.sign.slh_dsa_shake_256f import keygen as get_sign_key
from pqcrypto.kem.mceliece_8192128 import decaps as decrypt
from pqcrypto.kem.mceliece_8192128 import keygen as generate_keypair
from pqcrypto.kem.mceliece_8192128 import encaps as encrypt
from pqcrypto.sign.slh_dsa_shake_256f import  sign, verify
import pqcrypto
from 私钥加解密 import *
from 加密原语 import hasher_maker,encrypt_,suiji
from 文件加密 import showInfo, showWarm,QMessageBox
magic=4983469496906568914487877934861856809289047442692285886511892208267146676519
magic=magic.to_bytes(32)


class zs:
    def __init__(self,key1,key2,k1,k2,nonce):

        self.key1=(int.from_bytes(key1)^int.from_bytes(k1)).to_bytes(32)
        self.key2=(int.from_bytes(key2)^int.from_bytes(k2)).to_bytes(32)
        self.nonce1=nonce[:12]
        self.nonce2=nonce[12:24]
        self.aes=AESGCM(self.key1)
        self.cha=ChaCha20Poly1305(self.key2)
        self.len=0

    def update(self,m):
        self.len+=1

        self.nonce1=((int.from_bytes(self.nonce1)+1)%(2**(12*8))).to_bytes(12)
        self.nonce2=((int.from_bytes(self.nonce2)+1)%(2**(12*8))).to_bytes(12)
        return self.cha.encrypt(self.nonce2,self.aes.encrypt(self.nonce1,m,self.len.to_bytes(12)),self.len.to_bytes(12))


class zs_:
    def __init__(self,key1,key2,k1,k2,nonce):
        self.key1=(int.from_bytes(key1)^int.from_bytes(k1)).to_bytes(32)
        self.key2=(int.from_bytes(key2)^int.from_bytes(k2)).to_bytes(32)
        self.nonce1=nonce[:12]
        self.nonce2=nonce[12:24]
        self.aes=AESGCM(self.key1)
        self.cha=ChaCha20Poly1305(self.key2)
        self.len=0
        
    def update(self,m):
        self.len+=1
        self.nonce1=((int.from_bytes(self.nonce1)+1)%(2**(12*8))).to_bytes(12)
        self.nonce2=((int.from_bytes(self.nonce2)+1)%(2**(12*8))).to_bytes(12)
        try:                   #尽量常数时间
            d=self.cha.decrypt(self.nonce2,m,self.len.to_bytes(12))
        except InvalidTag:
            d=self.aes.decrypt(self.nonce1,m,self.len.to_bytes(12))
            raise
        return self.aes.decrypt(self.nonce1,d,self.len.to_bytes(12))
    
class file:
        def __init__(self, f, long):
            self.f = open(f, 'rb')
            self.long = long
            self.len = math.ceil(Fraction(os.path.getsize(f) , long))
        def read(self):
            return self.f.read(self.long)

def write(f, msg):
        f.write(msg)


def jiami(message,name,mipath='文件——密文'):

    changdu=secrets.randbelow(suiji).to_bytes(4)

    
    f_gong = open(name + '——公钥', 'rb')
    old=f_gong.read(64)
    g=f_gong.read()
    try:
        public_key = mlkem.MLKEM1024PublicKey.from_public_bytes(g[2592+64:64+1568+2592])
    except UnsupportedAlgorithm,ValueError:
        f_gong.close()
        return 4
    pk=g[1568+2592+64:]
    f_gong.close()
    f_s=open(name + '——私钥', 'rb')
    a,b=dusi_jia(f_s)
    try:
        private_key_sign=mldsa.MLDSA87PrivateKey.from_seed_bytes(a)
    except UnsupportedAlgorithm,ValueError:
        f_s.close()
        return 4
    si_sign=b
    f_s.close()

    hasher_=hasher_maker(private_key_sign.public_key())
    key1,c1= public_key.encapsulate()

    hasher_.update(key1)
    key2,c2=public_key.encapsulate()

    hasher_.update(key2)

    k1,c_1=encrypt_(pk)

    hasher_.update(k1)
    k2,c_2=encrypt_(pk)

    hasher_.update(k2)

    cipher = zs(key1,key2,k1,k2,hasher_.hash2.digest())

    
    f_ = open(mipath, 'wb')
    f_.write(magic)
    f_.write(c1+c2+c_1+c_2)
    mu=hasher_.digest()
    signature = private_key_sign.sign_mu(mu[0])
    f_.write(signature+sign(si_sign,mu[1]))
    f_.write(cipher.update(old))
    f_.write(cipher.update(changdu))
    f_.write(cipher.update(message))
    f_.write(os.urandom(int.from_bytes(changdu)))
    f_.write(cipher.update(b''))
    f_.close()
    with open(name + '——公钥', 'r+b') as f_gong:
        f_gong.write(mu[1])
    return 1
class ToolongError(Exception):
     pass

def jiemi(name,mipath='文件——密文'):
    if os.path.getsize(mipath)>100000000:
         raise ToolongError
    f = open(mipath, 'rb')
    a=f.read(32)
    if a!=magic:
        return 2
    c1 = f.read(1568)
    c2 = f.read(1568)
    c_1=f.read(208)
    c_2=f.read(208)
    text=f.read(4627)
    te=f.read(49856)
    f_s = open(name + '——私钥', 'rb')
    old,seed = dusi_jie(f_s)
    f_s.close()
    try:
        private_key = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed[32+128:96+128])
    except UnsupportedAlgorithm,ValueError:
            return 4
    pk=seed[96+128:]
    f_s.close()
    f_g=open(name + '——公钥', 'rb')
    f_g.seek(64,0)
    try:
        public_key_sign=mldsa.MLDSA87PublicKey.from_public_bytes(f_g.read(2592))
    except UnsupportedAlgorithm,ValueError:
            f_g.close()
            return 4
    g_sign=f_g.read(64)
    f_g.close()
    hasher_=hasher_maker(public_key_sign)
    key1=private_key.decapsulate(c1)
    key2=private_key.decapsulate(c2)
    k1=decrypt(pk,c_1)
    k2=decrypt(pk,c_2)
    hasher_.update(key1)
    hasher_.update(key2)
    hasher_.update(k1)
    hasher_.update(k2)
    t=hasher_.digest()
    try:
        public_key_sign.verify_mu(text,t[0])
    except InvalidSignature:
        return 3
    try:
        verify(g_sign, t[1], te)
    except pqcrypto.InvalidSignatureError:
        raise InvalidSignature


    nonce=t[1]
    cipher = zs_(key1,key2,k1,k2,nonce)
    symbol=cipher.update(f.read(64+32))==old
    if not symbol:
         z=QMessageBox.information(None, '提示', "检查到解密顺序与对方加密顺序不同，是否继续解密(本条是消息)？",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
         if z==QMessageBox.StandardButton.No:
            f.close()
            return 4


    changdu=cipher.update(f.read(4+32))
    changdu=int.from_bytes(changdu)
    m=f.read(os.path.getsize(f.name)-f.tell()-32-changdu)
    m=cipher.update(m)
    f.seek(changdu,1)
    if not cipher.update(f.read())==b'':
         raise InvalidTag
    f.close()
    with open(name + '——私钥', 'r+b') as f_s:
         f_s.write(t[1])
    return m