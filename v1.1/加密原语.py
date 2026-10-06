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
import pqcrypto
from pqcrypto.sign.slh_dsa_shake_256f import  sign, verify
from 私钥加解密 import *
tianchongfn=1100
suiji=1024*1024*3
fenkuai=24*1024*1024  #建议小于16gb
magic=7173652828892040422602214684981408631467807257282976502529641486308420901924
magic=magic.to_bytes(32)
class aesecb_en:
    def __init__(self,key):
        self.k=Cipher(algorithms.AES256(key),mode=modes.ECB(),backend=None).encryptor()
    def encrypt(self,data):
        k=len(data)%16
        if k:
            return self.k.update(data[:len(data)-k])+data[len(data)-k:]
        else:
            return self.k.update(data)
class aesecb_de:
    def __init__(self,key):
        self.k=Cipher(algorithms.AES256(key),mode=modes.ECB(),backend=None).decryptor()
    def decrypt(self,data):
        k=len(data)%16
        if k:
            return self.k.update(data[:len(data)-k])+data[len(data)-k:]
        else:
            return self.k.update(data)
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
        if type(m)is bytes:
            return self.cha.encrypt(self.nonce2,self.aes.encrypt(self.nonce1,m,self.len.to_bytes(12)),self.len.to_bytes(12))
        k=memoryview(m)[:len(m)-32]
        f=memoryview(m)[:len(m)-16]
        self.aes.encrypt_into(self.nonce1,k,self.len.to_bytes(12),f)
        self.cha.encrypt_into(self.nonce2,f,self.len.to_bytes(12),m)
        return m


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
        if type(m)is bytes:
            try:                   #尽量常数时间
                d=self.cha.decrypt(self.nonce2,m,self.len.to_bytes(12))
            except InvalidTag:
                d=self.aes.decrypt(self.nonce1,m,self.len.to_bytes(12))
                raise
            return self.aes.decrypt(self.nonce1,d,self.len.to_bytes(12))
        k=memoryview(m)[:len(m)-16]
        f=memoryview(m)[:len(m)-32]
        try:                   #尽量常数时间
            self.cha.decrypt_into(self.nonce2,m,self.len.to_bytes(12),k)
        except InvalidTag:
            try:
                self.aes.decrypt_into(self.nonce1,k,self.len.to_bytes(12),f)
            except InvalidTag:
                pass
            m[:]=bytearray(len(m))#清零缓冲区
            raise
        try:
            self.aes.decrypt_into(self.nonce1,k,self.len.to_bytes(12),f)
        except InvalidTag:
            m[:]=bytearray(len(m))
            raise
        return f,m



class hasher_maker:
    def __init__(self,a,copy=False):
        if copy:
            return
        else:
            self.hash1=MLDSAMuHasher(a)
            self.hash2=sha3(a.public_bytes_raw())
    def update(self,m):
        self.hash1.update(m)
        self.hash2.update(m)
    def digest(self):
        return self.hash1.finalize(),self.hash2.digest()
    def copy(self):
        hash1=self.hash1.copy()
        hash2=self.hash2.copy()
        a=hasher_maker(None,copy=True)
        a.hash1=hash1
        a.hash2=hash2
        return a
class _:
    def result(self):
        return None

def encrypt_(a):
    b,c=encrypt(a)
    return c,b
#       ------------------加密代码 ------------------


class workers:
    def __init__(self,a:list):
        self.a=a
    def read(self):
        k=self.a[-1]
        del self.a[-1]
        return k
    def buchong(self,a):
        if a is None:
            return
        self.a.append(a)
def jiami(path,name,miname='文件——密文'):
    
    
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
    f_s.close()
    try:
        private_key_sign=mldsa.MLDSA87PrivateKey.from_seed_bytes(a)
    except UnsupportedAlgorithm,ValueError:
        f_s.close()
        return 4
    si_sign=b

    hasher_=hasher_maker(private_key_sign.public_key())
    key1,c1= public_key.encapsulate()

    hasher_.update(key1)
    key2,c2=public_key.encapsulate()

    hasher_.update(key2)

    k1,c_1=encrypt_(pk)

    hasher_.update(k1)
    k2,c_2=encrypt_(pk)

    hasher_.update(k2)

    
    filename = Path(path).name.encode()
    mu=hasher_.digest()
    cipher = zs(key1,key2,k1,k2,mu[1])

    class file:
        def __init__(self, f, long):
            self.f = open(f, 'rb')
            self.long = long
            self.size=os.path.getsize(f)
            self.len = math.ceil(Fraction(self.size , long))
        def read(self,d):
            if self.f.tell()+self.long>=self.size:
                d=memoryview(d)[:self.size-self.f.tell()+32]
                f=memoryview(d)[:self.size-self.f.tell()]
                self.f.readinto(f)
                return d
            f=memoryview(d)[:self.long]
            self.f.readinto(f)
            return d

    def write(f, msg):
        f.write(msg)
        return msg
    f = file(path,fenkuai) 
    f_ = open(miname, 'wb')
    f_.write(magic)

    
    f_.write(c1+c2+c_1+c_2)

    long = len(filename)+32
    long=long.to_bytes(2)

    r=os.urandom(tianchongfn-int.from_bytes(long))

    signature = private_key_sign.sign_mu(mu[0])
    f_.write(signature+sign(si_sign,mu[1]))

    f_.write(cipher.update(old))
    f_.write(cipher.update(long))
    filename_en=cipher.update(filename)
    f_.write(filename_en)

    f_.write(r)
    f_.write(cipher.update(changdu))

    

    if f.len >= 3:
        worker=workers([bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32)] if f.len>3 else [bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32)])
        with ThreadPoolExecutor(max_workers=3) as pool:
            du = pool.submit(f.read,worker.read())
            du_jieguo = du.result()
            du = pool.submit(f.read,worker.read())
            jiami = pool.submit(cipher.update, du_jieguo)
            xie = _()
            for i in range(f.len - 2):
                du_jieguo = du.result()
                du = pool.submit(f.read,worker.read())
                jiamijieguo = jiami.result()
                jiami = pool.submit(cipher.update, du_jieguo)
                worker.buchong(xie.result())
                xie = pool.submit(write, f_, jiamijieguo)

            du_jieguo = du.result()
            jiamijieguo = jiami.result()
            jiami = pool.submit(cipher.update, du_jieguo)
            worker.buchong(xie.result())
            xie = pool.submit(write, f_, jiamijieguo)
            jiamijieguo = jiami.result()
            worker.buchong(xie.result())
            xie = pool.submit(write, f_, jiamijieguo)
            xie.result()
    else:  # 文件大小太小，不用线程加速
        for i in range(f.len):
            k=bytearray(fenkuai+32)
            k=f_.write(cipher.update(f.read(k)))

    f_.write(os.urandom(int.from_bytes(changdu)))
    f_.write(cipher.update(b''))
    f_.close()
    with open(name + '——公钥', 'r+b')as f_gong:
        f_gong.seek(0)
        f_gong.write(mu[1])
    return 1

#       ------------------解密代码 ------------------



def jiemi(f_,key1,key2,k1,k2,public_key_sign,nonce,name,rename='',miname='文件——密文',muli='.'):

    f = open(miname, 'rb')
    a=f.read(32)
    if a!=magic:
        raise
    f.seek(f.tell()+1568*2+208*2,0)
    text=f.read(4627)
    f.seek(f.tell()+49856,0)
    hasher_=hasher_maker(public_key_sign)
    class file_decrypt:
        def __init__(self, f, long,c):
            self.f = f
            self.long = long+32
            self.size=os.path.getsize(f.name) - f.tell()-c-32
            self.len = math.ceil(Fraction(self.size, self.long))
            

        def read(self,k):
            if self.size>=self.long:
                self.size-=self.long
                
                self.f.readinto(k)
                return k
            else:
                k=memoryview(k)[:self.size]
                self.f.readinto(k)
                return k

    def write(file,data):

        file.write(data[0])
        return data[1]
    hasher_.update(key1)
    hasher_.update(key2)

    hasher_.update(k1)
    hasher_.update(k2)
    t=hasher_.digest()

    public_key_sign.verify_mu(text,t[0])
    if t[1]!=nonce:
        raise InvalidSignature

    cipher = zs_(key1,key2,k1,k2,nonce)
    cipher.update(f.read(64+32))
    fnl=f.read(2+32)
    fnl=cipher.update(fnl)
    
    fn = f.read(int.from_bytes(fnl))
    fn=cipher.update(fn)
    f.seek(tianchongfn-int.from_bytes(fnl),1)
    if not Path(fn.decode()).name==fn.decode():
        f.close()
        return 2
    if not is_valid_filename(fn.decode()):
        f.close()
        return 2
    changdu=f.read(4+32)


    changdu=cipher.update(changdu)

    
    changdu=int.from_bytes(changdu)
    f = file_decrypt(f, fenkuai,changdu)  
    
    if f.len >= 3:
        worker=workers([bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32)] if f.len>3 else [bytearray(fenkuai+32),bytearray(fenkuai+32),bytearray(fenkuai+32)])
        with ThreadPoolExecutor(max_workers=3) as pool:
            du = pool.submit(f.read,worker.read())
            du_jieguo = du.result()
            du = pool.submit(f.read,worker.read())
            jiami = pool.submit(cipher.update, du_jieguo)
            xie = _()
            for i in range(f.len - 2):
                du_jieguo = du.result()
                du = pool.submit(f.read,worker.read())
                jiamijieguo = jiami.result()
                jiami = pool.submit(cipher.update, du_jieguo)
                worker.buchong(xie.result())
                xie = pool.submit(write,f_, jiamijieguo)

            du_jieguo = du.result()
            jiamijieguo = jiami.result()
            jiami = pool.submit(cipher.update, du_jieguo)
            worker.buchong(xie.result())
            xie = pool.submit(write,f_, jiamijieguo)
            jiamijieguo = jiami.result()
            worker.buchong(xie.result())
            xie = pool.submit(write,f_, jiamijieguo)
            worker.buchong(xie.result())


    else:
        k=bytearray(fenkuai+32)
        for i in range(f.len):
            k=write(f_,cipher.update(f.read(k)))
    
    f.f.seek(changdu, 1)
    cipher.update(f.f.read(32))
    
    f_.close()
    f.f.close()
    if rename:
        os.replace(f_.name,rename)
        with open(name + '——私钥', 'r+b')as f_s :
            f_s.write(t[1])
        return 1
    os.replace(f_.name,os.path.join(muli,fn.decode()))
    with open(name + '——私钥', 'r+b')as f_s :
        f_s.write(t[1])
    return 1

def line(name,miname='文件——密文'):
    
    f = open(miname, 'rb')
    a=f.read(32)
    if a!=magic:
        return 2
    c1 = f.read(1568)
    c2 = f.read(1568)
    c_1=f.read(208)
    c_2=f.read(208)
    text=f.read(4627)
    te=f.read(49856)
    with open(name + '——私钥', 'rb')as f_s :
        old,seed = dusi_jie(f_s)
    
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
        return 3


    nonce=t[1]
    cipher = zs_(key1,key2,k1,k2,nonce)
    symbol=cipher.update(f.read(64+32))==old

    fnl=f.read(2+32)
    fnl=cipher.update(fnl)

    fn = f.read(int.from_bytes(fnl))
    fn=cipher.update(fn)
    f.close()
    return key1,key2,k1,k2,public_key_sign,nonce,fn.decode(),symbol

    #       ------------------生成密钥代码 ------------------

def shengcheng(name):

    if os.path.exists(name+'——私钥'):
        return 3                #有重名回3
    if os.path.exists(name+'——公钥'):
        return 3
    private_key = mlkem.MLKEM1024PrivateKey.generate()
    public_key=private_key.public_key()
    private_key_sign = mldsa.MLDSA87PrivateKey.generate()

    public_key_sign=private_key_sign.public_key()
    pk, sk = generate_keypair()

    pk_sign, sk_sign = get_sign_key()#64,128
    
    s=private_key_sign.private_bytes_raw()+sk_sign+private_key.private_bytes_raw()+sk
    
    with open(name+'——公钥','wb')as f:
        f.write(b'0'*64+public_key_sign.public_bytes_raw()+pk_sign+public_key.public_bytes_raw()+pk)
    
    return 1,s





