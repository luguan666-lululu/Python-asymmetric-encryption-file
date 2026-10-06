from cryptography.hazmat.primitives.asymmetric import mlkem,mldsa
from pathvalidate import is_valid_filename
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSAMuHasher
from cryptography.exceptions import InvalidTag,InvalidSignature,UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher,  modes,algorithms
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.cobblestone import Cobblestone256Decryptor, Cobblestone256Encryptor
from time import sleep,time
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
import sys
from pqcrypto.sign.slh_dsa_shake_256f import keygen as get_sign_key
from pqcrypto.kem.mceliece_8192128 import decaps as decrypt
from pqcrypto.kem.mceliece_8192128 import keygen as generate_keypair
from pqcrypto.kem.mceliece_8192128 import encaps as encrypt
import pqcrypto
from pqcrypto.sign.slh_dsa_shake_256f import  sign, verify
import tempfile
from itertools import product
from 加密原语 import *
from 文件加密 import *
from 消息页面 import connect_message_page,decrypt_auto



    #       ------------------图形化代码 ------------------



fileside = ""


def again_jiami_():
    try:
        again_jiami(fileside,lineEdit_2,pushButton_3)
    except OSError :
        showWarm("文件或硬盘异常，请检查文件权限和硬盘空间")
    except passwordError:
            showWarm("未输入密码，加密失败")
    except Exception :
        showWarm("公钥或私钥无效")

    pushButton_3.setEnabled(True)

def again_jiemi_():
    decrypt_auto(ui,pushButton_4,lineEdit_3)


def  again_shengcheng_():
    again_shengcheng(lineEdit.text(),pushButton)

def selectFile():
    global fileside
    fd = QFileDialog()
    fd.setFileMode(QFileDialog.FileMode.ExistingFile)  # 设置多选
    fd.setDirectory('C:/')  # 设置初始化路径
    if fd.exec():  # 执行

        fileside = fd.selectedFiles()[0]
        print(fileside)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    try:
        a=os.path.join(sys._MEIPASS,'untitled.ui')
    except AttributeError:
        a='./untitled.ui'
    ui = uic.loadUi(a)    #初始化

    lineEdit: QLineEdit = ui.lineEdit       #输入文本一，生成密钥
    lineEdit_2: QLineEdit = ui.lineEdit_2   #输入文本二，加密
    lineEdit_3: QLineEdit = ui.lineEdit_3

    pushButton: QPushButton = ui.pushButton     #按钮一，生成密钥
    pushButton_2: QPushButton = ui.pushButton_2
    pushButton_3: QPushButton = ui.pushButton_3
    pushButton_4: QPushButton = ui.pushButton_4

    pushButton.clicked.connect(lambda:again_shengcheng_())

    pushButton_2.clicked.connect(selectFile)
    pushButton_3.clicked.connect(lambda: again_jiami_())

    pushButton_4.clicked.connect(lambda: again_jiemi_())
    connect_message_page(ui)
    ui.show()

    sys.exit(app.exec())

