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
def miwen():
    try:
        open('文件——密文', 'rb').close()
        return  None    
    except FileNotFoundError:
        return False
def showInfo(a):
    QMessageBox.information(None, '提示', a,QMessageBox.StandardButton.Ok)

def showQuestion(a):
    QMessageBox.information(None, '提示', a,QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)

def showWarm(a):
    QMessageBox.warning(None, '错误', a,QMessageBox.StandardButton.Ok)

fileside = ""
def again_jiami(fileside,lineEdit_2,pushButton_3,miname='文件——密文'):
    text = lineEdit_2.text()
    if Path(fileside).name=='文件——密文':
        showWarm("不能加密文件名为'文件——密文'的文件")
        return
    if not fileside:
        showWarm("未选择文件")
        return
    if miwen()==None:
        b = QMessageBox.information(None, '提示', "在该程序同目录下有加密文件,是否覆盖？",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
        if b== QMessageBox.StandardButton.No:
            showInfo("请自行改变文件名称")
            return
    if os.path.exists(text+'——公钥') == False or os.path.exists(text+'——私钥')==False:
        if not text:
            showWarm("未输入公钥")
            return
        else:
            showWarm("未将公钥或私钥放在与该程序同目录下")
            return 2
    if os.path.exists(text+'——公钥') and os.path.exists(text+'——私钥'):
        pushButton_3.setEnabled(False)
        pushButton_3.repaint()
        QApplication.processEvents()
        
        result = jiami(fileside,lineEdit_2.text(),miname=miname)
        
        if result == 1:
            showInfo("已成功加密")
            showInfo("已将加密文件放在与该程序同目录下")
            pushButton_3.setEnabled(True)
        
        if result ==4:
            showWarm("加密失败，请检查密钥和磁盘空间")
            pushButton_3.setEnabled(True)

def again_jiemi(pushButton_4,lineEdit_3,miname='文件——密文',muli='.'):
    pushButton_4.setEnabled(False)
    text = lineEdit_3.text()
    miwen_1 = miwen()
    if miwen_1 == False:
        showWarm("未将密文放在与该程序同目录下")
        return 
    if os.path.exists(text + '——私钥') == False or os.path.exists(text + '——公钥')==False:
        if not text:
            showWarm("未输入私钥")
        else:
            showWarm("未将私钥或公钥放在与该程序同目录下")
    else:
        pushButton_4.repaint()
        QApplication.processEvents()
        try:
           a=line(lineEdit_3.text(),miname=miname)
        except InvalidTag:
            showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因，解密已停止")
            return
        except passwordError:
                showWarm("未输入密码，解密失败")
                return
        except Exception as a:

            showWarm(f"解密失败：{a}")
            return
        if a==2:
            showWarm("文件格式不对")
            return None
        if a==3:
            showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因，解密已停止")
            return
        if a==4:
            showWarm("公钥或私钥无效")
            return None
        symbol=a[-1]
        line_1=a[-2]
        a=a[:len(a)-2]
        if not symbol:
            z=QMessageBox.information(None, '提示', "检查到解密顺序与对方加密顺序不同，是否继续解密(本条是文件)？",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
            if z==QMessageBox.StandardButton.No:
                return
            
        if os.path.exists(line_1) == True:
            y=False
            if line_1=='文件——密文' or line_1.endswith('——私钥') or line_1.endswith('——公钥'):
                y = QMessageBox.information(None, '提示', "在该程序同目录下有同名文件，是否要改变加密出来的文件名为temp开头.tmp结尾的文件？文件名："+line_1,QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
                y= y==QMessageBox.StandardButton.Ok
                if y:
                    tep='1234567890abcdfghABCDFGRIOPADF'
                    nmd=1
                    while os.path.exists(line_1) == True:
                        for i in product(tep, repeat=nmd):
                            line_1='temp'+''.join(i)+'.tmp'
                            if os.path.exists(line_1) == False:
                                break
                        nmd+=1
                        if nmd>=6:
                            showInfo("同目录文件太多，无法找到不同名文件，解密已经停止")
                            return
                    
                else:
                    showInfo("解密已停止")
                    return
            b=QMessageBox.StandardButton.No
            if not y:
                b = QMessageBox.information(None, '提示', "在该程序同目录下有同名文件，是否要覆盖？文件名："+line_1,QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)
            
            if b == QMessageBox.StandardButton.Ok or y:
                try:
                    with tempfile.NamedTemporaryFile(mode='wb',delete=False,dir='.')as f:
                        name=f.name
                        
                        result = jiemi(f,*a,lineEdit_3.text() , rename=line_1 if y else '',miname=miname,muli=muli)
                        
                except InvalidSignature:
                    try:
                        os.remove(name)
                    except FileNotFoundError:
                        pass
                    showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                    return
                except InvalidTag:
                    os.remove(name)
                    showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                    return
                except Exception as a:
                    try:
                        os.remove(name)
                    except:
                        pass
                    showWarm(f"解密失败：{a}")
                    return
                if  result == 2:
                    os.remove(name)
                    showWarm("文件名不合法，可能是因为系统问题或其他问题")
                if result == 1:
            
                    showInfo("已成功解密")
                    showInfo("已将解密文件放在与该程序同目录下")
            else:
                
                showInfo("请自行改变文件名称")
        else:
            
            try:
                with tempfile.NamedTemporaryFile(mode='wb',delete=False,dir='.')as f:
                    name=f.name
                    result = jiemi(f,*a,lineEdit_3.text(),miname=miname,muli=muli)
            except InvalidSignature:
                try:
                    os.remove(name)
                except FileNotFoundError:
                    pass
                showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                return
            except InvalidTag:
                os.remove(name)
                showWarm("文件遭篡改，加密的公钥和解密的私钥不匹配/被篡改，或其它未知原因,已写入部分文件，但已删除")
                return
            except Exception as a:
                os.remove(name)
                
                showWarm(f"解密失败：{a}")
                return
            if  result == 2:
                os.remove(name)
                showWarm("文件名不合法，可能是因为系统问题或其他问题")
            if result == 1:
                showInfo("已成功解密")
                showInfo("已将解密文件放在与该程序同目录下")

def again_shengcheng(text,pushButton):

    if not text:
        showWarm("未输入名称")
        return 2
    if os.path.exists(text + '——公钥') == True or os.path.exists(text + '——私钥') == True:
        showWarm("该程序的相同目录下有重名密钥")
        return 2
    else:
        pushButton.setEnabled(False)
        pushButton.repaint()
        QApplication.processEvents()
        result ,si= shengcheng(text)
        if result == 1:
            pushButton.setEnabled(True)
            showInfo("已成功生成密钥")
            a=QMessageBox.information(None, '提示', "是否加密私钥：",QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No)

            if a==QMessageBox.StandardButton.Ok:
                while True:
                    password1, ok = QInputDialog.getText(None,"密码验证", "请输入密码：", QLineEdit.EchoMode.Password)
                    if not ok:
                        break
                    password2, ok = QInputDialog.getText(None,"密码验证", "请再次输入密码：", QLineEdit.EchoMode.Password)
                    if not ok:
                        break
                    if password1==password2:
                        si=jiamisi(password1,si)
                        with open(text + '——私钥','wb') as f:
                            f.write(b'0'*64+si)
                        return 2
                    showInfo("两次密码输入不同，请重新输入")
                showInfo("未输入密码，将写入不加密的私钥")
            with open(text + '——私钥','wb') as f:
                f.write(b'0'*64+si)
        if result==3:
            pushButton.setEnabled(True)
            showWarm("该程序的相同目录下有重名密钥")
            return 2
