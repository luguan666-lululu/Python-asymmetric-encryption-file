"""消息文件加解密及类型识别；复用现有加密模块。"""

import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from pathvalidate import is_valid_filename
from PyQt6.QtWidgets import QApplication, QMessageBox

import 加密原语
import 文件加密
import 消息加密
from 文件加密 import showInfo, showWarm
from 私钥加解密 import passwordError


def decrypt_auto(ui, button, line_edit):
    """按文件头识别密文类型，文件密文仍交给原文件解密流程。"""
    button.setEnabled(False)
    try:
        with open("文件——密文", "rb") as ciphertext:
            header = ciphertext.read(32)
        if header == 消息加密.magic:
            _run_message(ui, line_edit.text(), decrypt=True)
        elif header == 加密原语.magic:
            ui.groupBox_message_result.hide()
            ui.plainTextEdit_message_result.clear()
            文件加密.again_jiemi(button, line_edit)
        else:
            showWarm("密文格式不正确，无法识别为文件密文或消息密文")
    except FileNotFoundError:
        showWarm("请将收到的密文命名为“文件——密文”，放在当前运行目录下")
    except OSError:
        showWarm("文件或硬盘异常，请检查文件权限和硬盘空间")
    finally:
        button.setEnabled(True)


def _run_message(ui, name, decrypt=False):
    name = name.strip()
    if not name:
        showWarm("请输入对面名称")
        return
    if not is_valid_filename(name, platform="Windows"):
        showWarm("名称不能包含路径或文件名中不允许的字符")
        return
    if not all(Path(name + suffix).is_file() for suffix in ("——公钥", "——私钥")):
        showWarm("请将同名的公钥和私钥放在当前运行目录下")
        return

    if not decrypt:
        message = ui.plainTextEdit_message_plain.toPlainText()
        if not message:
            showWarm("请输入要加密的消息")
            return
        if Path("文件——密文").exists():
            answer = QMessageBox.information(
                ui, "提示", "当前运行目录下已有“文件——密文”，是否覆盖？",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Ok:
                return

    buttons = (ui.pushButton_message_encrypt, ui.pushButton_4)
    for button in buttons:
        button.setEnabled(False)
        button.repaint()
    try:
        QApplication.processEvents()
        if decrypt:
            result = 消息加密.jiemi(name, mipath="文件——密文")
            if isinstance(result, bytes):
                message = result.decode("utf-8")
                ui.plainTextEdit_message_result.setPlainText(message)
                ui.groupBox_message_result.show()
                ui.tabWidget.setCurrentWidget(ui.tab_decrypt)
                ui.scrollArea_decrypt.ensureWidgetVisible(ui.groupBox_message_result)
                showInfo("已识别为消息密文，解密结果已显示在本页")
            elif result == 2:
                showWarm("不是消息密文，请检查密文格式")
            elif result == 3:
                showWarm("密文被篡改或密钥不匹配，消息解密失败")
            elif result == 4:
                return
            else:
                showWarm("公钥或私钥无效，消息解密失败")
        else:


            try:
                result = 消息加密.jiami(message.encode("utf-8"), name)
                if result == 1:
                    
                    showInfo("消息已成功加密，密文已保存为当前运行目录下的“文件——密文”")
                else:
                    showWarm("公钥或私钥无效，消息加密失败")
            finally:
                pass
    except passwordError:
        showWarm("未输入密码，消息操作已取消")
    except (InvalidTag, InvalidSignature):
        showWarm("密文被篡改或密钥不匹配，消息操作失败")
    except UnicodeDecodeError:
        showWarm("解密结果不是 UTF-8 文本消息")
    except OSError:
        showWarm("文件或硬盘异常，请检查密钥文件、文件权限和硬盘空间")
    except (ValueError, UnsupportedAlgorithm):
        showWarm("密文格式不正确或公钥、私钥无效")
    except 消息加密.ToolongError:
        showWarm("密文太长，几乎不可能是真实消息")
    except Exception:
        showWarm("消息操作失败，请检查密文和密钥")
    finally:
        for button in buttons:
            button.setEnabled(True)


def connect_message_page(ui):
    ui.groupBox_message_result.hide()
    ui.pushButton_message_encrypt.clicked.connect(
        lambda: _run_message(ui, ui.lineEdit_message_name.text())
    )
