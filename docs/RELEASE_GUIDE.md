# v1.1 源码与发布说明

本仓库为 [Python-asymmetric-encryption-file](https://github.com/luguan666-lululu/Python-asymmetric-encryption-file)。保留现有根目录 LICENSE，许可为 Apache License 2.0。

## 目录安排

- 根目录：README.md、SECURITY.md、CHANGELOG.md、.gitignore、LICENSE。
- v1.1/：六个 Python 源码模块、untitled.ui、加密程序v1.1.spec、requirements.txt、requirements-build.txt。
- docs/：本指南和 RELEASE_NOTES_v1.1.md。

不要把实际公私钥、通信密文、测试数据和构建缓存提交到仓库。根目录 .gitignore 只影响未跟踪文件，网页手工上传不受其保护。

## 运行与打包

在包含源码的 v1.1 文件夹中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe "加密程序v1.1.py"
.\.venv\Scripts\python.exe -m PyInstaller --clean "加密程序v1.1.spec"
Get-FileHash -Algorithm SHA256 -LiteralPath ".\dist\加密程序v1.1.exe"
```

spec 已配置单文件打包并包含 untitled.ui。当前 console=True，适合检查运行异常；如改为 console=False，需重新打包并验证界面反馈。

依赖版本对应已验证的 Windows x64 / Python 3.14.7 环境，不代表所有其他版本兼容。源码更新不会自动更新已发布的 exe、Release 附件或 v1.1 标签。

## 发布前核对

使用两套临时密钥做双向文件和文本消息往返，确认公钥交换、文件名恢复、同名提示及顺序提示；再在干净 Windows 环境验证 exe。不要使用真实通信私钥做发布测试。

界面说明已对齐 v1.1：数据层不含 AES-CBC，私钥 KDF 使用 512 MiB，数字签名认证会话秘密摘要；文件与消息共用顺序检查。完整边界见根目录 SECURITY.md。

如重新发布附件，请先核对构建使用的提交，附上实际 SHA-256 和平台说明。发布正文可参考同目录 RELEASE_NOTES_v1.1.md。保留旧程序与旧密钥以处理历史密文。
