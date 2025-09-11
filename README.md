# ChaCha20-Poly1305 批量加解密（PyQt5 + PyCryptodome）🎉🔐

仓库：github.com/wangyifan349/password  
许可证：MIT

---

## 简介 🚀
一个桌面工具，用 PyCryptodome 实现 ChaCha20-Poly1305，加/解密文件，支持批量、多线程、拖放、覆盖源文件或输出到目录、写入 salt 与 AAD。

---

## 快速开始 🛠️
先安装依赖：
```bash
pip install pycryptodome pyqt5
```

克隆并运行：
```bash
git clone https://github.com/wangyifan349/password.git
cd password
python chacha20_poly1305_gui_v2.py
```

---

## 功能亮点 ✨
- 支持批量文件与文件夹（拖放）📂  
- 多线程并发处理（可调并发数）⚡  
- 覆盖源文件（安全的临时文件替换）🔁  
- 密钥由密码通过 PBKDF2-HMAC-SHA256 派生（迭代 **10000**）🔑  
- 可写入 salt（格式：1 字节长度 + salt + nonce(12) + 密文 + tag(16)）🧂  
- 支持关联数据 AAD（加密/解密需一致）🧾

---

## 使用说明 ✅
1. 添加文件或文件夹（支持拖放）。  
2. 选择模式：encrypt / decrypt。  
3. 输入密码（或先派生并查看 salt）。  
4. 可选填写 salt（hex）或留空由程序生成并写入文件。  
5. 可选填写 AAD（需与解密时一致）。  
6. 选择输出目录或勾选“覆盖源文件”。  
7. 设置并发线程数，点击“开始”。  

---

## 输出格式说明 📦
加密文件格式（可选 salt）：  
[1 byte salt length][salt][nonce (12)][ciphertext][tag (16)]

---

## 安全注意 🔐
- PBKDF2 迭代次数为 **10000**（按要求）。  
- 程序尝试覆盖/删除敏感内存变量，但 Python 无法完全保证内存清零。  
- 使用覆盖源文件前请先备份重要数据。  

---

## 文件列表 📁
- chacha20_poly1305_gui_v2.py — 主程序（GUI + 多线程实现）  
- README.md — 本文件  
- LICENSE — MIT 许可证

---

## 许可证 — MIT © 2025 📝
版权所有 (c) 2025 wangyifan349

特此免费授权任何获得本软件及相关文档文件（“软件”）副本的人无限制地使用本软件，包括但不限于使用、复制、修改、合并、发布、分发、再许可及/或出售软件副本的权利，并允许向其提供软件的人在遵守下列条件的情况下这样做：

上述版权声明和本许可声明应包含在本软件的所有副本或实质部分中。

本软件按“现状”提供，不附带任何形式的明示或暗示保证，包括但不限于对适销性、特定用途适用性及不侵权的保证。在任何情况下，作者或版权持有人都不对因软件或软件的使用或其他交易而产生的任何索赔、损害或其他责任负责，无论是合同诉讼、侵权或其他行为中产生的，还是由于或与软件或软件的使用或其他交易有关。

## 联系方式 ✉️
    GitHub: https://github.com/wangyifan349/password
---

## 联系方式 ✉️
GitHub: https://github.com/wangyifan349/password

---

谢谢使用！😊
