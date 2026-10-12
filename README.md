# wxtract · 微信文本聊天记录一键提取工具（Windows）

双击即可把**本人微信（Windows 4.x）的全部文本聊天记录**导出成本地文件。

全程只在本机完成：**不联网、不上传、不修改微信**，只读取你登录了自己账号的微信数据。

> ⚠️ **仅用于解密你自己设备上、你自己账号的数据。** 导出的记录里包含大量隐私（包括聊天对象的），请自行妥善保管，不要外传。

## 它能导出什么

| 文件 | 内容 |
| --- | --- |
| `全部文本.txt` | 所有聊天，按会话分组，人类可读 |
| `聊天记录.jsonl` | 结构化数据（每行一条，含发送者 / 时间 / 类型 / 是否本人） |
| `按会话\*.txt` | 每个聊天一个文件 |
| `汇总.txt` | 各会话消息条数统计 |

输出长这样：

```text
[2026-01-01 12:00:00] 张三: 晚上一起吃饭吗
[2026-01-01 12:05:00] 我: 可以 几点
```

发送者显示为「我」的是你本人；链接 / 文件 / 引用 / 合并转发等会取出标题文字和 URL。

## 怎么用（exe）

1. 先启动微信并保持登录状态（密钥只存在于运行中的微信进程内存里）
2. 双击 `微信文本记录导出.exe`
3. UAC 弹窗点「是」（读取微信进程内存需要管理员权限）
4. 等待自动完成（约 1~3 分钟，取决于聊天记录多少）
5. 完成后 exe 同目录出现 `微信聊天记录_日期_时间\` 文件夹

## 从源码运行

```sh
git clone https://github.com/<你的用户名>/wxtract
cd wxtract
pip install -r requirements.txt   # 可选，装上功能更全
python wxtract.py [db_storage路径] # 需管理员权限；参数可省略，自动定位
```

可选依赖（不装也能跑）：

- `sqlcipher3`：走 SQLCipher 完整解密并**合并 WAL**（拿到最新消息）；编译困难时可用 `pip install sqlcipher3-binary`
- `zstandard`：解压新版微信的 zstd 压缩消息内容

没有任何必需第三方依赖：纯标准库也能逐页解密数据库。

## 打包 exe

```sh
pip install pyinstaller
pyinstaller --onefile --uac-admin --name wxtract wxtract.py
```

`--uac-admin` 让 exe 双击就请求管理员权限（读微信进程内存必需）。

## 工作原理

1. **定位数据目录**：读 `%APPDATA%\Tencent\xwechat\config\*.ini` 和 `Documents\xwechat_files\*\db_storage`
2. **取密钥**：微信 4.1+ 数据库用 SQLCipher4 加密，密钥不落盘、只在登录时算一次留在内存。本工具用 `ReadProcessMemory` **只读**扫描微信进程内存中的 `com.Tencent.WCDB.Config.Cipher` 运行时对象，XOR 解码配置拿到候选密钥
3. **校验**：用数据库第一页的 HMAC（PBKDF2-SHA512 派生 mac key）确认密钥正确
4. **解密**：有 `sqlcipher3` 时解密并合并 WAL；没有时用 Windows CNG（bcrypt）AES-CBC 逐页解密
5. **提取**：解析 message / contact / session 数据库，导出文本

密钥提取思路来自开源项目 [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool)（MIT），感谢。

## 常见问题

- **提示「未找到微信数据目录」**：确认微信登录过；或把 `...\xwechat_files\...\db_storage` 文件夹拖到 exe 上
- **提示「未能取得任何密钥」**：确认微信正在运行且已登录，并用管理员身份运行
- **微信更新后失败**：新版本密钥方案可能变化，等本项目跟进
- **导出目录不能写**（例如放在 `C:\Program Files`）：会自动改存到桌面

## 隐私与合规

- 仅解密**你自己设备上、你自己账号**的数据
- 工具不修改微信、不访问网络、不上传任何数据
- 输出目录含全部聊天明文，泄露风险等同于手机聊天记录本身，请加密妥善保管

## License

MIT。密钥提取思路来自 [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool)（MIT）。

---

### English summary

One-click local exporter for **your own** WeChat (Windows 4.x) text chat history. Locates the WeChat data directory, extracts the SQLCipher key by **read-only** scanning of the running WeChat process memory (HMAC-verified), decrypts the databases (SQLCipher4 / WAL-aware), and writes human-readable `.txt` plus structured `.jsonl` exports. No network access, no uploads, standard library only (optional `sqlcipher3` / `zstandard` for full fidelity). Key-extraction approach adapted from [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) (MIT). **Use only on your own device and account.**
