#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""微信文本聊天记录一键提取工具 (Windows)

双击运行：自动定位微信数据 -> 只读扫描进程内存取密钥 -> 解密数据库 ->
提取全部会话的文本聊天记录到 exe 同目录。

密钥提取思路来自 TANGandXUE/wcdb-key-tool (MIT)；
解密走 SQLCipher（若可用，合并 WAL）或纯标准库逐页解密（无第三方依赖）。
仅用于解密本人设备上本人账号的数据。
"""
import ctypes
import datetime
import glob
import hashlib
import hmac as hmac_mod
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b"SQLite format 3\x00"

CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
MAX_USER_ADDR = 0x0000_8000_0000_0000
CONFIG_BLOB_MAX = 1024
HEX_RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")

try:
    import sqlcipher3  # 可选：用于合并 WAL 的完整导出
except Exception:
    sqlcipher3 = None

try:
    import zstandard as zstd
    _dctx = zstd.ZstdDecompressor()
except Exception:
    _dctx = None

try:
    import ctypes.wintypes as wt
    _bcrypt = ctypes.WinDLL("bcrypt")
    _bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(wt.HANDLE), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    _bcrypt.BCryptSetProperty.argtypes = [wt.HANDLE, ctypes.c_wchar_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
    _bcrypt.BCryptGenerateSymmetricKey.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HANDLE), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
    _bcrypt.BCryptDecrypt.argtypes = [wt.HANDLE, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
except Exception:
    pass


def say(msg):
    print(msg, flush=True)


def pause():
    try:
        input("\n按回车退出...")
    except EOFError:
        pass


# ============================ AES-CBC (CNG) ============================
def aes_cbc_decrypt(key, iv, data):
    h_alg = wt.HANDLE()
    if _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0) != 0:
        raise RuntimeError("open AES provider failed")
    try:
        mode = ("ChainingModeCBC\x00").encode("utf-16-le")
        _bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, len(mode), 0)
        h_key = wt.HANDLE()
        if _bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0, key, len(key), 0) != 0:
            raise RuntimeError("gen key failed")
        try:
            iv_buf = ctypes.create_string_buffer(iv, len(iv))
            out = ctypes.create_string_buffer(len(data))
            n = ctypes.c_ulong(0)
            if _bcrypt.BCryptDecrypt(h_key, data, len(data), None, iv_buf, len(iv), out, len(out), ctypes.byref(n), 0) != 0:
                raise RuntimeError("decrypt failed")
            return out.raw[:n.value]
        finally:
            _bcrypt.BCryptDestroyKey(h_key)
    finally:
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def verify_enc_key(enc_key, page1):
    salt = page1[:SALT_SZ]
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, bytes(b ^ 0x3A for b in salt), 2, dklen=KEY_SZ)
    hm = hmac_mod.new(mac_key, page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]


# ============================ 内存扫描取密钥 ============================
def wechat_pids():
    pids = []
    for img in ("Weixin.exe", "WeChat.exe"):
        r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {img}", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for line in r.stdout.strip().splitlines():
            p = line.strip('"').split('","')
            if len(p) >= 5:
                try:
                    pids.append((int(p[1]), int(p[4].replace(",", "").replace(" K", "").strip() or 0)))
                except ValueError:
                    pass
    pids.sort(key=lambda x: x[1], reverse=True)
    return pids


def collect_db_files(db_dir):
    files, salt_to = [], {}
    for root, _d, names in os.walk(db_dir):
        for n in names:
            if not n.endswith(".db"):
                continue
            p = os.path.join(root, n)
            if os.path.getsize(p) < PAGE_SZ:
                continue
            with open(p, "rb") as f:
                page1 = f.read(PAGE_SZ)
            rel = os.path.relpath(p, db_dir)
            salt = page1[:SALT_SZ].hex()
            files.append((rel, p, salt, page1))
            salt_to.setdefault(salt, []).append(rel)
    return files, salt_to


def _xor(data, mask):
    return bytes(v ^ mask[i % len(mask)] for i, v in enumerate(data))


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0] if 0 <= o and o + 8 <= len(b) else 0


def _plausible_key(d):
    return len(d) == KEY_SZ and len(set(d)) >= 15 and d not in (b"\x00" * KEY_SZ, b"\xff" * KEY_SZ)


def _iter_chunks(regions, read, chunk=2 * 1024 * 1024, overlap=0):
    for base, size in regions:
        off, tail, tail_base = 0, b"", base
        while off < size:
            cur = min(chunk, size - off)
            c = read(base + off, cur) or b""
            data_base = tail_base if tail else base + off
            data = tail + c
            if data:
                yield data_base, data
                if overlap:
                    tail = data[-overlap:]
                    tail_base = data_base + max(0, len(data) - len(tail))
                else:
                    tail, tail_base = b"", base + off + cur
            else:
                tail, tail_base = b"", base + off + cur
            off += cur


def _find_bytes(regions, read, needle):
    out = set()
    for base, data in _iter_chunks(regions, read, overlap=max(0, len(needle) - 1)):
        pos = data.find(needle)
        while pos >= 0:
            out.add(base + pos)
            pos = data.find(needle, pos + 1)
    return out


def _candidates(blob):
    if not blob or len(blob) > CONFIG_BLOB_MAX:
        return []
    dec = _xor(blob, CONFIG_XOR_MASK)
    out, seen = [], set()
    for m in LITERAL_RE.finditer(dec):
        run = m.group(1).decode("ascii").lower()
        starts = [0]
        if len(run) > 96:
            starts += list(range(0, len(run) - 63, 32)) + [len(run) - 64]
        for s in dict.fromkeys(starts):
            if s < 0 or s + 64 > len(run):
                continue
            try:
                k = bytes.fromhex(run[s:s + 64])
            except ValueError:
                continue
            if not _plausible_key(k):
                continue
            emb = run[s + 64:s + 96] if s + 96 <= len(run) else None
            if (run[s:s + 64], emb) not in seen:
                seen.add((run[s:s + 64], emb))
                out.append((run[s:s + 64], emb))
    return out


def _scan_runtime(pid, regions, read, db_files, remaining, key_map):
    found = 0
    addrs = _find_bytes(regions, read, CONFIG_CIPHER_NAME)
    if not addrs:
        return 0
    patterns = [struct.pack("<Q", a) + struct.pack("<Q", len(CONFIG_CIPHER_NAME)) for a in addrs]
    seen = set()
    for base, data in _iter_chunks(regions, read, overlap=0x80):
        if not remaining:
            break
        for pat in patterns:
            pos = data.find(pat)
            while pos >= 0:
                qaddr = base + pos
                node = read(qaddr - 0x10, 0x50)
                if node and len(node) >= 0x40 and _u64(node, 0x10) in addrs and _u64(node, 0x18) == len(CONFIG_CIPHER_NAME):
                    cptr = _u64(node, 0x28)
                    if 0x10000 <= cptr < MAX_USER_ADDR:
                        obj = read(cptr + 0x88, 0x28)
                        if obj and len(obj) >= 0x18:
                            dptr, dlen = _u64(obj, 8), _u64(obj, 0x10)
                            if 0 < dlen <= CONFIG_BLOB_MAX and 0x10000 <= dptr < MAX_USER_ADDR:
                                blob = read(dptr, int(dlen))
                                if blob and len(blob) == dlen:
                                    for khex, emb in _candidates(blob):
                                        if (khex, emb) in seen:
                                            continue
                                        seen.add((khex, emb))
                                        try:
                                            k = bytes.fromhex(khex)
                                        except ValueError:
                                            continue
                                        targets = [emb] if emb in remaining else list(remaining)
                                        for sh in targets:
                                            if sh in remaining:
                                                for rel, _p, s, page1 in db_files:
                                                    if s == sh and verify_enc_key(k, page1):
                                                        key_map[sh] = khex
                                                        remaining.discard(sh)
                                                        found += 1
                                                        break
                pos = data.find(pat, pos + 1)
    return found


def extract_keys(db_dir):
    db_files, salt_to = collect_db_files(db_dir)
    say(f"[*] 发现 {len(db_files)} 个数据库，{len(salt_to)} 个独立 salt")
    k32, MEM_COMMIT, READABLE = ctypes.windll.kernel32, 0x1000, {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                    ("AllocationProtect", wt.DWORD), ("_p1", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_p2", wt.DWORD)]

    def read(h, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
            return buf.raw[:n.value]
        return None

    def regions_of(h):
        regs, addr, mbi = [], 0, MBI()
        while addr < 0x7FFFFFFFFFFF:
            if k32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
                regs.append((mbi.BaseAddress, mbi.RegionSize))
            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        return regs

    pids = wechat_pids()
    if not pids:
        say("[!] 未找到 Weixin.exe，请先启动并登录微信。")
        return {}, salt_to
    for pid, mem in pids:
        say(f"    微信进程 PID={pid} ({mem // 1024}MB)")
    key_map, remaining = {}, set(salt_to.keys())
    for pid, _ in pids:
        if not remaining:
            break
        h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not h:
            continue
        try:
            regs = regions_of(h)
            n = _scan_runtime(pid, regs, lambda a, s, _h=h: read(_h, a, s), db_files, remaining, key_map)
            if n:
                say(f"[+] 运行时 Config.Cipher 扫描命中 {n} 个 (PID={pid})")
            # 旧版本回退：直接扫明文 raw key
            if remaining:
                for base, size in regs:
                    if not remaining:
                        break
                    data = read(h, base, size)
                    if not data:
                        continue
                    for m in HEX_RE.finditer(data):
                        hs = m.group(1).decode()
                        if len(hs) < 96:
                            continue
                        khex, sh = hs[:64], hs[64:96]
                        if sh in remaining and verify_enc_key(bytes.fromhex(khex), dict((s, p) for _r, _pp, s, p in db_files)[sh]):
                            key_map[sh] = khex
                            remaining.discard(sh)
        finally:
            k32.CloseHandle(h)
    say(f"[+] 密钥: {len(key_map)}/{len(salt_to)}")
    return key_map, salt_to


# ============================ 解密 ============================
def _decrypt_page(key, page, pgno):
    iv = page[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    enc = page[SALT_SZ: PAGE_SZ - RESERVE_SZ] if pgno == 1 else page[:PAGE_SZ - RESERVE_SZ]
    dec = aes_cbc_decrypt(key, iv, enc)
    prefix = SQLITE_HDR if pgno == 1 else b""
    return prefix + dec + b"\x00" * RESERVE_SZ


def decrypt_all(db_dir, out_dir, key_map, db_files, salt_to):
    os.makedirs(out_dir, exist_ok=True)
    salt2key = {s: key_map[s] for s in key_map}
    ok = 0
    for rel, path, salt, _page1 in db_files:
        if salt not in salt2key:
            continue
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        khex = salt2key[salt]
        done = False
        if sqlcipher3 is not None:
            try:
                work = dst + ".enc"
                open(work, "wb").write(open(path, "rb").read())
                for suf in ("-wal", "-shm"):
                    if os.path.exists(path + suf):
                        open(work + suf, "wb").write(open(path + suf, "rb").read())
                if os.path.exists(dst):
                    os.remove(dst)
                con = sqlcipher3.connect(work)
                con.execute(f'PRAGMA key = "x\'{khex}\'";')
                con.execute("PRAGMA cipher_compatibility = 4;")
                con.execute(f"ATTACH DATABASE '{dst.replace(os.sep, '/')}' AS plain KEY '';")
                con.execute("SELECT sqlcipher_export('plain');")
                con.execute("DETACH DATABASE plain;")
                con.close()
                for suf in ("", "-wal", "-shm"):
                    if os.path.exists(work + suf):
                        os.remove(work + suf)
                done = True
            except Exception:
                done = False
        if not done:
            key = bytes.fromhex(khex)
            size = os.path.getsize(path)
            pages = size // PAGE_SZ + (1 if size % PAGE_SZ else 0)
            with open(path, "rb") as fi, open(dst, "wb") as fo:
                for pgno in range(1, pages + 1):
                    pg = fi.read(PAGE_SZ)
                    if len(pg) < PAGE_SZ:
                        if not pg:
                            break
                        pg += b"\x00" * (PAGE_SZ - len(pg))
                    fo.write(_decrypt_page(key, pg, pgno))
        ok += 1
    return ok


# ============================ 文本提取 ============================
TYPE_MAP = {1: "文本", 3: "图片", 34: "语音", 37: "好友请求", 42: "名片", 43: "视频",
            47: "表情", 48: "位置", 49: "应用消息", 50: "通话", 10000: "系统", 10002: "撤回"}
SUB_MAP = {1: "文字", 3: "音乐", 4: "视频", 5: "链接", 6: "文件", 8: "表情", 17: "位置共享",
           19: "合并转发", 24: "笔记", 33: "小程序", 36: "小程序", 51: "视频号", 53: "引用",
           57: "引用", 62: "直播", 87: "视频号", 2000: "转账", 2001: "红包"}


def to_text(v):
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        if _dctx and len(v) >= 4 and v[:4] == b"\x28\xb5\x2f\xfd":
            try:
                return _dctx.decompress(v).decode("utf-8", "replace")
            except Exception:
                pass
        return v.decode("utf-8", "replace")
    return str(v)


def appmsg(xml):
    def g(t):
        m = re.search(rf"<{t}>(.*?)</{t}>", xml, re.S)
        return re.sub(r"<!\[CDATA\[|\]\]>", "", m.group(1)).strip() if m else ""
    return g("title"), g("des"), g("url")


def safe(name):
    s = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", name).strip("._ ") or "unknown"
    return s[:90]


def extract_text(work, out, self_wxid):
    os.makedirs(out, exist_ok=True)
    usernames = set()
    disp = {}
    cpath = os.path.join(work, "contact", "contact.db")
    if os.path.exists(cpath):
        con = sqlite3.connect(cpath)
        for u, remark, nick, alias in con.execute("SELECT username, remark, nick_name, alias FROM contact"):
            disp[u] = remark or nick or alias or u
            usernames.add(u)
        con.close()
    spath = os.path.join(work, "session", "session.db")
    if os.path.exists(spath):
        con = sqlite3.connect(spath)
        for (u,) in con.execute("SELECT user_name FROM Name2Id"):
            usernames.add(u)
        con.close()

    msg_dbs = []
    md = os.path.join(work, "message")
    if os.path.isdir(md):
        msg_dbs += sorted(glob.glob(os.path.join(md, "message_*.db")))
        msg_dbs += sorted(glob.glob(os.path.join(md, "biz_message_*.db")))

    all_jsonl = open(os.path.join(out, "聊天记录.jsonl"), "w", encoding="utf-8")
    all_txt = open(os.path.join(out, "全部文本.txt"), "w", encoding="utf-8")
    by_dir = os.path.join(out, "按会话")
    os.makedirs(by_dir, exist_ok=True)
    summary = []
    total = 0
    for db in msg_dbs:
        con = sqlite3.connect(db)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        try:
            sender = {rid: u for rid, u in con.execute("SELECT rowid, user_name FROM Name2Id")}
        except Exception:
            sender = {}
        try:
            for (u,) in con.execute("SELECT user_name FROM Name2Id"):
                usernames.add(u)
        except Exception:
            pass
        md5map = {hashlib.md5(u.encode("utf-8")).hexdigest(): u for u in usernames}
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
        for t in tables:
            u = md5map.get(t[4:], t[4:12])
            name = disp.get(u, u)
            ct = "群聊" if u.endswith("@chatroom") else ("公众号" if u.startswith("gh_") or u.startswith("biz_") else "私聊")
            rows = None
            try:
                rows = con.execute(f'SELECT local_id, create_time, real_sender_id, local_type, message_content FROM "{t}" ORDER BY create_time').fetchall()
            except Exception:
                continue
            if not rows:
                continue
            path = os.path.join(by_dir, f"{safe(name)}__{safe(u)[-10:]}.txt")
            fo = open(path, "w", encoding="utf-8")
            fo.write(f"# {name} ({u}) [{ct}] 共 {len(rows)} 条\n\n")
            all_txt.write(f"\n\n{'='*60}\n# {name} ({u}) [{ct}] 共 {len(rows)} 条\n{'='*60}\n")
            for lid, ts, sid, lt, content in rows:
                total += 1
                su = sender.get(sid, "")
                who = "我" if su == self_wxid else disp.get(su, su or "?")
                raw = to_text(content)
                bt, sub = lt & 0xFFFFFFFF, lt >> 32
                body = ""
                kind = TYPE_MAP.get(bt, f"类型{bt}")
                if sub and bt == 49:
                    kind += f"·{SUB_MAP.get(sub, sub)}"
                if bt == 49 and raw.lstrip().startswith("<"):
                    title, des, url = appmsg(raw)
                    body = title or des or ""
                    if url:
                        body += f" [{url}]"
                elif bt == 1:
                    body = raw
                elif bt != 1:
                    body = f"[{kind}]"
                if not body.strip():
                    continue
                line = f"[{datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')}] {who}: {body}"
                fo.write(line + "\n")
                all_txt.write(line + "\n")
                all_jsonl.write(json.dumps({
                    "会话": name, "会话ID": u, "类型": ct,
                    "时间": datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                    "时间戳": ts, "发送者": who, "发送者ID": su,
                    "是本人": su == self_wxid,
                    "消息类型": kind, "文本": body,
                }, ensure_ascii=False) + "\n")
            fo.close()
            summary.append((total, name, u, ct, len(rows)))
        con.close()
    all_jsonl.close()
    all_txt.close()
    with open(os.path.join(out, "汇总.txt"), "w", encoding="utf-8") as f:
        f.write(f"微信文本聊天记录导出汇总\n导出时间: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n消息总数: {total}\n\n")
        for _i, name, u, ct, n in sorted(summary, key=lambda x: -x[4]):
            f.write(f"{n:7d}  [{ct}] {name}  ({u})\n")
    return total


def find_db_dirs():
    cands = []
    appdata = os.environ.get("APPDATA", "")
    cfg = os.path.join(appdata, "Tencent", "xwechat", "config")
    roots = []
    if os.path.isdir(cfg):
        for ini in glob.glob(os.path.join(cfg, "*.ini")):
            try:
                p = open(ini, encoding="utf-8").read(1024).strip()
            except Exception:
                try:
                    p = open(ini, encoding="gbk").read(1024).strip()
                except Exception:
                    continue
            if os.path.isdir(p):
                roots.append(p)
    roots.append(os.path.join(os.path.expanduser("~"), "Documents"))
    for r in roots:
        for m in glob.glob(os.path.join(r, "xwechat_files", "*", "db_storage")):
            if os.path.isdir(m):
                cands.append(m)
    return sorted(set(cands), key=lambda d: os.path.getsize(os.path.join(d, "message", "message_0.db")) if os.path.exists(os.path.join(d, "message", "message_0.db")) else 0, reverse=True)


def main():
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    base = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    try:
        _t = os.path.join(base, ".w_test")
        open(_t, "w").close()
        os.remove(_t)
    except Exception:
        base = os.path.join(os.path.expanduser("~"), "Desktop")
        os.makedirs(base, exist_ok=True)
    say("=" * 64)
    say("  微信文本聊天记录一键提取工具")
    say("  仅提取本人账号 · 全程本地 · 不联网")
    say("=" * 64)

    db_dirs = ([sys.argv[1]] if len(sys.argv) > 1 else []) or find_db_dirs()
    if not db_dirs:
        say("[!] 未找到微信数据目录。请确认微信已登录过，或把 db_storage 路径拖到本 exe 上。")
        pause()
        return
    db_dir = db_dirs[0]
    say(f"[*] 微信数据目录: {db_dir}")
    self_wxid = os.path.basename(os.path.dirname(db_dir))
    _m = re.match(r"^(.*)_[0-9a-fA-F]{4}$", self_wxid)
    if _m:
        self_wxid = _m.group(1)
    say(f"[*] 本人账号: {self_wxid}")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    work = tempfile.mkdtemp(prefix="wxtract_")
    out = os.path.join(base, f"微信聊天记录_{stamp}")
    os.makedirs(out, exist_ok=True)

    say("\n[1/3] 从微信进程内存提取密钥（只读）...")
    key_map, salt_to = extract_keys(db_dir)
    if not key_map:
        say("[!] 未能取得任何密钥。请确认：① 微信正在运行并已登录；② 以管理员身份运行。")
        pause()
        return

    say("\n[2/3] 解密数据库...")
    db_files, _ = collect_db_files(db_dir)
    n = decrypt_all(db_dir, work, key_map, db_files, salt_to)
    say(f"    已解密 {n} 个数据库" + ("" if sqlcipher3 is None else "（含 WAL 合并）"))

    say("\n[3/3] 提取文本聊天记录...")
    total = extract_text(work, out, self_wxid)
    say(f"\n完成！共 {total} 条消息")
    say(f"输出目录: {out}")
    say("  · 全部文本.txt        —— 所有聊天记录（可读）")
    say("  · 聊天记录.jsonl      —— 结构化数据")
    say("  · 按会话\\*.txt        —— 按聊天分组")
    say("  · 汇总.txt            —— 统计")
    shutil.rmtree(work, ignore_errors=True)
    pause()


if __name__ == "__main__":
    main()
