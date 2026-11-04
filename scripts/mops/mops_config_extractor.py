#!/usr/bin/env python3
import sys
import re
import struct
import json
import lief

MAX_WRAPPER_SCAN = 0x80
MAX_LEA_LOOKBACK = 0x20
MAX_NUL_SCAN = 0x400

LEA_RCX_RIP = b"\x48\x8d\x0d"
CMP_IMM8 = re.compile(rb"\x48\x83(?:\x7c\x24|\x7d)(.)(.)", re.S)
CMP_IMM32 = re.compile(rb"\x48\x81(?:\x7c\x24|\x7d)(.)(....)", re.S)
LEA_CALL = re.compile(rb"\x48\x8d\x0d(....)\xe8(....)", re.S)
CALL = re.compile(rb"\xe8(....)", re.S)
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# Globals for decryption keys
G_MULT = 13
G_ADD = -105

def dec_byte(b: int, i: int) -> int:
    r = i % 7 + 1
    return (((b << (8 - r)) | (b >> r)) & 0xFF) ^ ((G_MULT * i + G_ADD) & 0xFF)

def decrypt(data: bytes, length: int, width: int) -> bytes:
    return bytes(dec_byte(data[i * width], i) for i in range(length))

def is_clean(plain: bytes) -> bool:
    text = plain.rstrip(b"\0")
    return bool(text) and all(c in PRINTABLE for c in text)

class Image:
    def __init__(self, path: str):
        pe = lief.parse(path)
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"Not a valid PE file: {path}")
            
        self.base = pe.optional_header.imagebase
        self.mem = bytearray(pe.optional_header.sizeof_image)
        self.code = []
        exec_flag = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
        
        for s in pe.sections:
            content = bytes(s.content)
            rva = s.virtual_address
            self.mem[rva:rva + len(content)] = content
            if s.has_characteristic(exec_flag):
                self.code.append((rva, rva + max(s.virtual_size, len(content))))

    def read(self, va: int, n: int) -> bytes:
        rva = va - self.base
        return bytes(self.mem[rva:rva + n])

    def rva_ok(self, rva: int) -> bool:
        return 0 <= rva < len(self.mem)

def wrapper_length(img: Image, wrapper_va: int) -> int:
    body = img.read(wrapper_va, MAX_WRAPPER_SCAN)
    hits = []
    if m := CMP_IMM8.search(body):
        hits.append((m.start(), m.group(2)[0]))
    if m := CMP_IMM32.search(body):
        hits.append((m.start(), struct.unpack("<I", m.group(2))[0]))
    if not hits:
        return None
    n = min(hits)[1]
    return n if 0 < n <= MAX_NUL_SCAN else None

def wrapper_width(img: Image, wrapper_va: int) -> int:
    return 2 if b"\x66\x89" in img.read(wrapper_va, MAX_WRAPPER_SCAN) else 1

def wrapper_calls(img: Image, wrapper_va: int) -> set:
    body = img.read(wrapper_va, MAX_WRAPPER_SCAN)
    return {wrapper_va + m.start() + 5 + struct.unpack("<i", m.group(1))[0] for m in CALL.finditer(body)}

def solve(img: Image, blob_va: int, length: int, hint: int = 1):
    for width in (hint, 3 - hint):
        raw = img.read(blob_va, (length or MAX_NUL_SCAN) * width)
        if length:
            plain = decrypt(raw, length, width)
        else:
            plain = bytearray()
            for i in range(len(raw) // width):
                c = dec_byte(raw[i * width], i)
                plain.append(c)
                if c == 0: break
            plain = bytes(plain)
        if is_clean(plain):
            return width, len(plain), plain.rstrip(b"\0").decode("latin-1")
    return None

def find_wrappers(img: Image) -> dict:
    cand = {}
    for start, end in img.code:
        seg = img.mem[start:end]
        for m in LEA_CALL.finditer(seg):
            lea_rva = start + m.start()
            blob_rva = lea_rva + 7 + struct.unpack("<i", m.group(1))[0]
            w_rva = lea_rva + 12 + struct.unpack("<i", m.group(2))[0]
            if img.rva_ok(blob_rva) and any(s <= w_rva < e for s, e in img.code):
                cand.setdefault(img.base + w_rva, []).append(img.base + blob_rva)

    wrappers = {}
    for w, blobs in cand.items():
        n = wrapper_length(img, w)
        if n is None or not wrapper_calls(img, w): continue
        if any(solve(img, b, n, wrapper_width(img, w)) for b in blobs):
            wrappers[w] = n

    counts = {}
    for w in wrappers:
        for t in wrapper_calls(img, w):
            counts[t] = counts.get(t, 0) + 1
    prims = {t for t, c in counts.items() if c >= 3}
    return {w: n for w, n in wrappers.items() if wrapper_calls(img, w) & prims}

def init_keys(path: str):
    global G_MULT, G_ADD
    with open(path, 'rb') as f:
        data = f.read()
    
    matches = re.findall(b'\x0F\xB6\xC0\x6B\xC0(.)([\x05\x2D])(.)\x00\x00\x00\x25\xFF\x00\x00\x00', data)
    if matches:
        mult, op, val = matches[0]
        G_MULT = mult[0]
        G_ADD = val[0] if op == b'\x05' else -val[0]
    else:
        G_MULT = 13
        G_ADD = 151

def extract_config(path: str) -> dict:
    init_keys(path)
    img = Image(path)
    wrappers = find_wrappers(img)
    seen = set()
    strings = []
    
    for start, end in img.code:
        seg = img.mem[start:end]
        for m in CALL.finditer(seg):
            call_rva = start + m.start()
            tgt = img.base + call_rva + 5 + struct.unpack("<i", m.group(1))[0]
            if tgt not in wrappers: continue
            
            call_va = img.base + call_rva
            back = img.read(call_va - MAX_LEA_LOOKBACK, MAX_LEA_LOOKBACK)
            i = back.rfind(LEA_RCX_RIP)
            if i < 0: continue
            
            lea_va = call_va - MAX_LEA_LOOKBACK + i
            blob = lea_va + 7 + struct.unpack("<i", img.read(lea_va + 3, 4))[0]
            if blob in seen: continue
            
            res = solve(img, blob, wrappers[tgt], wrapper_width(img, tgt))
            if not res: continue
            
            seen.add(blob)
            strings.append(res[2])

    config = {
        "c2": [],
        "ports": [],
        "campaign_id": None,
        "version": None,
        "install_path": None,
    }
    
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    ver_pattern = re.compile(r'^\d+\.\d+\.\d+$')
    
    excluded_domains = {'.exe', '.dll', '.sys', '.org'}
    
    for s in strings:
        if ip_pattern.match(s):
            if s not in config["c2"]:
                config["c2"].append(s)
        elif domain_pattern.match(s) and not any(s.lower().endswith(ext) for ext in excluded_domains):
            # It's a domain!
            if s not in config["c2"]:
                config["c2"].append(s)
        elif ver_pattern.match(s) and config["version"] is None:
            config["version"] = s
        elif s.isdigit():
            val = int(s)
            if val > 10000 and config["campaign_id"] is None:
                config["campaign_id"] = s
            elif 1 <= val <= 65535 and val not in (7, 8, 10, 11):
                if s not in config["ports"]:
                    config["ports"].append(s)
        elif s.endswith(".exe") and "\\" in s and config["install_path"] is None:
            config["install_path"] = s

    return config

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_payload.exe>")
        sys.exit(1)
        
    try:
        cfg = extract_config(sys.argv[1])
        print(json.dumps(cfg, indent=2))
    except Exception as e:
        print(f"[-] Error extracting config: {e}")
        sys.exit(1)
