#!/usr/bin/env python3
import struct
import os
import gzip
import io

BASE_DIR = r"c:\Users\erlkim\Documents\huawei\b310-xray-panel"
FW_IN = os.path.join(BASE_DIR, r"B310S-927\Firmware\B310s-927_UPDATE_21.316.01.02.66.BIN")
FW_OUT = os.path.join(BASE_DIR, r"B310S-927\Firmware\B310s-927_UPDATE_21.316.01.02.66_XRAY_MOD.BIN")

PANEL_BIN = os.path.join(BASE_DIR, r"dist\b310-xray-panel")
XRAY_BIN = os.path.join(BASE_DIR, r"dist\xray")
NET_SCRIPT = os.path.join(BASE_DIR, r"dist\net.sh")

def crc_x25(data: bytes) -> int:
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc = crc >> 1
    return (~crc) & 0xffff

class CpioArchive:
    def __init__(self):
        self.entries = [] # list of (name, mode, ino, mtime, data)

    @classmethod
    def from_bytes(cls, raw: bytes):
        arc = cls()
        pos = 0
        total = len(raw)
        while pos < total - 110:
            hdr = raw[pos:pos+110]
            if not hdr.startswith(b'070701'):
                break
            ino = int(hdr[6:14], 16)
            mode = int(hdr[14:22], 16)
            mtime = int(hdr[46:54], 16)
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
            
            pos += 110
            name = raw[pos:pos+namesize].rstrip(b'\x00').decode('utf-8', errors='ignore')
            pad1 = (4 - ((110 + namesize) % 4)) % 4
            pos += namesize + pad1
            
            if name == 'TRAILER!!!':
                break
                
            file_data = raw[pos:pos+filesize]
            pad2 = (4 - (filesize % 4)) % 4
            pos += filesize + pad2
            
            arc.entries.append({
                'name': name,
                'mode': mode,
                'ino': ino,
                'mtime': mtime,
                'data': file_data
            })
        return arc

    def get_file(self, name: str):
        for e in self.entries:
            if e['name'] == name:
                return e['data']
        return None

    def set_file(self, name: str, new_data: bytes, mode: int = 0o100755, mtime: int = 0):
        for e in self.entries:
            if e['name'] == name:
                e['data'] = new_data
                return
        self.entries.append({
            'name': name,
            'mode': mode,
            'ino': len(self.entries) + 1,
            'mtime': mtime,
            'data': new_data
        })

    def to_bytes(self) -> bytes:
        out = io.BytesIO()
        for idx, e in enumerate(self.entries):
            name = e['name']
            data = e['data']
            mode = e['mode']
            ino = e.get('ino', idx + 1)
            mtime = e.get('mtime', 0)
            
            name_bytes = name.encode('utf-8') + b'\x00'
            namesize = len(name_bytes)
            filesize = len(data)
            
            hdr_str = (
                f"070701"
                f"{ino:08X}"
                f"{mode:08X}"
                f"{0:08X}" # uid
                f"{0:08X}" # gid
                f"{1:08X}" # nlink
                f"{mtime:08X}"
                f"{filesize:08X}"
                f"{0:08X}" # devmajor
                f"{0:08X}" # devminor
                f"{0:08X}" # rdevmajor
                f"{0:08X}" # rdevminor
                f"{namesize:08X}"
                f"{0:08X}" # check
            )
            out.write(hdr_str.encode('ascii'))
            out.write(name_bytes)
            pad1_len = (4 - ((110 + namesize) % 4)) % 4
            if pad1_len:
                out.write(b'\x00' * pad1_len)
                
            out.write(data)
            pad2_len = (4 - (filesize % 4)) % 4
            if pad2_len:
                out.write(b'\x00' * pad2_len)

        # Append TRAILER!!!
        trailer_name = b'TRAILER!!!\x00'
        t_namesize = len(trailer_name)
        t_hdr = (
            f"070701"
            f"{0:08X}{0:08X}{0:08X}{0:08X}{1:08X}{0:08X}"
            f"{0:08X}"
            f"{0:08X}{0:08X}{0:08X}{0:08X}"
            f"{t_namesize:08X}"
            f"{0:08X}"
        )
        out.write(t_hdr.encode('ascii'))
        out.write(trailer_name)
        pad_t = (4 - ((110 + t_namesize) % 4)) % 4
        if pad_t:
            out.write(b'\x00' * pad_t)
            
        # Pad entire archive to 512 bytes (standard cpio block)
        cur_len = out.tell()
        pad_end = (512 - (cur_len % 512)) % 512
        if pad_end:
            out.write(b'\x00' * pad_end)
            
        return out.getvalue()

def build_partition_header(meta_template: bytes, file_seq: int, payload: bytes) -> bytes:
    file_size = len(payload)
    num_blocks = (file_size + 4095) // 4096
    hdr_len = 98 + 2 * num_blocks
    
    # Template contains: seq(4), hwid(8), file_seq(4), file_size(4), date(16), time(16), name(32)...
    # Construct base 98-byte header
    base98 = bytearray(98)
    base98[0:4] = b'\x55\xaa\x5a\xa5'
    base98[4:8] = struct.pack('<I', hdr_len)
    base98[8:8+len(meta_template)] = meta_template[:90] # copy sequence, hwid, dates, name
    
    # Update file_seq, file_size
    base98[20:24] = struct.pack('<I', file_seq)
    base98[24:28] = struct.pack('<I', file_size)
    
    # Zero out CRC field at 92:94 for header calculation
    base98[92:94] = b'\x00\x00'
    base98[94:98] = b'\x00\x10\x00\x00' # block size = 4096
    
    hdr_crc = crc_x25(bytes(base98))
    base98[92:94] = struct.pack('<H', hdr_crc)
    
    # Calculate block CRCs
    crc_table = bytearray(2 * num_blocks)
    for b_idx in range(num_blocks):
        chunk = payload[b_idx*4096 : min(file_size, (b_idx+1)*4096)]
        c = crc_x25(chunk)
        crc_table[b_idx*2 : b_idx*2 + 2] = struct.pack('<H', c)
        
    return bytes(base98) + bytes(crc_table)

def main():
    print(f"Reading base firmware: {FW_IN}")
    with open(FW_IN, 'rb') as f:
        hdr92 = f.read(92)
        partitions = []
        while True:
            pos = f.tell()
            magic = f.read(4)
            if magic != b'\x55\xaa\x5a\xa5':
                break
            hdr_len = struct.unpack('<I', f.read(4))[0]
            data = f.read(hdr_len - 8)
            file_seq = struct.unpack('<I', data[12:16])[0]
            file_size = struct.unpack('<I', data[16:20])[0]
            payload = f.read(file_size)
            align = (4 - ((hdr_len + file_size) % 4)) % 4
            padding = f.read(align)
            
            partitions.append({
                'pos': pos,
                'magic': magic,
                'hdr_len': hdr_len,
                'data': data,
                'file_seq': file_seq,
                'file_size': file_size,
                'payload': payload,
                'align': align
            })

    print(f"Loaded {len(partitions)} partitions.")
    
    # -------------------------------------------------------------
    # 1. Modify Partition 9 (system, FileSeq 0x590000)
    # -------------------------------------------------------------
    print("\n[Part 1] Modifying Partition 9 (system)...")
    part9 = partitions[8]
    assert part9['file_seq'] == 0x590000, f"Expected 0x590000, got {hex(part9['file_seq'])}"
    
    sys_arc = CpioArchive.from_bytes(part9['payload'])
    print(f"Unpacked system CPIO: {len(sys_arc.entries)} entries.")
    
    with open(PANEL_BIN, 'rb') as f:
        panel_bytes = f.read()
    with open(XRAY_BIN, 'rb') as f:
        xray_bytes = f.read()
    with open(NET_SCRIPT, 'rb') as f:
        net_bytes = f.read()
        
    print(f"  Injecting bin/b310-xray-panel ({len(panel_bytes)} bytes)")
    sys_arc.set_file("bin/b310-xray-panel", panel_bytes, mode=0o100755)
    
    print(f"  Injecting bin/xray ({len(xray_bytes)} bytes)")
    sys_arc.set_file("bin/xray", xray_bytes, mode=0o100755)
    
    print(f"  Injecting etc/xray/net.sh ({len(net_bytes)} bytes)")
    sys_arc.set_file("etc/xray/net.sh", net_bytes, mode=0o100755)
    
    # Modify etc/autorun.sh
    autorun_orig = sys_arc.get_file("etc/autorun.sh").decode('utf-8', errors='ignore')
    if "/system/bin/b310-xray-panel" not in autorun_orig:
        hook = (
            "\n# Start Erlkim Xray Web Panel & Watchdog\n"
            "/system/bin/b310-xray-panel > /dev/null 2>&1 &\n"
        )
        # Place before comment padding blocks
        if "#=========================================================================" in autorun_orig:
            parts = autorun_orig.split("#=========================================================================", 1)
            autorun_mod = parts[0] + hook + "\n#=========================================================================" + parts[1]
        else:
            autorun_mod = autorun_orig + hook
            
        sys_arc.set_file("etc/autorun.sh", autorun_mod.encode('utf-8'), mode=0o100755)
        print("  Updated etc/autorun.sh with startup hook.")
        
    new_sys_payload = sys_arc.to_bytes()
    print(f"Repacked system CPIO: {len(new_sys_payload)} bytes ({len(new_sys_payload)/1024/1024:.2f} MB)")
    part9['payload'] = new_sys_payload
    
    # -------------------------------------------------------------
    # 2. Modify Partition 11 (webui, FileSeq 0x5b0000)
    # -------------------------------------------------------------
    print("\n[Part 2] Modifying Partition 11 (webui)...")
    part11 = partitions[10]
    assert part11['file_seq'] == 0x5b0000, f"Expected 0x5b0000, got {hex(part11['file_seq'])}"
    
    web_arc = CpioArchive.from_bytes(part11['payload'])
    print(f"Unpacked webui CPIO: {len(web_arc.entries)} entries.")
    
    # Modify header.html.gz
    hdr_gz = web_arc.get_file("WebApp/common/html/header.html.gz")
    hdr_html = gzip.decompress(hdr_gz).decode('utf-8', errors='ignore')
    
    if 'id="menu_xray"' not in hdr_html:
        nav_tab = (
            '\n\t\t\t\t<li id="menu_xray">\n'
            '\t\t\t\t    <a id="xray" href="xray.html">\n'
            '\t\t\t\t    <span style="color:#ff7597;font-weight:bold">🌸 XRAY</span>\n'
            '\t\t\t\t    </a>\n'
            '\t\t\t\t</li>\n'
        )
        # Insert after <li id="menu_settings"> ... </li>
        target = '</li>\n                <li id="menu_settings">'
        if target in hdr_html:
            hdr_html = hdr_html.replace(target, '</li>' + nav_tab + '                <li id="menu_settings">', 1)
        else:
            hdr_html = hdr_html.replace('</ul>', nav_tab + '            </ul>', 1)
            
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', mtime=0) as gz_out:
            gz_out.write(hdr_html.encode('utf-8'))
        web_arc.set_file("WebApp/common/html/header.html.gz", buf.getvalue(), mode=0o100644)
        print("  Injected '🌸 XRAY' navigation button in WebApp/common/html/header.html.gz")
        
    # Inject xray.html.gz (seamless iframe embedding)
    xray_html_content = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Erlkim Xray Panel - Huawei B310s</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body, html { width: 100%; height: 100%; background: #0d0a1a; overflow: hidden; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.top-bar {
  height: 42px; background: rgba(16, 12, 30, 0.95); border-bottom: 1px solid rgba(236,72,153,0.35);
  display: flex; align-items: center; justify-content: space-between; padding: 0 16px; color: #fff;
}
.brand-title { font-size: 0.88rem; font-weight: 700; color: #ff7597; display: flex; align-items: center; gap: 8px; }
.links { display: flex; gap: 10px; }
.btn-nav {
  color: #fdf2f8; text-decoration: none; font-size: 0.74rem; font-weight: 600;
  background: rgba(236,72,153,0.2); border: 1px solid rgba(236,72,153,0.4);
  padding: 4px 10px; border-radius: 8px; transition: all 0.2s;
}
.btn-nav:hover { background: rgba(236,72,153,0.35); }
iframe { width: 100%; height: calc(100% - 42px); border: none; }
</style>
</head>
<body>
<div class="top-bar">
  <div class="brand-title">
    <span>🌸</span> Erlkim Xray Panel <small style="color:#a855f7;font-size:0.75rem">(Huawei B310s-927)</small>
  </div>
  <div class="links">
    <a href="http://192.168.8.1:5000" target="_blank" class="btn-nav">↗ Buka Layar Penuh (Port :5000)</a>
    <a href="home.html" class="btn-nav">← Menu Router</a>
  </div>
</div>
<iframe src="http://192.168.8.1:5000"></iframe>
</body>
</html>"""

    buf_xray = io.BytesIO()
    with gzip.GzipFile(fileobj=buf_xray, mode='wb', mtime=0) as gz_out:
        gz_out.write(xray_html_content.encode('utf-8'))
    web_arc.set_file("WebApp/common/html/xray.html.gz", buf_xray.getvalue(), mode=0o100644)
    print("  Injected WebApp/common/html/xray.html.gz (Iframe wrapper).")

    new_web_payload = web_arc.to_bytes()
    print(f"Repacked webui CPIO: {len(new_web_payload)} bytes ({len(new_web_payload)/1024/1024:.2f} MB)")
    part11['payload'] = new_web_payload
    
    # -------------------------------------------------------------
    # 3. Assemble and Write Final .BIN Firmware File
    # -------------------------------------------------------------
    print(f"\n[Part 3] Rebuilding firmware into {FW_OUT}...")
    with open(FW_OUT, 'wb') as out_f:
        # 1. Write 92-byte multicast tool header
        out_f.write(hdr92)
        
        # 2. Write partitions
        for idx, p in enumerate(partitions):
            p_seq = p['file_seq']
            payload = p['payload']
            
            # Check if this partition was modified
            if p_seq in (0x590000, 0x5b0000):
                hdr = build_partition_header(p['data'], p_seq, payload)
            else:
                # Keep original header
                hdr = p['magic'] + struct.pack('<I', p['hdr_len']) + p['data']
                
            out_f.write(hdr)
            out_f.write(payload)
            
            align = (4 - ((len(hdr) + len(payload)) % 4)) % 4
            if align:
                out_f.write(b'\x00' * align)
                
            print(f"  Written partition {idx+1:02d} (0x{p_seq:06x}): Hdr {len(hdr)}B, Payload {len(payload)}B, Align {align}B")

    final_size = os.path.getsize(FW_OUT)
    orig_size = os.path.getsize(FW_IN)
    diff_mb = (final_size - orig_size) / (1024 * 1024)
    print(f"\nSUCCESS! Created {FW_OUT}")
    print(f"Original size: {orig_size / (1024*1024):.2f} MB")
    print(f"Modified size: {final_size / (1024*1024):.2f} MB (+{diff_mb:.2f} MB)")

if __name__ == '__main__':
    main()
