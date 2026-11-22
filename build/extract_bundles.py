#!/usr/bin/env python3
"""
Extract embedded assets (daemons, bundles, Xray-core, geo data)
from an existing vpn-ui-amd64 binary into backend/bin/amd64 and corebundle/core.
"""

import os
import sys
import struct

KNOWN_FILES = [
    # backend daemons and archives
    ("bin/amd64/libreswan-bundle.tgz", "backend/bin/amd64/libreswan-bundle.tgz"),
    ("bin/amd64/accel-ppp-bundle.tgz", "backend/bin/amd64/accel-ppp-bundle.tgz"),
    ("bin/amd64/strongswan-bundle.tgz", "backend/bin/amd64/strongswan-bundle.tgz"),
    ("bin/amd64/sstpc-bundle.tgz", "backend/bin/amd64/sstpc-bundle.tgz"),
    ("bin/amd64/pppd-bundle.tgz", "backend/bin/amd64/pppd-bundle.tgz"),
    ("bin/amd64/sstp-pppd-plugin.so", "backend/bin/amd64/sstp-pppd-plugin.so"),
    ("bin/amd64/telemt", "backend/bin/amd64/telemt"),
    ("bin/amd64/pptp", "backend/bin/amd64/pptp"),
    ("bin/amd64/openconnect", "backend/bin/amd64/openconnect"),
    ("bin/amd64/vpnc-script", "backend/bin/amd64/vpnc-script"),
    ("bin/amd64/xl2tpd", "backend/bin/amd64/xl2tpd"),
    ("bin/amd64/xl2tpd-control", "backend/bin/amd64/xl2tpd-control"),
    ("bin/amd64/openvpn", "backend/bin/amd64/openvpn"),
    ("bin/amd64/pptpd", "backend/bin/amd64/pptpd"),
    ("bin/amd64/pptpctrl", "backend/bin/amd64/pptpctrl"),
    ("bin/amd64/ocserv", "backend/bin/amd64/ocserv"),
    ("bin/amd64/occtl", "backend/bin/amd64/occtl"),

    # core and geo files
    ("core/amd64/xray", "corebundle/core/amd64/xray"),
    ("core/geoip.dat", "corebundle/core/geoip.dat"),
    ("core/geosite.dat", "corebundle/core/geosite.dat"),
    ("core/geoip_IR.dat", "corebundle/core/geoip_IR.dat"),
    ("core/geosite_IR.dat", "corebundle/core/geosite_IR.dat"),
    ("core/geoip_RU.dat", "corebundle/core/geoip_RU.dat"),
    ("core/geosite_RU.dat", "corebundle/core/geosite_RU.dat"),
]

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_bundles.py <path-to-vpn-ui-amd64>")
        sys.exit(1)

    bin_path = sys.argv[1]
    if not os.path.exists(bin_path):
        print(f"Error: {bin_path} not found")
        sys.exit(1)

    print(f"Reading {bin_path}...")
    with open(bin_path, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        print("Error: Input file is not an ELF binary")
        sys.exit(1)

    e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
    e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
    e_phnum = struct.unpack('<H', data[0x38:0x3a])[0]

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[off:off+4])[0]
        if p_type == 1: # PT_LOAD
            p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
            p_vaddr = struct.unpack('<Q', data[off+16:off+24])[0]
            p_filesz = struct.unpack('<Q', data[off+32:off+40])[0]
            segments.append((p_vaddr, p_offset, p_filesz))

    def vaddr_to_offset(vaddr):
        for p_vaddr, p_offset, p_filesz in segments:
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None

    def offset_to_vaddr(offset):
        for p_vaddr, p_offset, p_filesz in segments:
            if p_offset <= offset < p_offset + p_filesz:
                return p_vaddr + (offset - p_offset)
        return None

    extracted_count = 0
    for embed_name, out_path in KNOWN_FILES:
        target_bytes = embed_name.encode('utf-8')
        start = 0
        found = False

        while True:
            pos = data.find(target_bytes, start)
            if pos == -1:
                break

            vaddr = offset_to_vaddr(pos)
            if vaddr is not None:
                needle = struct.pack('<QQ', vaddr, len(target_bytes))
                ref_pos = data.find(needle)
                if ref_pos != -1:
                    data_vaddr, data_len = struct.unpack('<QQ', data[ref_pos+16:ref_pos+32])
                    data_offset = vaddr_to_offset(data_vaddr)
                    if data_offset is not None and data_offset + data_len <= len(data):
                        payload = data[data_offset:data_offset+data_len]
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, 'wb') as out_f:
                            out_f.write(payload)
                        # Set executable permission if in bin or xray
                        if "bin" in out_path or "xray" in out_path:
                            try:
                                os.chmod(out_path, 0o755)
                            except Exception:
                                pass
                        print(f"  [+] Extracted: {embed_name} -> {out_path} ({len(payload):,} bytes)")
                        extracted_count += 1
                        found = True
                        break
            start = pos + 1

        if not found:
            print(f"  [-] Not found or skipped: {embed_name}")

    print(f"\nDone! Extracted {extracted_count} / {len(KNOWN_FILES)} files.")

if __name__ == "__main__":
    main()
