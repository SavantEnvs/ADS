#!/usr/bin/env python3
"""Regenerate the starter seeds under mayhem/<target>/testsuite/ (committed; build.sh does not
run this). The input layout each harness expects is documented at the top of its source in
mayhem/harnesses/ and in fake_ads_server.h."""
import os
import struct

ROOT = os.path.dirname(os.path.abspath(__file__))
le16 = lambda v: struct.pack('<H', v)
le32 = lambda v: struct.pack('<I', v)
le64 = lambda v: struct.pack('<Q', v)
LOCAL = bytes([192, 168, 0, 1, 1, 1])
REMOTE = bytes([5, 6, 7, 8, 1, 1])


def chunk(payload, mode=0):
    return bytes([mode]) + le16(len(payload)) + payload


def ok(data=b''):  # AoEResponseHeader result + data
    return chunk(le32(0) + data)


def rd(data, result=0):  # AoEReadResponseHeader result + readLength + data
    return chunk(le32(result) + le32(len(data)) + data)


def lstr(s):
    return bytes([len(s)]) + s


def lblob(s):
    return le16(len(s)) + s


def raw_frame(cmd, payload, port=851, invoke=0):
    aoe = LOCAL + le16(30000) + REMOTE + le16(port) + le16(cmd) + le16(4) + \
        le32(len(payload)) + le32(0) + le32(invoke)
    return chunk(aoe + payload, mode=0xF0)


def notification(handle, sample):
    stamp = le64(0x01D0000000000000) + le32(1) + le32(handle) + le32(len(sample)) + sample
    body = le32(1) + stamp
    return le32(len(body)) + body


def symbol_entry(name, typ, comment, size, dtype, group=0x4040, offs=0):
    body = name + b'\0' + typ + b'\0' + comment + b'\0'
    hdr = struct.pack('<IIIIIIHHH', 30 + len(body), group, offs, size, dtype, 0,
                      len(name), len(typ), len(comment))
    return hdr + body


def find_data(name, attr):
    return le32(7) + le32(attr) + b'\0' * 40 + name.ljust(260, b'\0') + b'\0' * 14


REG = open(os.path.join(ROOT, '..', 'tools', 'test-data', 'simple.reg'), 'rb').read()

seeds = {
    'fuzz_ams_connection': {
        'mixed': bytes([2 | (3 << 3), 0, 1, 3 | (1 << 3), 4, 5, 6, 7]) +
        ok(le32(1)) +                                  # add notification -> handle 1
        raw_frame(8, notification(1, b'\x2a\0\0\0')) +  # one notification sample
        rd(b'A' * 25) +                                # read
        ok(le32(0x00030001) + b'Plc30 App\0'.ljust(16, b'\0')) +  # device info
        ok(le16(5) + le16(0)) +                        # read state
        rd(b'\x01\x02\x03\x04') +                      # read/write
        ok() + ok() +                                  # write, write control
        ok(le32(2)) + ok() +                           # add + del notification
        ok(),                                          # final del notification
        'notify-burst': bytes([2] * 8) + ok(le32(1)) +
        raw_frame(8, notification(1, b'\x01\x02\x03\x04')) +
        raw_frame(8, notification(1, b'')) +
        rd(b'\x07'),
    },
    'fuzz_symbol_access': {
        'show': b'\0' + lstr(b'MAIN.x') + lstr(b'42') +
        rd(le32(2) + le32(2 * 30 + 30)) +
        rd(symbol_entry(b'MAIN.x', b'DINT', b'', 4, 3) + symbol_entry(b'MAIN.b', b'BOOL', b'c', 1, 0x21)),
        'read': b'\x01' + lstr(b'MAIN.x') + lstr(b'') +
        rd(le32(1) + le32(30 + 13)) + rd(symbol_entry(b'MAIN.x', b'DINT', b'', 4, 3)) +
        rd(le32(1234)),
        'write': b'\x02' + lstr(b'MAIN.x') + lstr(b'0x10') +
        rd(le32(1) + le32(30 + 13)) + rd(symbol_entry(b'MAIN.x', b'DINT', b'', 4, 3)) + ok(),
    },
    'fuzz_registry_verify': {
        'simple.reg': REG,
        'small.reg': b'Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\A]\r\n'
                     b'"s"="a\\\\b\\"c"\r\n"d"=dword:00000001\r\n"h"=hex:00,ff\r\n',
    },
    'fuzz_ads_file': {
        'find': b'\0\x02' + lstr(b'C:\\TwinCAT') +
        rd(find_data(b'TwinCAT', 0x10)) + rd(find_data(b'.', 0x10)) +
        rd(find_data(b'file.txt', 0x20)) + rd(b'', result=1804) + rd(b'', result=1804),
        'read': b'\x01\0' + lstr(b'C:\\a.txt') + rd(le32(9)) + rd(b'hello') + rd(b'') + rd(b''),
        'delete': b'\x02\0' + lstr(b'C:\\a.txt') + rd(b''),
        'rename': b'\x03\0' + lstr(b'C:\\a.txt') + rd(b''),
    },
    'fuzz_udp_discovery': {
        'netid': b'\0' + le32(0x71146603) + le32(0) + le32(0x80000001) + REMOTE + le16(10000) +
        le32(1) + le16(5) + le16(4) + b'plc\0',
        'addroute': b'\x01' + le32(0x71146603) + le32(0) + le32(0x80000006) + REMOTE + le16(10000) +
        le32(2) + le16(5) + le16(4) + b'plc\0' + le16(1) + le16(4) + le32(0),
    },
    'fuzz_rtime_access': {
        'read-latency': b'\0' + le32(1) +
        rd(le32(1) + le32(1) + le64(3) + le32(1) + le32(0) + le32(6) + le32(3000)) +
        rd(le32(10) + le32(20) + le32(30)) + rd(le32(11) + le32(21) + le32(31)),
        'reset-latency': b'\x01' + le32(1) +
        rd(le32(1) + le32(1) + le64(3) + le32(1) + le32(0) + le32(6) + le32(3000)) +
        rd(le32(10) + le32(20) + le32(30)),
        'shared-cores': b'\x02' + le32(1) +
        rd(le32(1) + le32(1) + le64(3) + le32(1) + le32(0) + le32(6) + le32(3000)) + ok() + ok(),
        'cpu-settings': b'\x03' + le32(0) +
        rd(le32(2) + le32(2) + le64(0xf) + le32(2) + le32(1) + le32(6) + le32(2400)),
    },
    'fuzz_registry_access': {
        'export': b'\0' + lstr(b'HKEY_LOCAL_MACHINE\\SOFTWARE\\Test') + lblob(b'') +
        rd(b'Sub\0') + rd(b'', result=0x710) +
        rd(b'REG_SZ\0' + le32(1) + b'str\0') + rd(le32(4) + b'\0'), 
        'import': b'\x01' + lstr(b'') + lblob(REG) + ok() * 12,
    },
    'fuzz_service_access': {
        f'svc{i}': bytes([i]) + le32(0x15ad) + le32(0x0405) +
        rd(le32(2) + le32(1) + le32(3) + b'\x01' * 24) + rd(le32(1) + le16(1) + b'\x02' * 30) +
        rd(b'\x03' * 32) + rd(b'\x04' * 16) + ok() + ok()
        for i in range(9)
    },
}

for target, files in seeds.items():
    d = os.path.join(ROOT, target, 'testsuite')
    os.makedirs(d, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(d, name), 'wb') as f:
            f.write(data)
