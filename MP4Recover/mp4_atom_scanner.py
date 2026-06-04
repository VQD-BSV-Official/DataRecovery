#!/usr/bin/env python3
"""
MP4 / MOV Atom Scanner & File Size Estimator
=============================================
Dùng để phân tích cấu trúc atom trong file MP4/MOV hoặc raw binary dump.
Hỗ trợ:
  - Scan file MP4 thông thường
  - Scan raw disk image / binary dump
  - Tính toán dung lượng từ atom headers
  - Xuất báo cáo chi tiết

Tác giả: mp4_atom_scanner.py
Sử dụng: python mp4_atom_scanner.py <file>
"""

import struct
import os
import sys
import argparse
import json
import mmap
import ctypes
import multiprocessing
from pathlib import Path
from datetime import datetime


# ──────────────────────────────────────────────────────────────
# Windows raw device helpers
# ──────────────────────────────────────────────────────────────
def is_raw_device(filepath: str) -> bool:
    r"""Kiểm tra có phải Windows raw device path không (\\.\X: hoặc \\.\PhysicalDriveN)"""
    return filepath.startswith('\\\\.\\')


def get_device_size(filepath: str) -> int:
    """
    Lấy kích thước thực của file hoặc raw device.
    os.path.getsize() trả về 0 với \\.\C: nên cần dùng cách khác.
    """
    if not is_raw_device(filepath):
        return os.path.getsize(filepath)

    # Cách 1: DeviceIoControl IOCTL_DISK_GET_LENGTH_INFO
    try:
        GENERIC_READ      = 0x80000000
        FILE_SHARE_READ   = 0x00000001
        FILE_SHARE_WRITE  = 0x00000002
        OPEN_EXISTING     = 3
        INVALID_HANDLE    = ctypes.c_void_p(-1).value
        IOCTL_DISK_GET_LENGTH_INFO = 0x7405C

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            filepath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if handle == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())

        length = ctypes.c_int64(0)
        bytes_ret = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            ctypes.byref(length), ctypes.sizeof(length),
            ctypes.byref(bytes_ret),
            None
        )
        ctypes.windll.kernel32.CloseHandle(handle)
        if ok and length.value > 0:
            return length.value
    except Exception:
        pass

    # Cách 2: Seek to end
    try:
        with open(filepath, 'rb', buffering=0) as f:
            f.seek(0, 2)
            size = f.tell()
            if size > 0:
                return size
    except Exception:
        pass

    return 0


def open_device(filepath: str, buffering: int = 0):
    """
    Mở file hoặc raw device.
    Raw device PHẢI dùng buffering=0 (unbuffered) trên Windows.
    """
    if is_raw_device(filepath):
        return open(filepath, 'rb', buffering=0)
    return open(filepath, 'rb')


# ──────────────────────────────────────────────────────────────
# Màu sắc terminal
# ──────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def cprint(color, text):
    print(f"{color}{text}{C.RESET}")

def fmt_size(n: int) -> str:
    """Định dạng bytes → human readable"""
    if n < 1024:
        return f"{n} B"
    elif n < 1024**2:
        return f"{n/1024:.2f} KB"
    elif n < 1024**3:
        return f"{n/1024**2:.2f} MB"
    else:
        return f"{n/1024**3:.3f} GB"


# ──────────────────────────────────────────────────────────────
# Danh sách atom đã biết
# ──────────────────────────────────────────────────────────────
KNOWN_ATOMS = {
    # Container atoms (có thể chứa atom con)
    'moov': ('Container', 'Movie metadata container'),
    'trak': ('Container', 'Track container'),
    'mdia': ('Container', 'Media information container'),
    'minf': ('Container', 'Media information'),
    'stbl': ('Container', 'Sample table'),
    'dinf': ('Container', 'Data information'),
    'edts': ('Container', 'Edit list container'),
    'udta': ('Container', 'User data'),
    'ilst': ('Container', 'iTunes metadata list'),
    'meta': ('Container', 'Metadata container'),

    # Data atoms quan trọng
    'ftyp': ('Header',    'File type & compatibility → xác định loại file'),
    'mdat': ('Data',      'Media data → chứa raw video/audio frames'),
    'free': ('Padding',   'Free space / padding'),
    'skip': ('Padding',   'Skip / padding'),
    'wide': ('Padding',   'Wide box / reserved'),
    'pnot': ('Info',      'Preview'),

    # Movie/Track header
    'mvhd': ('Header',    'Movie header → duration, timescale, creation time'),
    'tkhd': ('Header',    'Track header → track ID, duration, dimensions'),
    'mdhd': ('Header',    'Media header → language, timescale'),
    'hdlr': ('Handler',   'Handler reference → video/audio/text'),
    'smhd': ('Header',    'Sound media header'),
    'vmhd': ('Header',    'Video media header'),
    'nmhd': ('Header',    'Null media header'),

    # Sample table
    'stsd': ('Table',     'Sample description → codec info (avc1, mp4a...)'),
    'stts': ('Table',     'Time-to-sample table → frame timing'),
    'stsc': ('Table',     'Sample-to-chunk table → chunk mapping'),
    'stsz': ('Table',     'Sample size table → kích thước từng frame'),
    'stco': ('Table',     'Chunk offset table 32-bit → vị trí dữ liệu'),
    'co64': ('Table',     'Chunk offset table 64-bit → vị trí dữ liệu (>4GB)'),
    'ctts': ('Table',     'Composition time offset'),
    'stss': ('Table',     'Sync sample table → keyframes'),

    # Data reference
    'dref': ('Ref',       'Data reference'),
    'url ': ('Ref',       'URL data reference'),
    'urn ': ('Ref',       'URN data reference'),

    # Edit
    'elst': ('Edit',      'Edit list → timeline mapping'),

    # Extra / metadata
    'uuid': ('UUID',      'Extended UUID box'),
    'iods': ('Descriptor','Initial object descriptor'),
    'esds': ('Descriptor','Elementary stream descriptor → codec params'),
    'avcC': ('Config',    'AVC/H.264 decoder config'),
    'hvcC': ('Config',    'HEVC/H.265 decoder config'),
    'mp4a': ('Codec',     'MPEG-4 audio'),
    'avc1': ('Codec',     'H.264 video'),
    'hev1': ('Codec',     'H.265/HEVC video'),
    'hvc1': ('Codec',     'H.265/HEVC video'),
    'av01': ('Codec',     'AV1 video'),
    'vp09': ('Codec',     'VP9 video'),
}

# Atoms là container (cần đệ quy vào)
CONTAINER_ATOMS = {
    'moov','trak','mdia','minf','stbl','dinf',
    'edts','udta','ilst','moof','traf','mvex',
}


# ──────────────────────────────────────────────────────────────
# Parser chính
# ──────────────────────────────────────────────────────────────
class AtomParser:
    def __init__(self, filepath: str, verbose: bool = False):
        self.filepath  = filepath
        self.file_size = get_device_size(filepath)
        self.verbose   = verbose
        self.atoms     = []          # flat list tất cả atoms
        self.errors    = []
        self._f        = None

    def _read(self, n: int) -> bytes:
        data = self._f.read(n)
        if len(data) < n:
            raise EOFError(f"Unexpected EOF (cần {n} bytes, đọc được {len(data)})")
        return data

    def _read_atom_header(self, offset: int):
        """
        Đọc header của 1 atom tại offset.
        Trả về (atom_type, header_size, total_size, data_offset)
        """
        self._f.seek(offset)
        raw = self._f.read(8)
        if len(raw) < 8:
            return None

        size32    = struct.unpack('>I', raw[0:4])[0]
        atom_type = raw[4:8]

        try:
            type_str = atom_type.decode('ascii')
        except Exception:
            type_str = atom_type.hex()

        # size = 1 → extended 64-bit size ở bytes 8-15
        if size32 == 1:
            ext_raw = self._f.read(8)
            if len(ext_raw) < 8:
                return None
            total_size  = struct.unpack('>Q', ext_raw)[0]
            header_size = 16
        # size = 0 → kéo dài đến hết file
        elif size32 == 0:
            total_size  = self.file_size - offset
            header_size = 8
        else:
            total_size  = size32
            header_size = 8

        data_offset = offset + header_size
        return type_str, header_size, total_size, data_offset

    def parse(self, offset: int = 0, end: int = None, depth: int = 0, parent: str = None):
        """Đệ quy parse atoms từ offset đến end"""
        if end is None:
            end = self.file_size

        while offset < end:
            if end - offset < 8:
                break

            result = self._read_atom_header(offset)
            if result is None:
                break

            type_str, header_size, total_size, data_offset = result

            # Sanity check
            if total_size < 8 and total_size != 0:
                if self.verbose:
                    cprint(C.RED, f"{'  '*depth}[!] Invalid atom size {total_size} @ offset {offset}")
                offset += 4
                continue

            if total_size > (self.file_size - offset) * 2:
                if self.verbose:
                    cprint(C.RED, f"{'  '*depth}[!] Atom size exceeds file @ offset {offset}")
                break

            data_size = total_size - header_size

            atom_info = {
                'type':        type_str,
                'offset':      offset,
                'total_size':  total_size,
                'header_size': header_size,
                'data_size':   data_size,
                'depth':       depth,
                'parent':      parent,
            }

            # Thêm thông tin đã biết
            if type_str in KNOWN_ATOMS:
                atom_info['category'], atom_info['description'] = KNOWN_ATOMS[type_str]
            else:
                atom_info['category']    = 'Unknown'
                atom_info['description'] = '(không xác định)'

            # Parse thêm nội dung cho một số atom quan trọng
            atom_info['extra'] = self._parse_atom_data(type_str, data_offset, data_size)

            self.atoms.append(atom_info)

            # Đệ quy vào container atoms
            if type_str in CONTAINER_ATOMS and data_size > 0:
                child_end = offset + total_size
                self.parse(
                    offset = data_offset,
                    end    = min(child_end, self.file_size),
                    depth  = depth + 1,
                    parent = type_str,
                )

            offset += total_size

    def _parse_atom_data(self, atom_type: str, data_offset: int, data_size: int) -> dict:
        """Parse nội dung chi tiết của một số atom đặc biệt"""
        extra = {}
        try:
            self._f.seek(data_offset)

            if atom_type == 'ftyp' and data_size >= 4:
                major_brand = self._f.read(4).decode('ascii', errors='replace')
                minor_ver   = struct.unpack('>I', self._f.read(4))[0] if data_size >= 8 else 0
                compat_count = (data_size - 8) // 4
                compat = []
                for _ in range(min(compat_count, 8)):
                    b = self._f.read(4)
                    if len(b) == 4:
                        compat.append(b.decode('ascii', errors='replace').strip())
                extra = {
                    'major_brand':       major_brand,
                    'minor_version':     minor_ver,
                    'compatible_brands': compat,
                }

            elif atom_type == 'mvhd' and data_size >= 20:
                version = struct.unpack('>B', self._f.read(1))[0]
                self._f.read(3)  # flags
                if version == 1:
                    create_time = struct.unpack('>Q', self._f.read(8))[0]
                    modify_time = struct.unpack('>Q', self._f.read(8))[0]
                    timescale   = struct.unpack('>I', self._f.read(4))[0]
                    duration    = struct.unpack('>Q', self._f.read(8))[0]
                else:
                    create_time = struct.unpack('>I', self._f.read(4))[0]
                    modify_time = struct.unpack('>I', self._f.read(4))[0]
                    timescale   = struct.unpack('>I', self._f.read(4))[0]
                    duration    = struct.unpack('>I', self._f.read(4))[0]

                dur_sec = duration / timescale if timescale else 0
                extra = {
                    'version':    version,
                    'timescale':  timescale,
                    'duration_units': duration,
                    'duration_sec':   round(dur_sec, 3),
                    'duration_fmt':   _fmt_duration(dur_sec),
                }

            elif atom_type == 'tkhd' and data_size >= 20:
                version = struct.unpack('>B', self._f.read(1))[0]
                self._f.read(3)
                if version == 1:
                    self._f.read(8+8)
                    track_id = struct.unpack('>I', self._f.read(4))[0]
                    self._f.read(4)
                    duration = struct.unpack('>Q', self._f.read(8))[0]
                else:
                    self._f.read(4+4)
                    track_id = struct.unpack('>I', self._f.read(4))[0]
                    self._f.read(4)
                    duration = struct.unpack('>I', self._f.read(4))[0]
                # skip to width/height
                self._f.read(8+36)  # reserved + matrix
                width_fp  = struct.unpack('>I', self._f.read(4))[0]
                height_fp = struct.unpack('>I', self._f.read(4))[0]
                extra = {
                    'track_id': track_id,
                    'duration_units': duration,
                    'width':  width_fp >> 16,
                    'height': height_fp >> 16,
                }

            elif atom_type == 'hdlr' and data_size >= 12:
                self._f.read(4+4)  # version+flags, pre_defined
                handler = self._f.read(4).decode('ascii', errors='replace')
                handler_map = {
                    'vide': 'Video track',
                    'soun': 'Audio track',
                    'text': 'Text/subtitle track',
                    'tmcd': 'Timecode track',
                    'data': 'Data track',
                }
                extra = {
                    'handler_type': handler.strip(),
                    'handler_name': handler_map.get(handler.strip(), 'Unknown'),
                }

            elif atom_type == 'mdat':
                extra = {
                    'note': 'Raw media data (video + audio frames)',
                    'data_size_actual': data_size,
                }

            elif atom_type == 'stsz' and data_size >= 12:
                self._f.read(4)  # version+flags
                sample_size  = struct.unpack('>I', self._f.read(4))[0]
                sample_count = struct.unpack('>I', self._f.read(4))[0]
                extra = {
                    'sample_size':  sample_size,
                    'sample_count': sample_count,
                    'note': 'Uniform size' if sample_size > 0 else f'{sample_count} variable-size samples',
                }

            elif atom_type == 'stco' and data_size >= 8:
                self._f.read(4)
                entry_count = struct.unpack('>I', self._f.read(4))[0]
                offsets = []
                for _ in range(min(entry_count, 3)):
                    o = struct.unpack('>I', self._f.read(4))[0]
                    offsets.append(o)
                extra = {
                    'entry_count':    entry_count,
                    'first_offsets':  offsets,
                }

            elif atom_type == 'co64' and data_size >= 8:
                self._f.read(4)
                entry_count = struct.unpack('>I', self._f.read(4))[0]
                offsets = []
                for _ in range(min(entry_count, 3)):
                    o = struct.unpack('>Q', self._f.read(8))[0]
                    offsets.append(o)
                extra = {
                    'entry_count':   entry_count,
                    'first_offsets': offsets,
                    'note':          '64-bit offsets (file > 4GB)',
                }

        except Exception as e:
            extra['parse_error'] = str(e)

        return extra

    def run(self):
        cprint(C.BOLD + C.CYAN, f"\n{'='*60}")
        cprint(C.BOLD + C.WHITE, f"  MP4 Atom Scanner")
        cprint(C.CYAN, f"{'='*60}")
        print(f"  File : {self.filepath}")
        print(f"  Size : {fmt_size(self.file_size)}  ({self.file_size:,} bytes)")
        cprint(C.CYAN, f"{'='*60}\n")

        with open_device(self.filepath) as f:
            self._f = f
            self.parse()

        self._print_tree()
        self._print_size_report()
        self._print_summary()
        return self.atoms

    def _print_tree(self):
        cprint(C.BOLD + C.YELLOW, "\n📦 CẤU TRÚC ATOM TREE")
        cprint(C.YELLOW, "─" * 60)

        CAT_COLOR = {
            'Data':      C.RED,
            'Header':    C.CYAN,
            'Container': C.BLUE,
            'Table':     C.GREEN,
            'Codec':     C.YELLOW,
            'Config':    C.YELLOW,
            'Padding':   C.GRAY,
        }

        for a in self.atoms:
            indent = "  " * a['depth']
            prefix = "└─ " if a['depth'] > 0 else "▶ "
            cat    = a.get('category', '')
            color  = CAT_COLOR.get(cat, C.WHITE)

            size_str = fmt_size(a['total_size'])
            desc     = a.get('description', '')

            print(f"{indent}{prefix}{color}{C.BOLD}{a['type']}{C.RESET}"
                  f"  {C.GRAY}{size_str:>12}{C.RESET}"
                  f"  {C.GRAY}@{a['offset']:,}{C.RESET}"
                  f"  {color}{desc}{C.RESET}")

            # In extra info
            extra = a.get('extra', {})
            if extra and 'parse_error' not in extra:
                for k, v in extra.items():
                    if k == 'note':
                        continue
                    print(f"{indent}   {C.GRAY}├ {k}: {C.WHITE}{v}{C.RESET}")

    def _print_size_report(self):
        cprint(C.BOLD + C.GREEN, "\n\n📊 PHÂN TÍCH DUNG LƯỢNG")
        cprint(C.GREEN, "─" * 60)

        # Chỉ lấy top-level atoms (depth=0)
        top_atoms = [a for a in self.atoms if a['depth'] == 0]

        total_from_atoms = sum(a['total_size'] for a in top_atoms)
        mdat_atoms = [a for a in self.atoms if a['type'] == 'mdat']
        moov_atoms = [a for a in self.atoms if a['type'] == 'moov']

        # Bảng top-level
        print(f"\n  {'Atom':<8} {'Size':>14} {'Size (bytes)':>16}  Mô tả")
        print(f"  {'─'*8} {'─'*14} {'─'*16}  {'─'*20}")

        for a in top_atoms:
            pct = a['total_size'] / self.file_size * 100
            bar = int(pct / 5) * '█'
            print(f"  {C.BOLD}{a['type']:<8}{C.RESET}"
                  f" {fmt_size(a['total_size']):>14}"
                  f" {a['total_size']:>16,}"
                  f"  {bar} {pct:.1f}%")

        print(f"  {'─'*8} {'─'*14} {'─'*16}")
        print(f"  {'TỔNG':<8} {fmt_size(total_from_atoms):>14} {total_from_atoms:>16,}")
        print(f"  {'FILE':<8} {fmt_size(self.file_size):>14} {self.file_size:>16,}")

        # So sánh
        diff = abs(total_from_atoms - self.file_size)
        diff_pct = diff / self.file_size * 100 if self.file_size else 0
        print()
        if diff_pct < 0.1:
            cprint(C.GREEN, f"  ✓ Atom sizes khớp hoàn hảo với file size (±{diff_pct:.3f}%)")
        elif diff_pct < 1.0:
            cprint(C.YELLOW, f"  ⚠ Sai lệch nhỏ: {fmt_size(diff)} ({diff_pct:.2f}%) - có thể có padding")
        else:
            cprint(C.RED, f"  ✗ Sai lệch lớn: {fmt_size(diff)} ({diff_pct:.1f}%) - file có thể bị cắt xén")

        # Chi tiết mdat
        if mdat_atoms:
            print()
            cprint(C.BOLD + C.RED, "  📹 Chi tiết MDAT (Media Data):")
            for i, m in enumerate(mdat_atoms):
                pct = m['total_size'] / self.file_size * 100
                print(f"    mdat #{i+1}:")
                print(f"      Offset      : {m['offset']:,} bytes")
                print(f"      Total size  : {fmt_size(m['total_size'])} ({m['total_size']:,} bytes)")
                print(f"      Header size : {m['header_size']} bytes {'(extended 64-bit)' if m['header_size']==16 else '(standard 32-bit)'}")
                print(f"      Data size   : {fmt_size(m['data_size'])} ({m['data_size']:,} bytes)")
                print(f"      % of file   : {pct:.2f}%")
                print(f"      End offset  : {m['offset'] + m['total_size']:,} bytes")

        # Chi tiết moov
        if moov_atoms:
            print()
            cprint(C.BOLD + C.BLUE, "  🎬 Chi tiết MOOV (Metadata):")
            for m in moov_atoms:
                extra = m.get('extra', {})
                print(f"    Offset     : {m['offset']:,} bytes")
                print(f"    Total size : {fmt_size(m['total_size'])}")

            # Tìm mvhd trong children
            mvhd = next((a for a in self.atoms if a['type'] == 'mvhd'), None)
            if mvhd and mvhd.get('extra'):
                e = mvhd['extra']
                print(f"    Duration   : {e.get('duration_fmt','?')} ({e.get('duration_sec','?')}s)")
                print(f"    Timescale  : {e.get('timescale','?')} units/sec")

    def _print_summary(self):
        cprint(C.BOLD + C.CYAN, "\n\n📋 TÓM TẮT")
        cprint(C.CYAN, "─" * 60)

        atom_types = list(dict.fromkeys(a['type'] for a in self.atoms))
        has_moov = 'moov' in atom_types
        has_mdat = 'mdat' in atom_types
        has_co64 = 'co64' in atom_types
        has_avc1 = 'avc1' in atom_types
        has_hev1 = 'hev1' in atom_types or 'hvc1' in atom_types

        print(f"  Tổng số atoms   : {len(self.atoms)}")
        print(f"  Loại atoms      : {', '.join(atom_types)}")
        print(f"  Có moov box     : {'✓' if has_moov else '✗ (file có thể bị hỏng!)'}")
        print(f"  Có mdat box     : {'✓' if has_mdat else '✗'}")
        print(f"  64-bit offsets  : {'✓ (co64 - file >4GB)' if has_co64 else 'Không (stco 32-bit)'}")
        print(f"  Video codec     : {'H.264 (avc1)' if has_avc1 else 'H.265/HEVC' if has_hev1 else 'Xem stsd'}")

        ftyp = next((a for a in self.atoms if a['type'] == 'ftyp'), None)
        if ftyp and ftyp.get('extra'):
            e = ftyp['extra']
            print(f"  File brand      : {e.get('major_brand','?')}")
            print(f"  Compat brands   : {', '.join(e.get('compatible_brands', []))}")

        # Cảnh báo
        warnings = []
        if not has_moov:
            warnings.append("MOOV box thiếu → metadata mất, cần dùng untrunc để phục hồi")
        if not has_mdat:
            warnings.append("MDAT box thiếu → không có media data")
        top = [a for a in self.atoms if a['depth'] == 0]
        total_top = sum(a['total_size'] for a in top)
        if abs(total_top - self.file_size) / self.file_size > 0.01:
            warnings.append(f"Tổng atom size ({fmt_size(total_top)}) ≠ file size ({fmt_size(self.file_size)}) → file bị cắt xén hoặc có trailing data")

        if warnings:
            print()
            cprint(C.YELLOW, "  ⚠ Cảnh báo:")
            for w in warnings:
                cprint(C.YELLOW, f"    • {w}")

        print()
        cprint(C.GREEN, "  ✓ Scan hoàn tất!")
        print()


# ──────────────────────────────────────────────────────────────
# Raw Disk Scanner (tìm MP4 trên raw image)
# ──────────────────────────────────────────────────────────────
class RawScanner:
    """Quét raw disk image / Windows device để tìm MP4 atom signatures"""

    SECTOR_SIZE = 512
    # Chunk 128MB - sector-aligned, đọc nhanh trên NVMe/SSD
    # Phải là bội số của 512 để Windows không báo lỗi EINVAL
    CHUNK       = 128 * 1024 * 1024

    # ftyp signatures phổ biến
    FTYP_BRANDS = [
        b'isom', b'iso2', b'iso4', b'iso5', b'iso6',
        b'mp41', b'mp42', b'M4V ', b'M4A ', b'M4P ',
        b'qt  ', b'MSNV', b'avc1', b'f4v ', b'dash',
        b'3gp4', b'3gp5', b'3gp6', b'HEVC',
    ]

    def __init__(self, filepath: str, max_scan_gb: float = None):
        self.filepath   = filepath
        self.file_size  = get_device_size(filepath)
        self.scan_limit = int(max_scan_gb * 1024**3) if max_scan_gb else self.file_size
        self._is_device = is_raw_device(filepath)

    def _aligned(self, n: int) -> int:
        """Làm tròn n xuống bội số của SECTOR_SIZE (bắt buộc với raw device)"""
        return (n // self.SECTOR_SIZE) * self.SECTOR_SIZE

    def _read_chunk(self, f, offset: int, size: int) -> bytes:
        """
        Đọc chunk từ device, đảm bảo sector-aligned.
        Windows yêu cầu offset VÀ size đều phải là bội số 512.
        """
        aligned_offset = self._aligned(offset)
        aligned_size   = self._aligned(size + self.SECTOR_SIZE)  # luôn đủ lớn
        try:
            f.seek(aligned_offset)
            data = f.read(aligned_size)
            # Cắt đúng phần cần
            skip = offset - aligned_offset
            return data[skip:skip + size]
        except OSError as e:
            # EINVAL thường là do misaligned access
            cprint(C.RED, f"\n  [!] Read error @ {offset:,}: {e}")
            return b''

    def scan(self):
        cprint(C.BOLD + C.CYAN, f"\n{'='*60}")
        cprint(C.BOLD + C.WHITE, f"  RAW DISK SCANNER - Tìm MP4 Atoms")
        cprint(C.CYAN, f"{'='*60}")
        print(f"  File   : {self.filepath}")

        if self.file_size == 0:
            cprint(C.RED, "\n  ✗ Không lấy được kích thước! Kiểm tra:")
            cprint(C.YELLOW, "    1. Chạy cmd.exe với quyền Administrator")
            cprint(C.YELLOW, "    2. Dùng đúng path: \\\\.\\ C:  hoặc  \\\\.\\PhysicalDrive0")
            return []

        print(f"  Size   : {fmt_size(self.file_size)}  ({self.file_size:,} bytes)")
        scan_end = min(self.scan_limit, self.file_size)
        print(f"  Scan   : {fmt_size(scan_end)}")
        if self._is_device:
            cprint(C.YELLOW, f"  Mode   : Raw Windows Device (sector-aligned reads)")
        cprint(C.CYAN, f"{'='*60}\n")

        candidates = []
        last_pct   = -1

        with open_device(self.filepath) as f:
            offset = 0
            scanned = 0

            while offset < scan_end:
                # Sector-align chunk size
                remaining  = scan_end - offset
                chunk_size = self._aligned(min(self.CHUNK, remaining))
                if chunk_size == 0:
                    break

                f.seek(offset)
                try:
                    data = f.read(chunk_size)
                except OSError as e:
                    cprint(C.RED, f"\n  [!] Lỗi đọc @ {offset:,}: {e}")
                    offset += self.SECTOR_SIZE
                    continue

                if not data:
                    break

                # Tìm 'ftyp' trong chunk - bước nhảy theo sector để nhanh
                pos = 0
                dlen = len(data)
                while pos < dlen - 12:
                    if data[pos+4:pos+8] == b'ftyp':
                        abs_offset = offset + pos
                        brand = data[pos+8:pos+12]
                        if any(brand == b for b in self.FTYP_BRANDS):
                            size32 = struct.unpack('>I', data[pos:pos+4])[0]
                            cprint(C.GREEN,
                                f"\n  ✓ ftyp @ {abs_offset:,} ({fmt_size(abs_offset)})"
                                f"  brand={brand.decode('ascii','replace')}"
                                f"  size={size32}")
                            candidates.append(abs_offset)
                        pos += self.SECTOR_SIZE  # bước 512 bytes
                    else:
                        pos += self.SECTOR_SIZE

                scanned += len(data)
                pct = int(scanned / scan_end * 100)
                if pct != last_pct:
                    mb_s_hint = ""
                    print(f"\r  Tiến độ: {pct:3d}%  {fmt_size(scanned)} / {fmt_size(scan_end)}"
                          f"  [{offset:,}]{mb_s_hint}     ", end='', flush=True)
                    last_pct = pct
                offset += len(data)

        print(f"\n\n  Tìm thấy {len(candidates)} MP4 signature(s).\n")

        # Parse từng candidate
        results = []
        for i, start_offset in enumerate(candidates):
            print(f"  {'─'*50}")
            print(f"  Candidate #{i+1} @ offset {start_offset:,} ({fmt_size(start_offset)})")
            try:
                parser = AtomParser(self.filepath, verbose=False)
                parser.file_size = self.file_size
                with open_device(self.filepath) as f:
                    parser._f = f
                    parser.parse(
                        offset = start_offset,
                        end    = min(start_offset + 10 * 1024**3, self.file_size)
                    )

                top      = [a for a in parser.atoms if a['depth'] == 0]
                est_size = sum(a['total_size'] for a in top)
                print(f"    Atoms     : {[a['type'] for a in top]}")
                print(f"    Est. size : {fmt_size(est_size)} ({est_size:,} bytes)")
                results.append({'offset': start_offset, 'estimated_size': est_size, 'atoms': top})
            except Exception as e:
                print(f"    Error: {e}")

        return results


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def _fmt_duration(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = seconds % 60
    if h > 0:
        return f"{h}h {m:02d}m {s:05.2f}s"
    elif m > 0:
        return f"{m}m {s:05.2f}s"
    else:
        return f"{s:.2f}s"


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='MP4 Atom Scanner & File Size Estimator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  # Phân tích file MP4 bình thường
  python mp4_atom_scanner.py video.mp4

  # Phân tích file MOV
  python mp4_atom_scanner.py clip.mov

  # Quét raw disk image tìm MP4 (giới hạn 10GB đầu)
  python mp4_atom_scanner.py disk.img --raw --limit 10

  # Xuất kết quả JSON
  python mp4_atom_scanner.py video.mp4 --json output.json
        """
    )
    parser.add_argument('file',          help='File MP4/MOV hoặc raw disk image')
    parser.add_argument('--raw',         action='store_true', help='Chế độ quét raw disk image')
    parser.add_argument('--limit',       type=float, default=None, metavar='GB',
                        help='Giới hạn scan (GB), chỉ dùng với --raw')
    parser.add_argument('--json',        metavar='OUTPUT', help='Xuất kết quả ra file JSON')
    parser.add_argument('-v','--verbose',action='store_true', help='Verbose mode')

    args = parser.parse_args()

    # os.path.exists() trả về False với \\.\C: nên cần check riêng
    filepath = args.file
    if is_raw_device(filepath):
        # Thử mở để xác nhận có tồn tại / có quyền
        try:
            with open(filepath, 'rb', buffering=0) as _test:
                pass
        except PermissionError:
            cprint(C.RED, f"✗ Không có quyền truy cập: {filepath}")
            cprint(C.YELLOW, "  → Chạy lại cmd.exe với quyền Administrator")
            sys.exit(1)
        except FileNotFoundError:
            cprint(C.RED, f"✗ Không tìm thấy device: {filepath}")
            cprint(C.YELLOW, "  → Thử \\\\.\\ C:  hoặc  \\\\.\\PhysicalDrive0")
            sys.exit(1)
        except Exception as e:
            cprint(C.RED, f"✗ Lỗi mở device: {e}")
            sys.exit(1)
    elif not os.path.exists(filepath):
        cprint(C.RED, f"✗ File không tồn tại: {filepath}")
        sys.exit(1)

    if args.raw:
        scanner = RawScanner(filepath, max_scan_gb=args.limit)
        results = scanner.scan()
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            cprint(C.GREEN, f"\n  ✓ JSON xuất ra: {args.json}")
    else:
        ap = AtomParser(filepath, verbose=args.verbose)
        atoms = ap.run()
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(atoms, f, indent=2, default=str)
            cprint(C.GREEN, f"\n  ✓ JSON xuất ra: {args.json}")


if __name__ == '__main__':
    main()
