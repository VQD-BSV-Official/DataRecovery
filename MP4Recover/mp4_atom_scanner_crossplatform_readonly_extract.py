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
import platform
import multiprocessing
from pathlib import Path
from datetime import datetime


# ──────────────────────────────────────────────────────────────
# Windows raw device helpers
# ──────────────────────────────────────────────────────────────
def is_raw_device(filepath: str) -> bool:
    """Detect raw/block device paths for Windows, macOS, and Linux.

    Windows examples: \\.\\PhysicalDrive2, \\.\\D:
    macOS examples: /dev/rdisk4s2, /dev/disk4s2
    Linux examples: /dev/sdb, /dev/sdb1
    """
    if not filepath:
        return False
    if filepath.startswith('\\\\.\\') or filepath.startswith('\\\\?\\'):
        return True
    if filepath.startswith('/dev/'):
        return True
    return False


def is_windows_raw_device(filepath: str) -> bool:
    return bool(filepath and (filepath.startswith('\\\\.\\') or filepath.startswith('\\\\?\\')))


def device_mode_label(filepath: str) -> str:
    if is_windows_raw_device(filepath):
        return 'Raw Windows device (read-only, sector-aligned reads)'
    if filepath.startswith('/dev/rdisk') or filepath.startswith('/dev/disk'):
        return 'Raw macOS device (read-only, sector-aligned reads)'
    if filepath.startswith('/dev/'):
        return 'Raw Linux/Unix device (read-only, sector-aligned reads)'
    return 'Regular file/image (read-only)'

def _windows_create_readonly_handle(filepath: str):
    """Create a Windows handle with READ access only and safe sharing.

    This avoids Python's default open() sharing problems on raw devices. It does
    NOT request write access. Closing the Python file object will close the handle.
    """
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(filepath),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(err, ctypes.FormatError(err), filepath)
    return handle


def _windows_close_handle(handle):
    try:
        ctypes.WinDLL('kernel32', use_last_error=True).CloseHandle(handle)
    except Exception:
        pass


def get_device_size(filepath: str) -> int:
    """
    Get real size of a file or raw/block device.
    Supports regular files, macOS /dev/rdisk*, Linux /dev/* block devices,
    and Windows raw physical/volume devices.
    """

    # Regular file/image - use normal file size.
    if not is_raw_device(filepath):
        return os.path.getsize(filepath)

    system = platform.system()

    # macOS raw/block device.
    if system == 'Darwin':
        try:
            import fcntl, array
            DKIOCGETBLOCKCOUNT = 0x40086419
            DKIOCGETBLOCKSIZE = 0x40046418
            with open(filepath, 'rb', buffering=0) as f:
                buf_count = array.array('Q', [0])
                buf_size = array.array('I', [0])
                fcntl.ioctl(f.fileno(), DKIOCGETBLOCKCOUNT, buf_count, True)
                fcntl.ioctl(f.fileno(), DKIOCGETBLOCKSIZE, buf_size, True)
                if buf_count[0] > 0 and buf_size[0] > 0:
                    return int(buf_count[0] * buf_size[0])
        except Exception:
            pass

        try:
            import subprocess, re
            dev = filepath.replace('/dev/rdisk', '/dev/disk')
            result = subprocess.run(['diskutil', 'info', dev], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'Disk Size' in line or 'Partition Size' in line or 'Total Size' in line:
                    m = re.search(r'\((\d+)\s+Bytes\)', line)
                    if m:
                        return int(m.group(1))
        except Exception:
            pass

    # Windows raw device.
    if system == 'Windows' or is_windows_raw_device(filepath):
        handle = None
        try:
            IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
            handle = _windows_create_readonly_handle(filepath)
            length = ctypes.c_longlong(0)
            bytes_ret = ctypes.c_ulong(0)
            ok = ctypes.WinDLL('kernel32', use_last_error=True).DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                None,
                0,
                ctypes.byref(length),
                ctypes.sizeof(length),
                ctypes.byref(bytes_ret),
                None,
            )
            if ok and length.value > 0:
                return int(length.value)
        except Exception:
            pass
        finally:
            if handle is not None:
                _windows_close_handle(handle)

    # Linux block device fallback.
    if system == 'Linux' and filepath.startswith('/dev/'):
        try:
            import fcntl
            BLKGETSIZE64 = 0x80081272
            buf = bytearray(8)
            with open(filepath, 'rb', buffering=0) as f:
                fcntl.ioctl(f.fileno(), BLKGETSIZE64, buf, True)
            return struct.unpack('Q', buf)[0]
        except Exception:
            pass

    # Last fallback: seek to end. May fail or return 0 on some raw devices.
    try:
        with open(filepath, 'rb', buffering=0) as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size > 0:
                return int(size)
    except Exception:
        pass

    return 0

def open_device(filepath: str, buffering: int = 0):
    """Open regular files and raw devices READ-ONLY.

    Safety guarantee: this function always opens the source with read-only mode.
    It never opens the source with write/update flags. Output JSON/log files are
    handled separately by the CLI and should be placed on Desktop/recovery disk.
    """
    if is_windows_raw_device(filepath) and platform.system() == 'Windows':
        import msvcrt
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
        handle = _windows_create_readonly_handle(filepath)
        fd = msvcrt.open_osfhandle(handle, flags)
        return os.fdopen(fd, 'rb', buffering=0)

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


def is_plausible_atom_type(type_str: str) -> bool:
    """Return True only for normal printable 4-byte MP4/MOV atom names.

    This is important when scanning a raw formatted drive. After a real clip
    ends, the next bytes may be zeros or random data. The old script accepted
    a zero/garbage atom and accidentally counted the rest of the 4 TB device
    as part of the candidate file.
    """
    if not isinstance(type_str, str) or len(type_str) != 4:
        return False
    return all(32 <= ord(ch) <= 126 for ch in type_str)


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
    def __init__(self, filepath: str, verbose: bool = False, allow_zero_size: bool = True):
        self.filepath  = filepath
        self.file_size = get_device_size(filepath)
        self.verbose   = verbose
        # In raw-disk mode this must be False. Otherwise a zero-filled area
        # after a clip can be misread as a size=0 atom extending to EOF.
        self.allow_zero_size = allow_zero_size
        self.atoms     = []          # flat list tất cả atoms
        self.errors    = []
        self._f        = None

    SECTOR = 512

    def _aligned_read(self, offset: int, n: int) -> bytes:
        """Sector-aligned read for macOS raw devices (offset and size must be multiples of 512)."""
        aligned_offset = (offset // self.SECTOR) * self.SECTOR
        aligned_size   = (((offset - aligned_offset) + n + self.SECTOR - 1) // self.SECTOR) * self.SECTOR
        self._f.seek(aligned_offset)
        data = self._f.read(aligned_size)
        skip = offset - aligned_offset
        return data[skip:skip + n]

    def _read(self, n: int) -> bytes:
        pos  = self._f.seek(0, 1)
        data = self._aligned_read(pos, n)
        self._f.seek(pos + len(data))
        if len(data) < n:
            raise EOFError(f"Unexpected EOF (need {n} bytes, got {len(data)})")
        return data

    def _read_atom_header(self, offset: int):
        """
        Read atom header at offset with sector-aligned reads for macOS raw devices.
        Returns (atom_type, header_size, total_size, data_offset, size32)
        """
        raw = self._aligned_read(offset, 8)
        if len(raw) < 8:
            return None

        size32    = struct.unpack('>I', raw[0:4])[0]
        atom_type = raw[4:8]

        try:
            type_str = atom_type.decode('ascii')
        except Exception:
            type_str = atom_type.hex()

        # size = 1 → extended 64-bit size at bytes 8-15
        if size32 == 1:
            ext_raw = self._aligned_read(offset + 8, 8)
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
        return type_str, header_size, total_size, data_offset, size32

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

            type_str, header_size, total_size, data_offset, size32 = result

            # Stop at garbage / zero-filled raw-disk data.
            # A valid MP4 atom type is a printable 4-character code.
            # Example bug fixed: bytes 00 00 00 00 00 00 00 00 were parsed
            # as a fake atom of type '\x00\x00\x00\x00' with size=0,
            # making a small clip look like a 3+ TB file.
            if not is_plausible_atom_type(type_str):
                if self.verbose:
                    cprint(C.YELLOW, f"{'  '*depth}[stop] Invalid atom type {type_str!r} @ offset {offset:,}")
                break

            if size32 == 0 and not self.allow_zero_size:
                if self.verbose:
                    cprint(C.YELLOW, f"{'  '*depth}[stop] size=0 atom {type_str!r} @ offset {offset:,} disabled in raw mode")
                break

            # Sanity check
            if total_size < 8 and total_size != 0:
                if self.verbose:
                    cprint(C.RED, f"{'  '*depth}[!] Invalid atom size {total_size} @ offset {offset}")
                offset += 4
                continue

            if offset + total_size > self.file_size:
                if self.verbose:
                    cprint(C.RED, f"{'  '*depth}[!] Atom size exceeds device/file @ offset {offset:,}")
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
        """Parse detailed content of special atoms using sector-aligned reads."""
        extra = {}
        try:
            # Read the entire atom data in one aligned read, then parse from buffer
            read_size = min(data_size, 512)  # we only need first ~512 bytes for metadata
            buf = self._aligned_read(data_offset, max(read_size, 64))
            import io
            stream = io.BytesIO(buf)

            if atom_type == 'ftyp' and data_size >= 4:
                major_brand  = stream.read(4).decode('ascii', errors='replace')
                minor_ver    = struct.unpack('>I', stream.read(4))[0] if data_size >= 8 else 0
                compat_count = (data_size - 8) // 4
                compat = []
                for _ in range(min(compat_count, 8)):
                    b = stream.read(4)
                    if len(b) == 4:
                        compat.append(b.decode('ascii', errors='replace').strip())
                extra = {
                    'major_brand':       major_brand,
                    'minor_version':     minor_ver,
                    'compatible_brands': compat,
                }

            elif atom_type == 'mvhd' and data_size >= 20:
                version = struct.unpack('>B', stream.read(1))[0]
                stream.read(3)  # flags
                if version == 1:
                    create_time = struct.unpack('>Q', stream.read(8))[0]
                    modify_time = struct.unpack('>Q', stream.read(8))[0]
                    timescale   = struct.unpack('>I', stream.read(4))[0]
                    duration    = struct.unpack('>Q', stream.read(8))[0]
                else:
                    create_time = struct.unpack('>I', stream.read(4))[0]
                    modify_time = struct.unpack('>I', stream.read(4))[0]
                    timescale   = struct.unpack('>I', stream.read(4))[0]
                    duration    = struct.unpack('>I', stream.read(4))[0]

                dur_sec = duration / timescale if timescale else 0
                extra = {
                    'version':    version,
                    'timescale':  timescale,
                    'duration_units': duration,
                    'duration_sec':   round(dur_sec, 3),
                    'duration_fmt':   _fmt_duration(dur_sec),
                }

            elif atom_type == 'tkhd' and data_size >= 20:
                version = struct.unpack('>B', stream.read(1))[0]
                stream.read(3)
                if version == 1:
                    stream.read(8+8)
                    track_id = struct.unpack('>I', stream.read(4))[0]
                    stream.read(4)
                    duration = struct.unpack('>Q', stream.read(8))[0]
                else:
                    stream.read(4+4)
                    track_id = struct.unpack('>I', stream.read(4))[0]
                    stream.read(4)
                    duration = struct.unpack('>I', stream.read(4))[0]
                stream.read(8+36)
                width_fp  = struct.unpack('>I', stream.read(4))[0]
                height_fp = struct.unpack('>I', stream.read(4))[0]
                extra = {
                    'track_id': track_id,
                    'duration_units': duration,
                    'width':  width_fp >> 16,
                    'height': height_fp >> 16,
                }

            elif atom_type == 'hdlr' and data_size >= 12:
                stream.read(4+4)
                handler = stream.read(4).decode('ascii', errors='replace')
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
                stream.read(4)
                sample_size  = struct.unpack('>I', stream.read(4))[0]
                sample_count = struct.unpack('>I', stream.read(4))[0]
                extra = {
                    'sample_size':  sample_size,
                    'sample_count': sample_count,
                    'note': 'Uniform size' if sample_size > 0 else f'{sample_count} variable-size samples',
                }

            elif atom_type == 'stco' and data_size >= 8:
                stream.read(4)
                entry_count = struct.unpack('>I', stream.read(4))[0]
                offsets = []
                for _ in range(min(entry_count, 3)):
                    o = struct.unpack('>I', stream.read(4))[0]
                    offsets.append(o)
                extra = {
                    'entry_count':    entry_count,
                    'first_offsets':  offsets,
                }

            elif atom_type == 'co64' and data_size >= 8:
                stream.read(4)
                entry_count = struct.unpack('>I', stream.read(4))[0]
                offsets = []
                for _ in range(min(entry_count, 3)):
                    o = struct.unpack('>Q', stream.read(8))[0]
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
    OVERLAP     = 2 * 1024 * 1024  # protects signatures near chunk boundaries

    # ftyp signatures phổ biến
    FTYP_BRANDS = [
        # Sony XAVC / A7SIII / A7RV / FX series
        b'XAVC', b'XAVS', b'XAV2',
        # Standard MP4 / ISO
        b'isom', b'iso2', b'iso4', b'iso5', b'iso6',
        b'mp41', b'mp42', b'M4V ', b'M4A ', b'M4P ',
        b'qt  ', b'MSNV', b'avc1', b'f4v ', b'dash',
        b'3gp4', b'3gp5', b'3gp6', b'HEVC',
    ]

    def __init__(self, filepath: str, max_scan_gb: float = None, start_gb: float = 0, candidate_window_gb: float = 64):
        self.filepath    = filepath
        self.file_size   = get_device_size(filepath)
        self.scan_start  = int(start_gb * 1024**3)
        # NOTE: --limit is treated as END offset in GB for backward compatibility
        # with your previous commands: --start 480 --limit 485 means 480→485 GB.
        self.scan_limit  = int(max_scan_gb * 1024**3) if max_scan_gb else self.file_size
        self.candidate_window = int(candidate_window_gb * 1024**3)
        self._is_device  = is_raw_device(filepath)

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
            cprint(C.YELLOW, "    1. macOS: run with sudo and use /dev/rdiskNsM or /dev/diskNsM")
            cprint(C.YELLOW, "  → Windows examples: \\\\.\\D:  or  \\\\.\\PhysicalDrive0")
            return []

        print(f"  Size   : {fmt_size(self.file_size)}  ({self.file_size:,} bytes)")
        scan_start = max(0, self._aligned(self.scan_start))
        scan_end   = min(self.scan_limit, self.file_size)
        if scan_end <= scan_start:
            cprint(C.RED, f"\n  ✗ --start ({fmt_size(scan_start)}) >= --limit ({fmt_size(scan_end)}), nothing to scan.")
            return []

        scan_total = scan_end - scan_start
        print(f"  Start  : {fmt_size(scan_start)}  ({scan_start:,} bytes)")
        print(f"  End    : {fmt_size(scan_end)}  ({scan_end:,} bytes)")
        print(f"  Range  : {fmt_size(scan_total)}")
        cprint(C.YELLOW, f"  Mode   : {device_mode_label(self.filepath)}")
        cprint(C.CYAN, f"{'='*60}\n")

        candidates = []
        last_pct   = -1

        with open_device(self.filepath) as f:
            offset  = scan_start
            scanned = 0
            overlap = b''
            seen = set()

            while offset < scan_end:
                remaining  = scan_end - offset
                chunk_size = self._aligned(min(self.CHUNK, remaining))
                if chunk_size == 0:
                    break

                try:
                    # Raw devices require aligned seek/read. offset and chunk_size
                    # are sector-aligned here.
                    f.seek(offset)
                    body = f.read(chunk_size)
                except OSError as e:
                    cprint(C.RED, f"\n  [!] Read error @ {offset:,}: {e}")
                    offset += self.SECTOR_SIZE
                    scanned += self.SECTOR_SIZE
                    overlap = b''
                    continue

                if not body:
                    break

                # Faster and more reliable than stepping every sector in Python:
                # bytes.find() runs in C. This also catches ftyp signatures that
                # are not exactly at a 512-byte loop position. The candidate file
                # start is 4 bytes before the literal 'ftyp'.
                data = overlap + body
                base = offset - len(overlap)
                pos = 0
                while True:
                    idx = data.find(b'ftyp', pos)
                    if idx == -1:
                        break
                    file_start = base + idx - 4
                    if idx >= 4 and scan_start <= file_start < scan_end:
                        size32 = struct.unpack('>I', data[idx-4:idx])[0]
                        brand = data[idx+4:idx+8]
                        if (8 <= size32 <= 1024 * 1024 and brand in self.FTYP_BRANDS and file_start not in seen):
                            seen.add(file_start)
                            cprint(C.GREEN,
                                f"\n  ✓ ftyp @ {file_start:,} ({fmt_size(file_start)})"
                                f"  brand={brand.decode('ascii','replace')}"
                                f"  size={size32}")
                            candidates.append(file_start)
                    pos = idx + 4

                scanned += len(body)
                pct = int(scanned / scan_total * 100)
                if pct != last_pct:
                    print(f"\r  Progress: {pct:3d}%  {fmt_size(scanned)} / {fmt_size(scan_total)}"
                          f"  [offset {offset:,}]     ", end='', flush=True)
                    last_pct = pct

                # Keep a small overlap so a signature split across chunk boundary
                # is not missed. Do not let overlap make progress accounting wrong.
                overlap = data[-self.OVERLAP:] if len(data) > self.OVERLAP else data
                offset += len(body)

        print(f"\n\n  Tìm thấy {len(candidates)} MP4 signature(s).\n")

        # Parse từng candidate
        results = []
        for i, start_offset in enumerate(candidates):
            print(f"  {'─'*50}")
            print(f"  Candidate #{i+1} @ offset {start_offset:,} ({fmt_size(start_offset)})")
            try:
                parser = AtomParser(self.filepath, verbose=False, allow_zero_size=False)
                parser.file_size = self.file_size
                parse_end = min(start_offset + self.candidate_window, self.file_size)
                with open_device(self.filepath) as f:
                    parser._f = f
                    parser.parse(offset=start_offset, end=parse_end)

                top = [a for a in parser.atoms if a['depth'] == 0]

                if not top or top[0]['type'] != 'ftyp':
                    print("    Rejected   : first valid atom is not ftyp")
                    continue

                atom_names = [a['type'] for a in top]
                last_end = max(a['offset'] + a['total_size'] for a in top)
                est_size = last_end - start_offset
                has_mdat = any(a['type'] == 'mdat' for a in top)
                has_moov = any(a['type'] == 'moov' for a in top)
                status = 'likely_complete' if has_mdat and has_moov else 'metadata_or_data_missing'

                print(f"    Atoms     : {atom_names}")
                print(f"    Status    : {status}")
                print(f"    End       : {last_end:,} ({fmt_size(last_end)})")
                print(f"    Est. size : {fmt_size(est_size)} ({est_size:,} bytes)")
                results.append({
                    'offset': start_offset,
                    'offset_gb': round(start_offset / 1024**3, 6),
                    'end_offset': last_end,
                    'end_gb': round(last_end / 1024**3, 6),
                    'estimated_size': est_size,
                    'estimated_size_gb': round(est_size / 1024**3, 6),
                    'status': status,
                    'has_mdat': has_mdat,
                    'has_moov': has_moov,
                    'atoms': top,
                })
            except Exception as e:
                print(f"    Error: {e}")

        return results




# ──────────────────────────────────────────────────────────────
# Read-only raw range extractor
# ──────────────────────────────────────────────────────────────
def refuse_raw_output_path(output_path: str):
    """Prevent catastrophic mistakes like --output /dev/rdisk4s2 or \\.\PhysicalDrive2."""
    if not output_path:
        raise ValueError("Missing --output path")
    if is_raw_device(output_path):
        raise ValueError("Refusing to write output to a raw device path. Choose Desktop or a recovery disk path.")


def extract_range_readonly(source: str, start_gb: float, size_gb: float, output_path: str, chunk_mb: int = 128):
    """Copy a byte range from a source drive/file to an output file.

    Safety:
      - source is opened read-only via open_device()
      - output is the only file opened for writing
      - output cannot be a raw device path
      - reads are sector-aligned for macOS/Windows raw devices
    """
    if start_gb < 0:
        raise ValueError("--start cannot be negative")
    if size_gb <= 0:
        raise ValueError("--size must be greater than 0")
    if chunk_mb <= 0:
        raise ValueError("--chunk-mb must be greater than 0")

    refuse_raw_output_path(output_path)

    source_size = get_device_size(source)
    if source_size <= 0:
        raise RuntimeError("Could not determine source size. Use sudo/admin and the correct raw device path.")

    start = int(start_gb * 1024**3)
    total = int(size_gb * 1024**3)
    if start >= source_size:
        raise ValueError(f"Start offset is beyond source size: {fmt_size(start)} >= {fmt_size(source_size)}")
    if start + total > source_size:
        clipped = source_size - start
        cprint(C.YELLOW, f"  ⚠ Requested range exceeds source size. Clipping size to {fmt_size(clipped)}")
        total = clipped

    sector = 512
    chunk = max(sector, int(chunk_mb * 1024**2))
    chunk = (chunk // sector) * sector

    aligned_start = (start // sector) * sector
    skip = start - aligned_start
    first_read = min(total + skip, chunk)
    if first_read % sector:
        first_read = ((first_read + sector - 1) // sector) * sector

    out = os.path.abspath(os.path.expanduser(output_path))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)

    cprint(C.BOLD + C.CYAN, f"\n{'='*60}")
    cprint(C.BOLD + C.WHITE, "  READ-ONLY RANGE EXTRACTOR")
    cprint(C.CYAN, f"{'='*60}")
    print(f"  Source : {source}")
    print(f"  Mode   : {device_mode_label(source)}")
    print(f"  Start  : {fmt_size(start)} ({start:,} bytes)")
    print(f"  Size   : {fmt_size(total)} ({total:,} bytes)")
    print(f"  End    : {fmt_size(start + total)} ({start + total:,} bytes)")
    print(f"  Output : {out}")
    cprint(C.YELLOW, "  Safety : source opened read-only; only output file is written")
    cprint(C.CYAN, f"{'='*60}\n")

    copied = 0
    current = aligned_start
    first = True
    last_pct = -1

    with open_device(source) as src, open(out, 'wb') as dst:
        while copied < total:
            if first:
                read_size = first_read
            else:
                remaining = total - copied
                read_size = min(chunk, remaining)
                if read_size % sector:
                    read_size = ((read_size + sector - 1) // sector) * sector

            src.seek(current)
            data = src.read(read_size)
            if not data:
                raise RuntimeError(f"Read stopped early at source offset {current:,}")

            if first:
                data = data[skip:]
                first = False

            need = min(len(data), total - copied)
            dst.write(data[:need])
            copied += need
            current += read_size

            pct = int(copied / total * 100) if total else 100
            if pct != last_pct:
                print(f"\r  Progress: {pct:3d}%  {fmt_size(copied)} / {fmt_size(total)}", end='', flush=True)
                last_pct = pct

    print()
    cprint(C.GREEN, f"\n  ✓ Extracted safely to: {out}")
    return out


def hex_dump_range_readonly(source: str, start_gb: float, size_mb: float, output_path: str, force_hex: bool = False):
    """Write a textual hex dump for a SMALL range only.

    A 4 GB binary range becomes 8+ GB as plain hex text, so this mode refuses
    large dumps unless --force-hex is used. For recovery, use --extract instead.
    """
    if size_mb <= 0:
        raise ValueError("--hex-size-mb must be greater than 0")
    if size_mb > 64 and not force_hex:
        raise ValueError("Refusing huge hex dump. Use --extract for large ranges, or add --force-hex if you really need text hex.")

    refuse_raw_output_path(output_path)
    source_size = get_device_size(source)
    if source_size <= 0:
        raise RuntimeError("Could not determine source size. Use sudo/admin and the correct raw device path.")

    start = int(start_gb * 1024**3)
    total = int(size_mb * 1024**2)
    if start + total > source_size:
        total = source_size - start

    sector = 512
    aligned_start = (start // sector) * sector
    skip = start - aligned_start
    read_total = total + skip
    if read_total % sector:
        read_total = ((read_total + sector - 1) // sector) * sector

    out = os.path.abspath(os.path.expanduser(output_path))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)

    with open_device(source) as src:
        src.seek(aligned_start)
        data = src.read(read_total)[skip:skip + total]

    with open(out, 'w', encoding='utf-8') as dst:
        for i in range(0, len(data), 16):
            row = data[i:i+16]
            abs_off = start + i
            hex_part = ' '.join(f'{b:02x}' for b in row)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            dst.write(f'{abs_off:016x}  {hex_part:<47}  |{ascii_part}|\n')

    cprint(C.GREEN, f"\n  ✓ Hex dump saved to: {out}")
    return out


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

  # Quét raw disk image/device tìm MP4
  python mp4_atom_scanner.py disk.img --raw --limit 10

  # macOS raw Sony drive, scan 480→485 GB
  sudo python3 mp4_atom_scanner.py /dev/rdisk4s2 --raw --start 480 --limit 485 --json ~/Desktop/xavc_scan.json

  # Windows raw physical drive, scan 480→485 GB (run CMD/PowerShell as Administrator)
  python mp4_atom_scanner.py \\\\.\\PhysicalDrive2 --raw --start 480 --limit 485 --json C:\\Users\\YourName\\Desktop\\xavc_scan.json

  # Extract/copy 4 GB raw segment from 480→484 GB to Desktop (source read-only)
  sudo python3 mp4_atom_scanner.py /dev/rdisk4s2 --extract --start 480 --size 4 --output ~/Desktop/drive_480_484GB.bin

  # Small text hex dump only, example 1 MB from 480 GB
  sudo python3 mp4_atom_scanner.py /dev/rdisk4s2 --hex-dump --start 480 --hex-size-mb 1 --output ~/Desktop/drive_480GB_sample.hex

  # Xuất kết quả JSON
  python mp4_atom_scanner.py video.mp4 --json output.json
        """
    )
    parser.add_argument('file',          help='File MP4/MOV hoặc raw disk image')
    parser.add_argument('--raw',         action='store_true', help='Chế độ quét raw disk image')
    parser.add_argument('--start',       type=float, default=0, metavar='GB',
                        help='Start scan offset in GB (default: 0)')
    parser.add_argument('--limit',       type=float, default=None, metavar='GB',
                        help='End scan offset in GB (default: full drive)')
    parser.add_argument('--json',        metavar='OUTPUT', help='Xuất kết quả ra file JSON')
    parser.add_argument('--extract',     action='store_true', help='Extract/copy a raw byte range from source to --output (source read-only)')
    parser.add_argument('--size',        type=float, default=None, metavar='GB', help='Extract size in GB when using --extract')
    parser.add_argument('--output',      metavar='OUTPUT', help='Output file path for --extract or --hex-dump')
    parser.add_argument('--chunk-mb',    type=int, default=128, help='Copy chunk size in MB for --extract (default: 128)')
    parser.add_argument('--hex-dump',    action='store_true', help='Write a textual hex dump for a SMALL range')
    parser.add_argument('--hex-size-mb', type=float, default=None, metavar='MB', help='Hex dump size in MB when using --hex-dump')
    parser.add_argument('--force-hex',   action='store_true', help='Allow hex dumps larger than 64 MB; not recommended')
    parser.add_argument('--candidate-window', type=float, default=64, metavar='GB',
                        help='Max bytes after each ftyp to inspect for atoms (default: 64 GB)')
    parser.add_argument('-v','--verbose',action='store_true', help='Verbose mode')

    args = parser.parse_args()

    # os.path.exists() trả về False với \\.\C: nên cần check riêng
    filepath = args.file
    if is_raw_device(filepath):
        # Thử mở để xác nhận có tồn tại / có quyền
        try:
            with open_device(filepath) as _test:
                pass
        except PermissionError:
            cprint(C.RED, f"✗ Không có quyền truy cập: {filepath}")
            cprint(C.YELLOW, "  → macOS: use sudo. Windows: run CMD/PowerShell as Administrator")
            sys.exit(1)
        except FileNotFoundError:
            cprint(C.RED, f"✗ Không tìm thấy device: {filepath}")
            cprint(C.YELLOW, "  → Windows examples: \\\\.\\D:  or  \\\\.\\PhysicalDrive0")
            sys.exit(1)
        except Exception as e:
            cprint(C.RED, f"✗ Lỗi mở device: {e}")
            sys.exit(1)
    elif not os.path.exists(filepath):
        cprint(C.RED, f"✗ File không tồn tại: {filepath}")
        sys.exit(1)

    if args.json and is_raw_device(args.json):
        cprint(C.RED, "✗ Refusing to write JSON to a raw device path. Choose Desktop or another recovery disk path.")
        sys.exit(1)

    if args.extract:
        if args.size is None:
            cprint(C.RED, "✗ --extract requires --size in GB")
            sys.exit(1)
        if not args.output:
            cprint(C.RED, "✗ --extract requires --output")
            sys.exit(1)
        try:
            extract_range_readonly(filepath, args.start, args.size, args.output, chunk_mb=args.chunk_mb)
        except Exception as e:
            cprint(C.RED, f"✗ Extract failed: {e}")
            sys.exit(1)
        return

    if args.hex_dump:
        if args.hex_size_mb is None:
            cprint(C.RED, "✗ --hex-dump requires --hex-size-mb")
            sys.exit(1)
        if not args.output:
            cprint(C.RED, "✗ --hex-dump requires --output")
            sys.exit(1)
        try:
            hex_dump_range_readonly(filepath, args.start, args.hex_size_mb, args.output, force_hex=args.force_hex)
        except Exception as e:
            cprint(C.RED, f"✗ Hex dump failed: {e}")
            sys.exit(1)
        return

    if args.raw:
        scanner = RawScanner(filepath, max_scan_gb=args.limit, start_gb=args.start, candidate_window_gb=args.candidate_window)
        results = scanner.scan()
        if args.json:
            out_dir = os.path.dirname(os.path.abspath(args.json))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            cprint(C.GREEN, f"\n  ✓ JSON xuất ra: {args.json}")
    else:
        ap = AtomParser(filepath, verbose=args.verbose)
        atoms = ap.run()
        if args.json:
            out_dir = os.path.dirname(os.path.abspath(args.json))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(atoms, f, indent=2, default=str)
            cprint(C.GREEN, f"\n  ✓ JSON xuất ra: {args.json}")


if __name__ == '__main__':
    main()
