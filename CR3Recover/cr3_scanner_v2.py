#!/usr/bin/env python3
"""
cr3_scanner.py — Quét file raw/disk tìm ảnh Canon CR3

Thuật toán:
  1. Buffer search tìm b'ftyp', kiểm tra major_brand CR3
  2. Duyệt top-level atoms (ISOBMFF) để tính kích thước
  3. Đọc make/model từ atom 'CMT1' (EXIF IFD0 nhúng trong CR3)
  4. Ghi log + in bảng sau khi quét xong toàn bộ file

Cách dùng:
  cr3_scanner.py -i card.img
  cr3_scanner.py -i 16GB.dsk -o out/
  cr3_scanner.py -i dump.img -o recovered/ -v
"""

import os, sys, struct, argparse, time
from pathlib import Path
from datetime import datetime

MB = 1 << 20

# ── ANSI ──────────────────────────────────────────────────────────────────────
_tty = sys.stdout.isatty()
def _a(c): return c if _tty else ""
R  = _a("\033[0m");  B  = _a("\033[1m");  D  = _a("\033[2m")
G  = _a("\033[92m"); C  = _a("\033[96m"); Y  = _a("\033[93m")
M  = _a("\033[95m"); RE = _a("\033[91m"); CL = _a("\033[2K")

# ── Hằng số ───────────────────────────────────────────────────────────────────
CR3_BRANDS  = {b'crx ', b'CR3 '}
MP4_BRANDS  = {b'mp41', b'mp42', b'mp4v', b'M4V ', b'M4A ', b'M4P ',
               b'avc1', b'qt  ', b'MSNV', b'F4V ', b'3gp4', b'3gp5',
               b'heic', b'heif', b'avif', b'mif1'}
MAX_CR3     = 2 * 1024 * MB   # 2 GB
EXIF_READ   = 64 * 1024       # đọc 64 KB để parse make/model


# ── Helpers ───────────────────────────────────────────────────────────────────
def fmt_sz(n: float) -> str:
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def _draw_progress(done: int, total: int, found: int, spd: float, eta_s: float):
    if not _tty: return
    pct = done / total if total else 0
    w = 30; f = int(w * pct)
    bar = "█" * f + "░" * (w - f)
    eta = f" ETA {int(eta_s//60):02d}:{int(eta_s%60):02d}" if eta_s > 0 else ""
    line = (f"{C}[{bar}]{R} {pct*100:5.1f}%  "
            f"{G}{fmt_sz(done)}{R}/{fmt_sz(total)}  "
            f"{Y}⚡{spd:.0f} MB/s{R}  "
            f"{M}📷 {found}{R}{D}{eta}{R}")
    sys.stdout.write(f"\r{CL}{line}")
    sys.stdout.flush()

def _clear_bar():
    if _tty:
        sys.stdout.write(f"\r{CL}")
        sys.stdout.flush()


# ── EXIF make/model từ CMT1 atom ─────────────────────────────────────────────
def _read_str(data: bytes, off: int, n: int) -> str:
    try:
        return data[off:off+n].rstrip(b'\x00').decode('ascii', 'replace').strip()
    except Exception:
        return ""

def parse_make_model(buf: bytes) -> tuple:
    """
    Parse make/model từ buf chứa CR3.
    CR3 lưu EXIF IFD0 trong atom 'CMT1' nằm bên trong 'moov'.
    buf là EXIF IFD0 payload (bắt đầu bằng 'II' hoặc 'MM').
    """
    try:
        if len(buf) < 8: return "", ""
        e = '<' if buf[:2] == b'II' else '>'
        if struct.unpack(e+'H', buf[2:4])[0] != 42: return "", ""
        ifd = struct.unpack(e+'I', buf[4:8])[0]
        if ifd + 2 > len(buf): return "", ""
        nent = struct.unpack(e+'H', buf[ifd:ifd+2])[0]
        mk = mo = ""
        for i in range(min(nent, 64)):
            o = ifd + 2 + i * 12
            if o + 12 > len(buf): break
            tag, typ, cnt = struct.unpack(e+'HHI', buf[o:o+8])
            if typ != 2: continue
            vr = buf[o+8:o+12]
            if cnt <= 4:
                val = vr[:cnt].rstrip(b'\x00').decode('ascii', 'replace').strip()
            else:
                soff = struct.unpack(e+'I', vr)[0]
                val  = _read_str(buf, soff, cnt)
            if   tag == 0x010F: mk = val
            elif tag == 0x0110: mo = val
            if mk and mo: break
        return mk, mo
    except Exception:
        return "", ""

def extract_make_model_from_cr3(file, ftyp_pos: int, cr3_size: int) -> tuple:
    """
    Tìm atom 'CMT1' bên trong CR3, đọc make/model.
    Chỉ quét trong phần moov (bỏ qua mdat lớn).
    """
    try:
        # Đọc tối đa EXIF_READ bytes để tìm CMT1
        read_len = min(cr3_size, EXIF_READ)
        file.seek(ftyp_pos)
        blob = file.read(read_len)
        idx = blob.find(b'CMT1')
        if idx < 4: return "", ""
        # CMT1 atom: size(4) + 'CMT1' + payload
        atom_start = idx - 4
        atom_size  = struct.unpack_from('>I', blob, atom_start)[0]
        payload_start = atom_start + 8
        payload_end   = min(atom_start + atom_size, len(blob))
        payload = blob[payload_start:payload_end]
        return parse_make_model(payload)
    except Exception:
        return "", ""


# ── Atom reader ───────────────────────────────────────────────────────────────
def read_atom_header(file) -> tuple:
    """Trả về (pos, name, total_size, hlen) hoặc (pos, None, 0, 0) nếu EOF."""
    pos = file.tell()
    raw = file.read(8)
    if len(raw) < 8: return pos, None, 0, 0
    raw_size = struct.unpack_from('>I', raw, 0)[0]
    name = raw[4:8]
    if raw_size == 1:
        ext = file.read(8)
        if len(ext) < 8: return pos, None, 0, 0
        return pos, name, struct.unpack('>Q', ext)[0], 16
    return pos, name, raw_size, 8

def _is_cr3_ftyp(file, pos: int, size: int, hlen: int) -> bool:
    file.seek(pos + hlen)
    if size - hlen < 4: return False
    major = file.read(4)
    if len(major) < 4: return False
    return major not in MP4_BRANDS and major in CR3_BRANDS

def calc_cr3_size(file, ftyp_pos: int, file_size: int,
                  last_atom: bytes, max_atoms: int) -> int:
    """Duyệt atoms từ ftyp_pos, trả về tổng size CR3 (hoặc 0 nếu lỗi)."""
    file.seek(ftyp_pos)
    total = 0; idx = 0
    while True:
        pos, name, size, hlen = read_atom_header(file)
        if name is None: break
        try:
            name_str = name.decode('ascii')
            if not all(0x20 <= b <= 0x7E for b in name): raise ValueError
        except Exception:
            return 0
        if size == 0: size = file_size - pos
        if size > MAX_CR3 or size < hlen: return 0
        total += size; idx += 1
        if last_atom and name == last_atom: break
        if max_atoms > 0 and idx >= max_atoms: break
        file.seek(pos + size)
    return total


# ── Tìm CR3 headers ───────────────────────────────────────────────────────────
def find_cr3_headers(file, file_size: int, bufsize: int):
    """Generator yield abs_offset của từng CR3 header."""
    OVERLAP = 32
    pos = 0
    while pos < file_size:
        file.seek(pos)
        buf = file.read(bufsize)
        if not buf: break
        search_at = 0
        while search_at < len(buf):
            idx = buf.find(b'ftyp', search_at)
            if idx < 0: break
            if idx < 4: search_at = idx + 1; continue
            abs_off = pos + idx - 4
            file.seek(abs_off)
            _, name, size, hlen = read_atom_header(file)
            if name == b'ftyp' and hlen > 0 and size >= hlen:
                if _is_cr3_ftyp(file, abs_off, size, hlen):
                    yield abs_off
                    search_at = idx - 4 + max(size, 8)
                    continue
            search_at = idx + 1
        advance = len(buf) - OVERLAP
        if advance <= 0: break
        pos += advance


# ── Ghi file khôi phục ───────────────────────────────────────────────────────
def restore_file(src, offset: int, size: int, out_path: Path,
                 bufsize: int = 16 * MB) -> bool:
    if out_path.exists(): return False
    src.seek(offset)
    remaining = size
    try:
        with out_path.open('wb') as dst:
            while remaining > 0:
                buf = src.read(min(bufsize, remaining))
                if not buf: break
                dst.write(buf)
                remaining -= len(buf)
        return True
    except IOError:
        return False


# ── Quét chính ───────────────────────────────────────────────────────────────
def scan(input_path: Path, outdir, args) -> list:
    file_size = input_path.stat().st_size
    bufsize   = args.chunk_mb * MB
    last_atom = args.lastchunk.encode('ascii') if not args.maxchunks else b''
    max_atoms = args.maxchunks

    # Banner
    print(f"""
{B}{C}  ╔══════════════════════════════════════════╗
  ║   CR3 SCANNER  ·  Canon RAW Recovery     ║
  ╚══════════════════════════════════════════╝{R}
  {D}ISOBMFF atom parser · major-brand check · make/model extract{R}""")
    print(f"\n{B}{'─'*68}{R}")
    print(f"  {C}📂 Input  :{R} {input_path}")
    print(f"  {C}💾 Size   :{R} {fmt_sz(file_size)}")
    if outdir:
        print(f"  {C}📁 OutDir :{R} {outdir}")
    print(f"  {C}📋 Log    :{R} {args.log_path}")
    print(f"{B}{'─'*68}{R}\n")

    results = []
    t0 = time.perf_counter()
    file_id = 1

    with input_path.open('rb') as dump, input_path.open('rb') as cr3:
        for offset in find_cr3_headers(dump, file_size, bufsize):

            size = calc_cr3_size(cr3, offset, file_size, last_atom, max_atoms)
            if size <= 0:
                continue

            make, model = extract_make_model_from_cr3(cr3, offset, size)

            rec = {
                'id':         file_id,
                'abs_offset': offset,
                'size_bytes': size,
                'make':       make or "—",
                'model':      model or "—",
                'saved':      False,
            }

            if outdir:
                out_path = outdir / f"{file_id:04d}.CR3"
                rec['saved'] = restore_file(cr3, offset, size, out_path, bufsize)

            results.append(rec)
            file_id += 1

            if args.verbose:
                _clear_bar()
                mk = rec['make']; mo = rec['model']
                sv = f"→ {C}{file_id-1:04d}.CR3{R}" if rec['saved'] else ""
                print(f"  {G}[#{rec['id']:04d}]{R}  "
                      f"{M}@0x{offset:010X}{R}  "
                      f"{Y}{fmt_sz(size):>10}{R}  "
                      f"{D}{mk} {mo}{R}  {sv}")

            elapsed = time.perf_counter() - t0
            spd = (offset >> 20) / max(elapsed, 1e-9)
            rem = ((file_size - offset) >> 20) / max(spd, 0.1)
            _draw_progress(offset, file_size, len(results), spd, rem)

    _clear_bar()
    elapsed = time.perf_counter() - t0
    avg_spd = (file_size >> 20) / max(elapsed, 1e-9)

    print(f"\n{B}{'─'*68}{R}")
    if results:
        print(f"  {G}✅ Xong!{R}  "
              f"{B}{len(results)}{R} file CR3  │  "
              f"{elapsed:.1f}s  │  {avg_spd:.0f} MB/s TB")
    else:
        print(f"  {Y}⚠  Không tìm thấy CR3 nào.{R}")
        print(f"  {D}Thử -v để xem log, hoặc đổi --lastchunk{R}")
    print(f"{B}{'─'*68}{R}\n")

    return results, elapsed, avg_spd, file_size


# ── Bảng kết quả ─────────────────────────────────────────────────────────────
def print_table(results: list):
    if not results:
        print(f"\n{Y}  Không tìm thấy CR3 nào.{R}\n")
        return
    SEP = "─" * 80
    print(f"\n{B}{SEP}{R}")
    print(f"  {B}{'No.':<8} {'Offset (hex)':<16} {'Size':>10}  "
          f"{'Make':<20} Model{R}")
    print(SEP)
    for r in results:
        sv = f" {G}✓{R}" if r['saved'] else ""
        print(f"  {C}[#{r['id']:04d}]{R}  "
              f"{M}@0x{r['abs_offset']:010X}{R}  "
              f"{Y}{fmt_sz(r['size_bytes']):>10}{R}  "
              f"{D}{r['make']:<20}{r['model']}{R}{sv}")
    print(SEP)
    print(f"  Tổng: {G}{B}{len(results)}{R} ảnh\n")


# ── Ghi log ───────────────────────────────────────────────────────────────────
def write_log(log_path: str, input_path: Path, results: list,
              elapsed: float, avg_spd: float, file_size: int):
    SEP = "─" * 100
    header = (
        f"{SEP}\n"
        f"  cr3_scanner  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Source : {input_path}  ({fmt_sz(file_size)})\n"
        f"  Found  : {len(results)} CR3 files\n"
        f"{SEP}\n\n"
        f"  {'No.':<8} {'Offset (hex)':<16} {'Size':>12}  "
        f"{'Make':<20} Model\n"
        f"  {'─'*98}\n"
    )
    rows = [
        f"  [#{r['id']:04d}]   @0x{r['abs_offset']:010X}   "
        f"{fmt_sz(r['size_bytes']):>12}   "
        f"{r['make']:<20}{r['model']}\n"
        for r in results
    ]
    footer = (
        f"\n{SEP}\n"
        f"  Total   : {len(results)} files\n"
        f"  Scanned : {fmt_sz(file_size)}\n"
        f"  Time    : {elapsed:.2f} s\n"
        f"  Speed   : {avg_spd:.0f} MB/s\n"
    )
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.writelines(rows)
        f.write(footer)
    print(f"  {C}📋 Log  :{R} {log_path}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog='cr3_scanner',
        description='📷 Quét file RAW / disk image tìm ảnh Canon CR3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python cr3_scanner.py -i card.img
  python cr3_scanner.py -i 16GB.dsk -o out/
  python cr3_scanner.py -i dump.img -o out/ -v
  sudo python cr3_scanner.py -i /dev/sdc -o out/
        """
    )
    ap.add_argument('-i', '--input',  required=True,
                    help='File dump / disk image / device')
    ap.add_argument('-o', '--outdir', default=None,
                    help='Thư mục lưu file khôi phục (không bắt buộc)')
    ap.add_argument('--lastchunk', default='mdat', metavar='NAME',
                    help='Tên atom cuối CR3 (mặc định: mdat)')
    ap.add_argument('--maxchunks', type=int, default=0, metavar='N',
                    help='Số atoms cố định thay cho --lastchunk')
    ap.add_argument('--chunk-mb', type=int, default=64, metavar='MB',
                    help='Buffer đọc MB (mặc định: 64)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='In từng ảnh ngay khi tìm thấy')
    ap.add_argument('--no-table', action='store_true',
                    help='Bỏ qua bảng kết quả cuối')
    args = ap.parse_args()

    # Validate input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"\n{RE}  ❌ Không tìm thấy: {args.input}{R}\n")
        sys.exit(1)

    # Xử lý outdir: tạo nếu chưa có, None nếu không truyền
    outdir = None
    if args.outdir:
        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)   # ← tạo folder nếu chưa có

    # Log luôn ghi (cạnh input nếu không có -o)
    args.log_path = str(outdir / "cr3_scanner.log") if outdir else str(input_path) + ".log"

    # Validate thêm
    if args.maxchunks < 0:
        ap.error("--maxchunks phải >= 0")
    if not args.lastchunk and not args.maxchunks:
        ap.error("--lastchunk không được rỗng")
    if args.chunk_mb < 1:
        ap.error("--chunk-mb phải >= 1")

    results, elapsed, avg_spd, file_size = scan(input_path, outdir, args)

    if not args.no_table:
        print_table(results)

    write_log(args.log_path, input_path, results, elapsed, avg_spd, file_size)


if __name__ == '__main__':
    main()
