#!/usr/bin/env python3
"""
jpeg_scanner.py — Quét file raw/disk tìm ảnh JPEG
Hỗ trợ FF D8 FF E0 (JFIF) và FF D8 FF E1 (EXIF)

Thuật toán:
  1. Đọc chunk 256 MB vào RAM
  2. numpy stride trick — so sánh 4 byte đầu mỗi sector song song
  3. Precompute toàn bộ FF D9 bằng uint16 view (zero-copy, ~2 GB/s)
  4. searchsorted — gắn EOI vào header trong O(log n)
  5. carry — xử lý ảnh vắt qua ranh giới nhiều chunk
"""

import os, sys, struct, argparse, time
from datetime import datetime
import numpy as np

# ── Hằng số ───────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
SECTOR     = 512
CHUNK_SIZE = 256 * 1024 * 1024     # 256 MB / lần đọc  ← FIX: was 1*1024*1024
MIN_IMG_MB = 0.064                  # 64 KB – lọc thumbnail
EXIF_BYTES = 8 * 1024              # chỉ đọc 8 KB đầu để parse EXIF

# ANSI (tự tắt nếu không phải TTY)
_tty = sys.stdout.isatty()
def _a(code): return code if _tty else ""
R  = _a("\033[0m");  B  = _a("\033[1m");  D  = _a("\033[2m")
G  = _a("\033[92m"); C  = _a("\033[96m"); Y  = _a("\033[93m")
M  = _a("\033[95m"); RE = _a("\033[91m"); CL = _a("\033[2K")


# ── EXIF parser ───────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def _s(data, off, n):
    try:
        return data[off:off+n].rstrip(b'\x00').decode('ascii', 'replace').strip()
    except Exception:
        return ""

def parse_make_model(buf: bytes) -> tuple:
    """Trả về (make, model) từ APP1 EXIF. buf bắt đầu tại FF D8."""
    try:
        if len(buf) < 20:                      return "", ""
        if buf[0:4] != b'\xFF\xD8\xFF\xE1':   return "", ""
        if buf[6:10] != b'Exif':              return "", ""
        t = buf[12:]
        if len(t) < 8:                         return "", ""
        e = '<' if t[:2] == b'II' else '>'
        if struct.unpack(e+'H', t[2:4])[0] != 42: return "", ""
        ifd = struct.unpack(e+'I', t[4:8])[0]
        if ifd + 2 > len(t):                   return "", ""
        nent = struct.unpack(e+'H', t[ifd:ifd+2])[0]
        mk = mo = ""
        for i in range(min(nent, 64)):
            o = ifd + 2 + i * 12
            if o + 12 > len(t): break
            tag, typ, cnt = struct.unpack(e+'HHI', t[o:o+8])
            if typ != 2: continue
            vr = t[o+8:o+12]
            if cnt <= 4:
                val = vr[:cnt].rstrip(b'\x00').decode('ascii','replace').strip()
            else:
                soff = struct.unpack(e+'I', vr)[0]
                val  = _s(t, soff, cnt)
            if   tag == 0x010F: mk = val
            elif tag == 0x0110: mo = val
            if mk and mo: break
        return mk, mo
    except Exception:
        return "", ""

def short_cam(make: str, model: str) -> str:
    if not make and not model: return "Unknown"
    noise = {'eos','dsc','ilce','dslr','digital','camera','mark',
             'ii','iii','iv','v','vi','vii','viii'}
    parts = []
    if make:  parts.append(make.split()[0])
    make0 = make.split()[0] if make else ""
    
    if make0:
        parts.append(make0)
    if model:
        for tok in model.split():
            t = tok.lower().rstrip('.,')
            if t not in noise and t != make0.lower():  # ← thêm điều kiện này
                parts.append(tok)

    return "".join(parts)[:22]


# ── Helpers ───────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def fmt_sz(n: float) -> str:
    for u in ('B','KB','MB','GB','TB'):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

_last_bar_len = [0]
def draw_progress(done: int, total: int, found: int, spd: float, eta_s: float):
    pct = done / total if total else 0
    w   = 34; f = int(w * pct)
    bar = "█" * f + "░" * (w - f)
    eta = f" ETA {int(eta_s//60):02d}:{int(eta_s%60):02d}" if eta_s > 0 else ""
    line = (f"{C}[{bar}]{R} {pct*100:5.1f}%  "
            f"{G}{fmt_sz(done)}{R}/{fmt_sz(total)}  "
            f"{Y}⚡{spd:.0f} MB/s{R}  "
            f"{M}🖼 {found}{R}{D}{eta}{R}")
    sys.stdout.write(f"\r{CL}{line}")
    sys.stdout.flush()
    _last_bar_len[0] = len(line)

def clear_bar():
    sys.stdout.write(f"\r{CL}")
    sys.stdout.flush()


# ── Precompute EOI positions từ buffer ───────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def find_all_eois(buf: bytes) -> "np.ndarray":
    """
    Trả về array các vị trí 'byte SAU FF D9' (tức end-exclusive offset).
    Dùng uint16 view zero-copy, xử lý cả vị trí chẵn lẫn lẻ.
    """
    TARGET = np.uint16(0xD9FF)   # little-endian: byte thấp=FF, byte cao=D9

    # Vị trí chẵn
    u16e = np.frombuffer(buf, dtype=np.uint16)
    even = (np.where(u16e == TARGET)[0] * 2) + 2

    # Vị trí lẻ — cắt buf[1:] về bội số 2
    tail = buf[1:]
    trim = len(tail) - (len(tail) & 1)
    u16o = np.frombuffer(tail[:trim], dtype=np.uint16)
    odd  = (np.where(u16o == TARGET)[0] * 2) + 3

    return np.sort(np.concatenate([even, odd])).astype(np.int64)


# ── Xử lý 1 chunk ────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def process_chunk(buf: bytes, base_off: int, min_bytes: int,
                  carry) -> tuple:
    """
    carry = None  hoặc  dict:
        abs_offset  : offset tuyệt đối của header (bytes)
        hdr_type    : 'E0' | 'E1'
        make, model : từ EXIF (hoặc "—")
        camera      : tên rút gọn
        accum_bytes : tổng số byte đã đọc từ header đến hết chunk TRƯỚC
                      ← FIX: thay tail_bytes, cộng dồn qua nhiều chunk

    Trả về (results_list, new_carry_or_None)
    """
    results = []

    arr = np.frombuffer(buf, dtype=np.uint8)
    n   = len(arr) // SECTOR

    # ── Bước 1: tìm headers theo sector ──────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────────
    b0 = arr[0::SECTOR][:n]; b1 = arr[1::SECTOR][:n]
    b2 = arr[2::SECTOR][:n]; b3 = arr[3::SECTOR][:n]
    hmask     = (b0==0xFF) & (b1==0xD8) & (b2==0xFF) & ((b3==0xE0)|(b3==0xE1))
    hdr_secs  = np.where(hmask)[0]
    hdr_offs  = (hdr_secs * SECTOR).astype(np.int64)
    hdr_types = (b3[hdr_secs] == 0xE1).astype(np.uint8)   # 1=E1, 0=E0

    # ── Bước 2: precompute tất cả FF D9 ──────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────────
    all_eois = find_all_eois(buf)                          # end offsets (sau D9)
    sentinel = np.array([len(buf) + 1], dtype=np.int64)
    eois_ext = np.concatenate([all_eois, sentinel])

    # ── Bước 3: xử lý carry từ chunk trước ───────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────────
    if carry is not None:
        # Giới hạn tìm EOI: phải trước header đầu tiên của chunk này
        lim = int(hdr_offs[0]) if len(hdr_offs) > 0 else len(buf)
        # FIX: dùng EOI ĐẦU TIÊN (lo) thay vì cuối cùng (hi-1)
        # → tránh nuốt header nằm giữa 2 FF D9
        lo = np.searchsorted(eois_ext, 0,   'left')   # bất kỳ EOI nào trước lim
        hi = np.searchsorted(eois_ext, lim, 'left')
        if lo < hi:
            # Lấy EOI đầu tiên hợp lệ ở chunk này
            best_eoi  = int(eois_ext[lo])
            img_size  = carry['accum_bytes'] + best_eoi
            if img_size >= min_bytes:
                results.append({
                    'abs_offset': carry['abs_offset'],
                    'hdr_type':   carry['hdr_type'],
                    'size_bytes': img_size,
                    'size_mb':    img_size, # / (1 << 20),
                    'make':       carry['make'],
                    'model':      carry['model'],
                    'camera':     carry['camera'],
                })
        else:
            # EOI chưa thấy trong chunk này → tiếp tục carry, cộng dồn size
            carry['accum_bytes'] += len(buf)
            return results, carry   # ← FIX: giữ nguyên carry qua chunk rỗng

    # ── Bước 4: ghép header → EOI trong chunk ────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────────
    new_carry = None
    n_hdrs    = len(hdr_offs)

    for i in range(n_hdrs):
        hoff  = int(hdr_offs[i])
        is_e1 = int(hdr_types[i])
        abs_h = base_off + hoff

        # Giới hạn: EOI phải nằm trước header kế tiếp
        lim = int(hdr_offs[i + 1]) if i + 1 < n_hdrs else len(buf)

        # FIX: tìm EOI ĐẦU TIÊN đủ xa (>= min_bytes sau header)
        lo = np.searchsorted(eois_ext, hoff + min_bytes, 'left')
        hi = np.searchsorted(eois_ext, lim,              'left')

        if lo < hi:
            # Có EOI hợp lệ — lấy EOI ĐẦU TIÊN (lo), không phải cuối (hi-1)
            best_eoi = int(eois_ext[lo])
            img_size = best_eoi - hoff
            make = model = ""
            if is_e1:
                eb  = buf[hoff: min(hoff + EXIF_BYTES, len(buf))]
                make, model = parse_make_model(eb)
            results.append({
                'abs_offset': abs_h,
                'hdr_type':   'E1' if is_e1 else 'E0',
                'size_bytes': img_size,
                'size_mb':    img_size, # / (1 << 20),
                'make':       make or "—",
                'model':      model or "—",
                'camera':     short_cam(make, model),
            })
        elif i == n_hdrs - 1:
            # Header cuối chunk — EOI chưa thấy → carry
            make = model = ""
            if is_e1:
                eb  = buf[hoff: min(hoff + EXIF_BYTES, len(buf))]
                make, model = parse_make_model(eb)
            new_carry = {
                'abs_offset': abs_h,
                'hdr_type':   'E1' if is_e1 else 'E0',
                'make':       make or "—",
                'model':      model or "—",
                'camera':     short_cam(make, model),
                # FIX: đổi tên tail_bytes → accum_bytes, rõ hơn
                'accum_bytes': len(buf) - hoff,
            }
        # else: header giữa chunk không tìm được EOI → ảnh corrupt, bỏ qua

    return results, new_carry


# ── Quét chính ────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def scan(filepath: str, log_path: str, min_mb: float, verbose: bool):
    fsize     = os.path.getsize(filepath)
    min_bytes = int(min_mb * (1 << 20))

    print(f"\n{B}{'─'*68}{R}")
    print(f"  {C}📂 File :{R} {filepath}")
    print(f"  {C}💾 Size :{R} {fmt_sz(fsize)}")
    print(f"  {C}📋 Log  :{R} {log_path}")
    print(f"  {C}🔎 Min  :{R} {min_mb:.3f} MB")
    print(f"{B}{'─'*68}{R}\n")

    all_results: list = []
    carry             = None
    t0                = time.perf_counter()
    bytes_done        = 0

    with open(filepath, 'rb') as fd:
        base = 0
        while True:
            raw = fd.read(CHUNK_SIZE)
            if not raw: break
            chunk = bytes(raw)   # immutable — safe for np.frombuffer

            found, carry = process_chunk(chunk, base, min_bytes, carry)
            all_results.extend(found)

            if verbose and found:
                clear_bar()
                for r in found:
                    idx = len(all_results) - len(found) + found.index(r) + 1
                    print(f"  {G}[#{idx:04d}]{R}  "
                          f"@0x{r['abs_offset']:010X}  "
                          f"{Y}{r['hdr_type']}{R}  "
                          f"{r['size_mb']:>12,d}  "
                          # f"{B}{r['camera']:<22}{R}  "
                          f"{D}{r['make']} {r['model']}{R}")

            bytes_done += len(chunk)
            base       += len(chunk)
            elapsed = time.perf_counter() - t0
            spd  = (bytes_done >> 20) / max(elapsed, 1e-9)
            rem  = ((fsize - bytes_done) >> 20) / max(spd, 0.1)
            draw_progress(bytes_done, fsize, len(all_results), spd, rem)

    elapsed = time.perf_counter() - t0
    avg_spd = (fsize >> 20) / max(elapsed, 1e-9)

    sys.stdout.write("\n")
    print(f"\n{B}{'─'*68}{R}")
    print(f"  {G}✅ Xong!{R}  "
          f"{B}{len(all_results)}{R} ảnh tìm thấy  │  "
          f"{elapsed:.1f}s  │  "
          f"{avg_spd:.0f} MB/s TB")

    # ── Ghi log ───────────────────────────────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────────
    SEP = "─" * 100
    header_txt = ( # Ghi log ở đây
        f"{SEP}\n"
        f"  jpeg_scanner  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Source : {filepath}  ({fmt_sz(fsize)})\n"
        f"  Filter : >= {min_mb:.3f} MB  ·  Found {len(all_results)} images\n"
        f"{SEP}\n\n"
        f"  {'No.':<8} {'Offset (hex)':<16} {'Hdr':<5} {'Size':>10}  "
        f"       {'Make':<20} Model\n"
        f"  {'─'*100}\n"
    )



    rows = [
        f"  [#{i:04d}]   @0x{r['abs_offset']:010X}   "
        f"{r['hdr_type']:<5}"
        f"{r['size_mb']:>12,d} B   "
        # f"{r['camera']:<24}"
        f"{r['make']:<20}"
        f"{r['model']}\n"
        for i, r in enumerate(all_results, 1)
    ]


    footer = (
        f"\n{SEP}\n"
        f"  Total   : {len(all_results)} images\n"
        f"  Scanned : {fmt_sz(fsize)}\n"
        f"  Time    : {elapsed:.2f} s\n"
        f"  Speed   : {avg_spd:.0f} MB/s\n"
    )


    with open(log_path, 'w', encoding='utf-8') as lf:
        lf.write(header_txt)
        lf.writelines(rows)
        lf.write(footer)

    print(f"  {C}📋 Log  :{R} {log_path}\n")
    return all_results


# ── In bảng kết quả ───────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def print_table(results: list):
    if not results:
        print(f"\n{Y}  Không tìm thấy ảnh nào.{R}\n")
        return
    SEP = "─" * 100
    print(f"\n{B}{SEP}{R}")


    print(f"  {B}{'No.':<8} {'Offset (hex)':<16} {'Hdr':<5} {'Size (B)':>10}  "
          f"     {'Make':<20} Model{R}")
    print(SEP)
    for i, r in enumerate(results, 1):
        hc = G if r['hdr_type'] == 'E1' else Y


        print(f"  {C}[#{i:04d}]{R}  "
              f"{M}@0x{r['abs_offset']:010X}{R}  "
              f"{hc}{r['hdr_type']:<5}{R}"
              f"{r['size_mb']:>12,d} B   "
              #f"{B}{r['camera']:<24}{R}"
              f"{D}{r['make']:<20}{r['model']}{R}")
    print(SEP)
    print(f"  Tổng: {G}{B}{len(results)}{R} ảnh\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog='jpeg_scanner',
        description='🔍 Quét file RAW / disk image tìm ảnh JPEG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python jpeg_scanner.py card.img
  python jpeg_scanner.py 16GB.dsk -o result.log --min-size 1.0
  python jpeg_scanner.py card.img -v --no-table
  sudo python jpeg_scanner.py /dev/sdc -o scan.log
        """
    )


    
    args_def = [
        (('input',), {
            'help': 'File raw / disk image / device (vd: /dev/sdc)'
        }),
        (('-o', '--output'), {
            'default': None,
            'help': 'File log đầu ra (mặc định: <input>.log)'
        }),
        (('--min-size',), {
            'type': float,
            'default': MIN_IMG_MB,
            'metavar': 'MB',
            'help': f'Kích thước tối thiểu tính là ảnh (mặc định {MIN_IMG_MB} MB)'
        }),
        (('-v', '--verbose'), {
            'action': 'store_true',
            'help': 'In từng ảnh ngay khi tìm thấy'
        }),
        (('--no-table',), {
            'action': 'store_true',
            'help': 'Bỏ qua bảng kết quả cuối'
        }),
        (('--chunk-mb',), {
            'type': int,
            'default': 256,
            'metavar': 'MB',
            'help': 'Kích thước chunk đọc (mặc định 256 MB, giảm nếu ít RAM)'
        }),
    ]



    for flags, kwargs in args_def:
        ap.add_argument(*flags, **kwargs)



    args = ap.parse_args()
    if not os.path.exists(args.input):
        print(f"\n{RE}  ❌ Không tìm thấy file: {args.input}{R}\n")
        sys.exit(1)

    global CHUNK_SIZE
    CHUNK_SIZE = args.chunk_mb * (1 << 20)

    log = args.output or (args.input + ".log")




    print(f"""
{B}{C}  ╔══════════════════════════════════════╗
  ║   JPEG RAW SCANNER  ·  High speed    ║
  ╚══════════════════════════════════════╝{R}
  {D}numpy · sector-aligned · uint16 EOI scan{R}""")

    results = scan(args.input, log, args.min_size, args.verbose)
    if not args.no_table:
        print_table(results)


if __name__ == '__main__':
    main()
