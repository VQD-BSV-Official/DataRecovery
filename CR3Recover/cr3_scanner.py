#!/usr/bin/env python3
"""
cr3_recover.py — Khôi phục ảnh Canon CR3 từ memory dump / disk image

Thuật toán (học từ WojciechMula/recovercr3, viết lại hoàn chỉnh):
  1. Quét buffer tìm chuỗi b'ftyp' tại byte-offset+4 của mỗi atom
  2. Đọc major_brand → xác nhận là CR3 ('crx ' hoặc 'CR3 ')
     → Chỉ reject khi MAJOR brand là video (mp41, qt, ...), compat brands được bỏ qua
  3. Duyệt top-level atoms liên tiếp, cộng dồn size
  4. Dừng khi gặp atom cuối (mặc định b'mdat') hoặc đủ maxchunks
  5. Ghi file ra outdir

CR3 structure (Canon R6 ví dụ):
    ftyp (24B)  → moov (35KB) → uuid → uuid → free → mdat (20-27 MB)
"""

import os, sys, struct, argparse, logging, time
from pathlib import Path
from datetime import datetime

MB = 1024 * 1024

# ANSI color (tự tắt nếu không TTY)
_tty = sys.stdout.isatty()
def _a(c): return c if _tty else ""
R  = _a("\033[0m");  B  = _a("\033[1m");  D  = _a("\033[2m")
G  = _a("\033[92m"); C  = _a("\033[96m"); Y  = _a("\033[93m")
M  = _a("\033[95m"); RE = _a("\033[91m"); CL = _a("\033[2K")

# ── CR3 constants ─────────────────────────────────────────────────────────────
# CR3 major brands hợp lệ
CR3_MAJOR_BRANDS = {b'crx ', b'CR3 '}

# Major brands chắc chắn là video — loại bỏ ngay
# NOTE: chỉ check MAJOR brand, KHÔNG check compatible brands
# vì CR3 thực tế có compat brand 'isom', 'crx ', v.v.
MP4_MAJOR_BRANDS = {
    b'mp41', b'mp42', b'mp4v', b'M4V ', b'M4A ', b'M4P ',
    b'avc1', b'qt  ', b'MSNV', b'F4V ', b'3gp4', b'3gp5',
    b'heic', b'heif', b'avif', b'mif1',
}

MAX_CR3_SIZE = 2 * 1024 * MB   # giới hạn 2 GB / file


# ── Helpers ───────────────────────────────────────────────────────────────────
def fmt_sz(n: float) -> str:
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def _draw_progress(done: int, total: int, found: int, spd: float, eta_s: float):
    if not _tty:
        return
    pct = done / total if total else 0
    w   = 30; f = int(w * pct)
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


# ── Atom parser ───────────────────────────────────────────────────────────────
def read_atom_header(file) -> tuple:
    """
    Đọc atom header ISOBMFF tại vị trí hiện tại.
    Trả về (abs_pos, name_bytes, total_size, header_len)
    hoặc (pos, None, 0, 0) nếu EOF.

    Dạng thường  : size(4BE) + name(4)               → hlen=8
    Dạng mở rộng : mark=1(4BE) + name(4) + size(8BE) → hlen=16
    size=0        : atom kéo đến EOF (caller tính)
    """
    pos = file.tell()
    raw = file.read(8)
    if len(raw) < 8:
        return pos, None, 0, 0

    raw_size = struct.unpack_from('>I', raw, 0)[0]
    name     = raw[4:8]

    if raw_size == 1:
        ext = file.read(8)
        if len(ext) < 8:
            return pos, None, 0, 0
        total_size = struct.unpack('>Q', ext)[0]
        hlen       = 16
    else:
        total_size = raw_size   # 0 = đến EOF, caller xử lý
        hlen       = 8

    return pos, name, total_size, hlen


def is_cr3_ftyp(file, ftyp_pos: int, ftyp_size: int, ftyp_hlen: int) -> bool:
    """
    Kiểm tra atom ftyp tại ftyp_pos có phải CR3 không.
    Chỉ cần: major_brand ∈ CR3_MAJOR_BRANDS
    VÀ      : major_brand ∉ MP4_MAJOR_BRANDS  (phòng ngừa)
    """
    file.seek(ftyp_pos + ftyp_hlen)
    payload_len = ftyp_size - ftyp_hlen
    if payload_len < 4:
        return False

    major = file.read(4)
    if len(major) < 4:
        return False

    # Loại video ngay
    if major in MP4_MAJOR_BRANDS:
        return False

    # Phải là CR3
    return major in CR3_MAJOR_BRANDS


def calc_cr3_size(file, ftyp_pos: int, file_size: int,
                  last_chunk: bytes, max_chunks: int, log) -> int:
    """
    Tính tổng size file CR3 bằng cách duyệt top-level atoms.

    Dừng khi:
      - name == last_chunk  (mặc định b'mdat')
      - chunk_idx >= max_chunks  (nếu max_chunks > 0)
      - size > MAX_CR3_SIZE → coi là corrupt
      - EOF / lỗi đọc

    Trả về size > 0 hoặc 0 nếu invalid.
    """
    file.seek(ftyp_pos)
    total     = 0
    chunk_idx = 0

    while True:
        pos, name, size, hlen = read_atom_header(file)

        if name is None:
            break  # EOF

        # Validate name: ASCII printable
        try:
            name_str = name.decode('ascii')
            if not all(0x20 <= b <= 0x7E for b in name):
                raise ValueError
        except Exception:
            log.debug(f"    atom name lạ {name!r} @ {pos:,d} → dừng")
            total = 0
            break

        # size=0 → atom kéo đến EOF
        if size == 0:
            size = file_size - pos
            log.debug(f"    atom {name!r} size=0→EOF ({size:,d}B) @ {pos:,d}")
            total += size
            chunk_idx += 1
            # Tự dừng vì đây là atom cuối
            if not last_chunk or name == last_chunk:
                break
            break

        if size > MAX_CR3_SIZE:
            log.warning(f"    atom {name!r} size={size:,d} > 2GB @ {pos:,d} → có thể corrupt")
            total = 0
            break

        if size < hlen:
            log.debug(f"    atom {name!r} size={size} < hlen={hlen} @ {pos:,d} → corrupt")
            total = 0
            break

        log.debug(f"    [{chunk_idx}] atom {name!r} size={size:,d} @ {pos:,d}")
        total     += size
        chunk_idx += 1

        # Điều kiện dừng
        if last_chunk and name == last_chunk:
            break
        if max_chunks > 0 and chunk_idx >= max_chunks:
            break

        file.seek(pos + size)

    return total


# ── Tìm headers trong dump ────────────────────────────────────────────────────
def find_cr3_headers(file, file_size: int, bufsize: int, log):
    """
    Generator: yield abs_offset của từng CR3 header trong dump.

    Tìm b'ftyp' bằng buffer search (nhanh hơn seek từng sector).
    KHÔNG giả định sector alignment vì:
      - Một số dump không align 512B
      - CR3 header có thể nằm ở bất kỳ offset nào
    Overlap giữa buffer để không bỏ sót header vắt ranh giới.
    """
    SEARCH  = b'ftyp'
    OVERLAP = 32    # đủ cho atom header 16 bytes + margin

    pos = 0
    while pos < file_size:
        file.seek(pos)
        buf = file.read(bufsize)
        if not buf:
            break

        buf_len   = len(buf)
        search_at = 0

        while search_at < buf_len:
            # Tìm 'ftyp' trong buffer
            # 'ftyp' là name (byte 4-7 của atom), nên atom bắt đầu tại idx-4
            idx = buf.find(SEARCH, search_at)
            if idx < 0:
                break
            if idx < 4:
                # 'ftyp' quá gần đầu buffer → không có chỗ cho size(4B)
                search_at = idx + 1
                continue

            atom_start_buf = idx - 4
            abs_offset     = pos + atom_start_buf

            # Đọc atom header từ file (không dùng buf để tránh lỗi extended size)
            file.seek(abs_offset)
            _, name, size, hlen = read_atom_header(file)

            if name == SEARCH and hlen > 0 and size >= hlen:
                if is_cr3_ftyp(file, abs_offset, size, hlen):
                    log.debug(f"  CR3 @ 0x{abs_offset:X} ({abs_offset:,d}B)")
                    yield abs_offset
                    # Bước qua ftyp atom để tránh yield trùng
                    search_at = atom_start_buf + max(size, 8)
                    continue

            search_at = idx + 1

        # Bước sang buffer tiếp (giữ overlap)
        advance = buf_len - OVERLAP
        if advance <= 0:
            break
        pos += advance


# ── Ghi file ──────────────────────────────────────────────────────────────────
def restore_file(src_file, offset: int, size: int,
                 out_path: Path, log, bufsize: int = 16 * MB) -> bool:
    if out_path.exists():
        log.info(f"  {Y}⚠ Bỏ qua{R} (đã tồn tại): {out_path.name}")
        return False

    src_file.seek(offset)
    remaining = size
    try:
        with out_path.open('wb') as dst:
            while remaining > 0:
                k   = min(bufsize, remaining)
                buf = src_file.read(k)
                if not buf:
                    log.error(f"  Đọc thiếu dữ liệu khi ghi {out_path.name}")
                    break
                dst.write(buf)
                remaining -= len(buf)
        return True
    except IOError as e:
        log.error(f"  Lỗi ghi {out_path.name}: {e}")
        return False


# ── Application ───────────────────────────────────────────────────────────────
class Application:
    def __init__(self, args, log):
        self.args      = args
        self.log       = log
        self.file_size = args.input.stat().st_size
        self.file_id   = 1

        if args.maxchunks:
            self.last_chunk = b''
            self.max_chunks = args.maxchunks
        else:
            lc = args.lastchunk
            self.last_chunk = lc.encode('ascii') if isinstance(lc, str) else lc
            self.max_chunks = 0

    def run(self):
        args      = self.args
        log       = self.log
        file_size = self.file_size
        bufsize   = args.chunk_mb * MB

        _print_banner(args, file_size)

        count      = 0
        t0         = time.perf_counter()

        with args.input.open('rb') as dump, args.input.open('rb') as cr3:
            for offset in find_cr3_headers(dump, file_size, bufsize, log):

                size = calc_cr3_size(
                    cr3, offset, file_size,
                    self.last_chunk, self.max_chunks, log
                )

                if size <= 0:
                    log.debug(f"  0x{offset:X}: size=0 → bỏ")
                    continue

                name     = f"{self.file_id:04d}.CR3"
                out_path = args.outdir / name

                _clear_bar()
                log.info(f"{G}[#{self.file_id:04d}]{R}  "
                         f"{M}@0x{offset:010X}{R}  "
                         f"{Y}{fmt_sz(size):>10}{R}  "
                         f"→ {C}{name}{R}")

                ok = restore_file(cr3, offset, size, out_path, log, bufsize)
                if ok:
                    self.file_id += 1
                    count        += 1

                elapsed = time.perf_counter() - t0
                spd     = (offset >> 20) / max(elapsed, 1e-9)
                rem     = ((file_size - offset) >> 20) / max(spd, 0.1)
                _draw_progress(offset, file_size, count, spd, rem)

        _clear_bar()
        elapsed = time.perf_counter() - t0
        avg_spd = (file_size >> 20) / max(elapsed, 1e-9)

        print(f"\n{B}{'─'*68}{R}")
        if count:
            print(f"  {G}✅ Hoàn thành!{R}  Khôi phục {B}{G}{count}{R} file CR3")
        else:
            print(f"  {Y}⚠  Không tìm thấy file CR3 nào.{R}")
            print(f"  {D}Thử: -v để xem log chi tiết, hoặc --lastchunk để đổi atom cuối{R}")
        print(f"  {D}Quét: {fmt_sz(file_size)}  │  {elapsed:.1f}s  │  {avg_spd:.0f} MB/s{R}")
        print(f"{B}{'─'*68}{R}\n")
        return count


# ── Banner ────────────────────────────────────────────────────────────────────
def _print_banner(args, fsize):
    lc = args.lastchunk if not args.maxchunks else f"(maxchunks={args.maxchunks})"
    print(f"""
{B}{C}  ╔══════════════════════════════════════════╗
  ║   CR3 RECOVER  ·  Canon RAW Recovery     ║
  ╚══════════════════════════════════════════╝{R}
  {D}ISOBMFF atom parser · major-brand check · no MP4 false positive{R}""")
    print(f"\n{B}{'─'*68}{R}")
    print(f"  {C}📂 Input     :{R} {args.input}")
    print(f"  {C}💾 Size      :{R} {fmt_sz(fsize)}")
    print(f"  {C}📁 Out dir   :{R} {args.outdir}")
    print(f"  {C}⏹  Last atom :{R} {lc}")
    print(f"  {C}📦 Chunk     :{R} {args.chunk_mb} MB")
    print(f"{B}{'─'*68}{R}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(
        prog='cr3_recover',
        description='📷 Khôi phục ảnh Canon CR3 từ memory dump / disk image',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python cr3_recover.py --input card.img --outdir recovered/
  python cr3_recover.py --input 64GB.dsk --outdir out/ --lastchunk mdat -v
  python cr3_recover.py --input dump.img --outdir out/ --maxchunks 6
  sudo python cr3_recover.py --input /dev/sdc --outdir out/

Về --lastchunk / --maxchunks:
  Canon R6 : ftyp → moov → uuid → uuid → free → mdat  (dừng tại 'mdat')
  Mặc định : --lastchunk mdat

  Nếu camera của bạn khác, dùng -v để xem tên atoms rồi đổi --lastchunk.
  Hoặc dùng --maxchunks=N để đọc đúng N atoms.
        """
    )
    ap.add_argument('--input',  type=Path, required=True,
                    metavar='PATH', help='File dump / disk image / device')
    ap.add_argument('--outdir', type=Path, required=True,
                    metavar='DIR',  help='Thư mục lưu file khôi phục')
    ap.add_argument('--lastchunk', type=str, default='mdat', metavar='NAME',
                    help='Tên atom cuối CR3 (mặc định: mdat)')
    ap.add_argument('--maxchunks', type=int, default=0, metavar='N',
                    help='Số atoms cố định thay cho --lastchunk')
    ap.add_argument('--chunk-mb', type=int, default=64, metavar='MB',
                    help='Buffer đọc (mặc định: 64 MB)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='In chi tiết từng atom')
    args = ap.parse_args()

    if not args.input.exists():
        ap.error(f"Không tìm thấy: {args.input}")
    if not args.outdir.is_dir():
        ap.error(f"Thư mục không tồn tại: {args.outdir}")
    if args.maxchunks < 0:
        ap.error("--maxchunks phải >= 0")
    if not args.lastchunk and not args.maxchunks:
        ap.error("--lastchunk không được rỗng")
    if args.chunk_mb < 1:
        ap.error("--chunk-mb phải >= 1")
    return args


def setup_logger(verbose: bool) -> logging.Logger:
    log = logging.getLogger('cr3_recover')
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    if log.handlers:
        return log
    ch = logging.StreamHandler()

    class _Fmt(logging.Formatter):
        def format(self, r):
            if r.levelno == logging.DEBUG:
                return f"  {D}[DBG] {r.getMessage()}{R}"
            if r.levelno == logging.WARNING:
                return f"  {Y}[WRN] {r.getMessage()}{R}"
            if r.levelno == logging.ERROR:
                return f"  {RE}[ERR] {r.getMessage()}{R}"
            return f"  {r.getMessage()}"

    ch.setFormatter(_Fmt())
    log.addHandler(ch)
    return log


def main():
    args = parse_args()
    log  = setup_logger(args.verbose)
    app  = Application(args, log)
    app.run()


if __name__ == '__main__':
    main()
