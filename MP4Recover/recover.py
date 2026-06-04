import re
import os

BIN_FILE = "drive_480_to_484GB.dsk"
LOG_FILE = "log.txt"
OUT_DIR = "recovered"

os.makedirs(OUT_DIR, exist_ok=True)

with open(LOG_FILE, "r", encoding="utf-8") as f:
    log = f.read()

pattern = re.compile(
    r"Candidate #(\d+).*?offset ([\d,]+).*?End\s*:\s*([\d,]+)",
    re.S
)

with open(BIN_FILE, "rb") as fin:

    for num, start, end in pattern.findall(log):

        start = int(start.replace(",", ""))
        end = int(end.replace(",", ""))

        size = end - start

        print(f"Extracting #{num}: {start:,} -> {end:,} ({size:,} bytes)")

        fin.seek(start)
        data = fin.read(size)

        with open(
            os.path.join(OUT_DIR, f"candidate_{num}.mp4"),
            "wb"
        ) as fout:
            fout.write(data)

print("Done")