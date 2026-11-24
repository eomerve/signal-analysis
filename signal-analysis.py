
from pathlib import Path
from datetime import datetime
import struct
import json
import csv
import os

os.umask(0o077)

BASE = Path(__file__).resolve().parent

if not (BASE / "cms_raw.bin").exists():
    BASE = BASE.parent

raw = (BASE / "cms_raw.bin").read_bytes()

OUTPUT = BASE / "signal_analysis"
OUTPUT.mkdir(exist_ok=True)

frames = []
chunks = []

# Read capture timestamps
with open(BASE / "cms_raw.txt") as f:
    for line in f:
        item = json.loads(line)
        chunks.append(item)


def get_timestamp(end_offset):
    for chunk in chunks:
        start = chunk["byte_offset"]
        end = start + chunk["length"]

        if start < end_offset <= end:
            return chunk["timestamp"]

    return None


# Extract QCMS frames
offset = 0

while offset + 10 <= len(raw):

    if raw[offset:offset + 4] != b"QCMS":
        print("Invalid header:", offset)
        break

    length = int.from_bytes(
        raw[offset + 8:offset + 10],
        "little"
    )

    if length < 10 or offset + length > len(raw):
        print("Incomplete frame:", offset)
        break

    packet = raw[offset:offset + length]

    if length == 2518 and packet[7] == 5:

        frames.append({
            "offset": offset,
            "timestamp": get_timestamp(offset + length),
            "packet": packet
        })

    offset += length

print("Periodic frames:", len(frames))

if not frames:
    raise SystemExit("No periodic frames found")


# Print timing information
print("\nFRAME TIMING")

previous = None

for i, frame in enumerate(frames):

    timestamp = frame["timestamp"]

    print("Frame:", i + 1, timestamp)

    if timestamp:
        current = datetime.fromisoformat(timestamp)

        if previous:
            delta = (current - previous).total_seconds()
            print("Interval:", delta, "seconds")

        previous = current


# Inspect possible vital parameters
print("\nVITAL CANDIDATES")

for pos in range(16, 128, 2):

    values = [
        struct.unpack_from(
            "<h", frame["packet"], pos
        )[0]
        for frame in frames
    ]

    print(
        f"Offset {pos:03d} "
        f"(0x{pos:04X}): {values}"
    )


# Export aligned 16-bit candidates
with open(
    OUTPUT / "words.csv",
    "w",
    newline=""
) as f:

    writer = csv.writer(f)

    writer.writerow(
        ["offset"] +
        [f"frame_{i+1}" for i in range(len(frames))]
    )

    for pos in range(16, 2517, 2):

        values = [
            struct.unpack_from(
                "<h", frame["packet"], pos
            )[0]
            for frame in frames
        ]

        writer.writerow([pos] + values)


# Analyse changing 32-byte blocks
print("\nDATA BLOCK ANALYSIS")

for start in range(16, 2518, 32):

    end = min(start + 32, 2518)

    blocks = [
        frame["packet"][start:end]
        for frame in frames
    ]

    changed = sum(
        len(set(column)) > 1
        for column in zip(*blocks)
    )

    print(
        f"{start:04d}-{end-1:04d} "
        f"changed bytes: {changed}/{end-start}"
    )

print("\nSaved:", OUTPUT / "words.csv")