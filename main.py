import argparse
import os
import shutil
import json
import re
from datetime import datetime
from pathlib import Path

#!/usr/bin/env python3
"""
Example Python data-recovery helper.

Creates a "recovered" directory and offers:
- scanning for backup / temp files (.bak, ~, .swp, .tmp)
- attempting to extract valid JSON objects from corrupted text files
- simple file-carving for JPEG and PNG images out of a binary blob

This is an example starting point — real-forensic recovery is far more complex
and often requires raw-disk access and specialist tools.
"""


OUT_ROOT = Path("recovered")


def ensure_out_dir():
  OUT_ROOT.mkdir(parents=True, exist_ok=True)
  timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
  out = OUT_ROOT / timestamp
  out.mkdir()
  return out


# 1) Find common backup/temp files in a directory tree
COMMON_SUFFIXES = [".bak", ".backup", ".old", ".orig", "~", ".tmp", ".swp", ".save"]


def find_backup_files(root: Path):
  files = []
  for p in root.rglob("*"):
    if p.is_file():
      name = p.name
      if any(name.endswith(suf) for suf in COMMON_SUFFIXES) or name.startswith(".~") or name.endswith(".~"):
        files.append(p)
  return files


def recover_backups(root: Path):
  out = ensure_out_dir()
  matches = find_backup_files(root)
  for i, p in enumerate(matches, 1):
    dest = out / f"backup_{i}_{p.name}"
    try:
      shutil.copy2(p, dest)
    except Exception:
      try:
        # fallback to simple copy
        with p.open("rb") as rf, dest.open("wb") as wf:
          wf.write(rf.read())
      except Exception:
        continue
  print(f"Recovered {len(matches)} backup/temp files to: {out}")


# 2) Extract JSON-like objects from messy/corrupted text
def extract_json_objects_from_text(text: str):
  objs = []

  # Strategy: find balanced {...} blocks and balanced [...] blocks
  def extract_balanced(open_ch, close_ch):
    results = []
    level = 0
    start = None
    for i, ch in enumerate(text):
      if ch == open_ch:
        if level == 0:
          start = i
        level += 1
      elif ch == close_ch and level > 0:
        level -= 1
        if level == 0 and start is not None:
          snippet = text[start : i + 1]
          results.append(snippet)
    return results

  for s in extract_balanced("{", "}"):
    try:
      objs.append(json.loads(s))
    except Exception:
      pass

  for s in extract_balanced("[", "]"):
    try:
      parsed = json.loads(s)
      # If a top-level array, extend with elements
      if isinstance(parsed, list):
        objs.extend(parsed)
      else:
        objs.append(parsed)
    except Exception:
      pass

  # Additionally, try to find JSON via regex for quoted keys (best-effort)
  pattern = re.compile(r"\{(?:[^{}]|(?R))*\}", re.DOTALL) if hasattr(re, "compile") else None
  # The above recursive pattern may not be supported; we keep it optional

  return objs


def recover_json_from_file(path: Path):
  out = ensure_out_dir()
  recovered_count = 0
  with path.open("r", errors="ignore") as f:
    text = f.read()
  objs = extract_json_objects_from_text(text)
  for i, o in enumerate(objs, 1):
    fname = out / f"{path.stem}_json_{i}.json"
    try:
      with fname.open("w", encoding="utf8") as wf:
        json.dump(o, wf, indent=2, ensure_ascii=False)
      recovered_count += 1
    except Exception:
      continue
  print(f"Extracted {recovered_count} JSON object(s) from {path} -> {out}")


# 3) Simple carving for JPEG and PNG from a binary blob
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"IEND"


def carve_images_from_file(path: Path):
  out = ensure_out_dir()
  data = path.read_bytes()
  count = 0

  # JPEGs
  start = 0
  while True:
    s = data.find(JPEG_SOI, start)
    if s == -1:
      break
    e = data.find(JPEG_EOI, s + 2)
    if e == -1:
      # no explicit EOI found; write until next header or EOF
      next_header = data.find(JPEG_SOI, s + 2)
      endpos = next_header if next_header != -1 else len(data)
    else:
      endpos = e + 2
    out_path = out / f"{path.stem}_jpg_{count + 1}.jpg"
    out_path.write_bytes(data[s:endpos])
    count += 1
    start = endpos

  # PNGs
  start = 0
  while True:
    s = data.find(PNG_SIG, start)
    if s == -1:
      break
    # find 'IEND' chunk after s
    iend_pos = data.find(PNG_IEND, s + len(PNG_SIG))
    if iend_pos == -1:
      # fallback: write until next PNG header or EOF
      next_sig = data.find(PNG_SIG, s + len(PNG_SIG))
      endpos = next_sig if next_sig != -1 else len(data)
    else:
      # include "IEND" + 4 bytes CRC after it
      endpos = iend_pos + 4 + 4
      if endpos > len(data):
        endpos = len(data)
    out_path = out / f"{path.stem}_png_{count + 1}.png"
    out_path.write_bytes(data[s:endpos])
    count += 1
    start = endpos

  print(f"Carved {count} image(s) from {path} -> {out}")


def main():
  parser = argparse.ArgumentParser(prog="main.py", description="Example data recovery helper")
  sub = parser.add_subparsers(dest="command", required=True)

  p_backups = sub.add_parser("backups", help="scan a directory for backup/temp files and copy them")
  p_backups.add_argument("root", nargs="?", default=".", help="root directory to scan")

  p_json = sub.add_parser("json", help="attempt to extract JSON objects from a file")
  p_json.add_argument("file", help="file to scan for JSON")

  p_carve = sub.add_parser("carve", help="carve JPEG/PNG images from a binary file")
  p_carve.add_argument("file", help="binary file to carve images from")

  p_all = sub.add_parser("all", help="run all recovery actions on a path (directory or file)")
  p_all.add_argument("path", nargs="?", default=".", help="path to inspect")

  args = parser.parse_args()

  if args.command == "backups":
    root = Path(args.root).expanduser().resolve()
    recover_backups(root)

  elif args.command == "json":
    p = Path(args.file).expanduser().resolve()
    if not p.exists():
      print("File not found:", p)
      return
    recover_json_from_file(p)

  elif args.command == "carve":
    p = Path(args.file).expanduser().resolve()
    if not p.exists():
      print("File not found:", p)
      return
    carve_images_from_file(p)

  elif args.command == "all":
    p = Path(args.path).expanduser().resolve()
    if p.is_dir():
      # find files and try each technique
      for f in p.rglob("*"):
        if not f.is_file():
          continue
        # attempt JSON extraction for text-like names
        if f.suffix.lower() in {".log", ".txt", ".json", ".ndjson", ".csv"}:
          try:
            recover_json_from_file(f)
          except Exception:
            pass
        # carve binaries for images
        try:
          carve_images_from_file(f)
        except Exception:
          pass
      # copy backups
      recover_backups(p)
    elif p.is_file():
      # single file: try JSON and carving and also check if it's a backup itself
      try:
        recover_json_from_file(p)
      except Exception:
        pass
      try:
        carve_images_from_file(p)
      except Exception:
        pass
      # if file looks like a backup, copy it
      if any(p.name.endswith(s) for s in COMMON_SUFFIXES):
        out = ensure_out_dir()
        shutil.copy2(p, out / p.name)
        print(f"Copied backup file to {out}")

if __name__ == "__main__":
  main()