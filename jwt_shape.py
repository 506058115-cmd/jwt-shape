#!/usr/bin/env python3
"""Show a JWS token's JSON structure without exposing values or signature."""

import argparse
import base64
from collections import Counter
from itertools import islice
import json
from pathlib import Path
import re
import sys


MAX_INPUT_BYTES = 128 * 1024
MAX_DEPTH = 5
MAX_ARRAY_ITEMS = 100
MAX_OBJECT_KEYS = 200
MAX_NODES = 20_000
MAX_ROWS = 200
BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


def kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object" if isinstance(value, dict) else "array"


def property_path(path, key):
    if len(key) > 80:
        key = key[:77] + "..."
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def reject_constant(value):
    raise ValueError("non-standard JSON constant")


def decode_object(segment):
    if not segment or not BASE64URL.fullmatch(segment):
        raise ValueError("header and payload must be unpadded base64url JSON")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        value = json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
    except (ValueError, UnicodeError, json.JSONDecodeError, base64.binascii.Error):
        raise ValueError("header or payload is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise ValueError("header and claims must be JSON objects")
    return value


def summarize(label, root):
    counts = Counter()
    array_lengths = {}
    stack = [("$", root, 0)]
    visited = 0
    truncated = False

    while stack and visited < MAX_NODES:
        path, value, depth = stack.pop()
        visited += 1
        counts[(path, kind(value))] += 1
        if isinstance(value, dict):
            if depth + 1 >= MAX_DEPTH:
                truncated |= bool(value)
                continue
            entries = list(islice(value.items(), MAX_OBJECT_KEYS))
            truncated |= len(value) > len(entries)
            stack.extend(
                (property_path(path, key), child, depth + 1)
                for key, child in reversed(entries)
            )
        elif isinstance(value, list):
            array_lengths.setdefault(path, []).append(len(value))
            if depth + 1 >= MAX_DEPTH:
                truncated |= bool(value)
                continue
            children = value[:MAX_ARRAY_ITEMS]
            truncated |= len(value) > len(children)
            stack.extend((path + "[]", child, depth + 1) for child in reversed(children))

    rows = sorted(counts.items())
    print(f"{label}:")
    for (path, value_kind), count in rows[:MAX_ROWS]:
        detail = f"{value_kind} × {count}"
        if value_kind == "array":
            lengths = array_lengths[path]
            detail += f" (length {min(lengths)}–{max(lengths)})"
        print(f"  {path}  {detail}")
    if len(rows) > MAX_ROWS:
        truncated = True
        print(f"  … {len(rows) - MAX_ROWS} more structure rows omitted")
    if stack:
        truncated = True
    if truncated:
        print("  Note: summary is capped by depth, object, array, or node limits.")


def read_token(source_name):
    if source_name == "-":
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    else:
        with Path(source_name).open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the 128 KiB limit")
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ValueError("input must be an ASCII compact token") from None


def main():
    parser = argparse.ArgumentParser(
        description="Inspect a three-part token's JSON shape; values and signature stay hidden."
    )
    parser.add_argument("source", nargs="?", default="-", help="token text file, or - for standard input")
    args = parser.parse_args()

    try:
        token = read_token(args.source)
        parts = token.split(".")
        if len(parts) == 5:
            raise ValueError("five-part encrypted JWE tokens are not supported")
        if len(parts) != 3:
            raise ValueError("expected a three-part JWS compact token")
        if not BASE64URL.fullmatch(parts[2]):
            raise ValueError("signature segment contains non-base64url characters")
        header, claims = decode_object(parts[0]), decode_object(parts[1])
    except (OSError, ValueError) as error:
        print(f"jwt-shape: {error}", file=sys.stderr)
        return 2

    print("Three-part token decoded; authenticity and claims were not verified.")
    summarize("Header", header)
    summarize("Claims", claims)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
