#!/usr/bin/env python3
"""Generate one illustration with the OpenAI Images API.

    python art/gen_image.py <out.png> <size> <prompt-file> [reference.png ...]

With reference images the edits endpoint is used, so the character stays the
same person across frames. The key is read from the project's .env; every call
is appended to art/generated/log.jsonl with its token usage.
"""
import base64
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
MODEL = "gpt-image-2"


def api_key() -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("OPENAI_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("OPENAI_API_KEY not found in .env")


def main() -> None:
    out, size, prompt_file, *refs = sys.argv[1:]
    prompt = Path(prompt_file).read_text()
    headers = {"Authorization": f"Bearer {api_key()}"}
    t0 = time.time()
    with httpx.Client(timeout=300) as client:
        if refs:
            files = [("image[]", (Path(r).name, Path(r).read_bytes(), "image/png")) for r in refs]
            data = {"model": MODEL, "prompt": prompt, "size": size, "quality": "high"}
            r = client.post("https://api.openai.com/v1/images/edits", headers=headers, data=data, files=files)
        else:
            body = {"model": MODEL, "prompt": prompt, "size": size, "quality": "high", "n": 1}
            r = client.post("https://api.openai.com/v1/images/generations", headers=headers, json=body)
    if r.status_code != 200:
        raise SystemExit(f"API error {r.status_code}: {r.text[:600]}")
    payload = r.json()
    Path(out).write_bytes(base64.b64decode(payload["data"][0]["b64_json"]))
    record = {"out": out, "size": size, "model": MODEL, "refs": refs, "seconds": round(time.time() - t0, 1),
              "usage": payload.get("usage")}
    with open(Path(__file__).parent / "generated" / "log.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
