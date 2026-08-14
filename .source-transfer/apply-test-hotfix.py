from __future__ import annotations

from hashlib import sha256
from pathlib import Path

path = Path("/tmp/nplg-source/tests/helpers/pdf_factory.py")
old = '        algorithm="AES-256",\n'
new = (
    "        # The fixture only needs password protection; RC4 keeps this test\n"
    "        # independent of pypdf's optional cryptography extra.\n"
    '        algorithm="RC4-128",\n'
)
text = path.read_text(encoding="utf-8")
if text.count(old) != 1:
    raise SystemExit("expected AES fixture line was not found exactly once")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
actual = sha256(path.read_bytes()).hexdigest()
expected = "1fd601652d41acdf5a398c1e5914459063d8f6c1700a2da829fcda830ee573f0"
if actual != expected:
    raise SystemExit(f"patched fixture checksum mismatch: {actual}")
print("self-contained encrypted PDF fixture hotfix applied")
