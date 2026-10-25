"""Windows release checksum sidecar: LF only, so sha256sum -c and shasum -c accept it (#7).

Offline. Checks the bytes the build writes rather than the file's text: read_text() would hide a
carriage return. On the Windows runner a text-mode write fails here; on Linux and macOS the same
assertion keeps the contract explicit.
"""

from __future__ import annotations

from pathlib import Path

from release.build_windows import write_checksum_file

DIGEST = "0" * 64
NAME = "MySQL-DBA-Validator-v0.7.0-windows-x64.zip"


def test_checksum_file_has_one_lf_line_and_no_carriage_return(tmp_path: Path) -> None:
    path = tmp_path / f"{NAME}.sha256"

    write_checksum_file(path, DIGEST, NAME)

    assert path.read_bytes() == f"{DIGEST}  {NAME}\n".encode("ascii")
    assert b"\r" not in path.read_bytes()
