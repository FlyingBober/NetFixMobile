#!/usr/bin/env python3
"""Fetch verified nfqws (zapret) and ciadpi (byedpi) binaries for packaging."""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ZAPRET_API = "https://api.github.com/repos/bol-van/zapret/releases/latest"
BYEDPI_API = "https://api.github.com/repos/hufrea/byedpi/releases/latest"

ARCH_HINTS = {
    "x86_64": ["linux-x86_64", "x86_64", "amd64", "x64"],
    "aarch64": ["linux-arm64", "aarch64", "arm64"],
}

KNOWN_ARCH_TOKENS = [
    "x86_64", "amd64", "x64", "aarch64", "arm64", "armv7", "armv6", "armhf",
    "mips", "riscv", "ppc", "s390", "i386", "i686", "x86", "darwin", "macos",
    "windows", "win32", "win64", "freebsd", "openbsd",
]

SKIP_SUFFIXES = (".sha256", ".sha256sum", ".sig", ".asc", ".exe", ".txt", ".md")


def http_get_json(url: str) -> dict:
    cmd = [
        "curl",
        "-fsSL",
        "--retry",
        "3",
        "--retry-delay",
        "2",
        "--connect-timeout",
        "20",
        "--max-time",
        "60",
        "-H",
        "User-Agent: netfixlinux-packager/1.0",
        "-H",
        "Accept: application/vnd.github+json",
    ]
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token and "api.github.com" in url:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    cmd.append(url)
    res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
    return json.loads(res.stdout.decode("utf-8"))


def download_file_verified(url: str, dest_path: str, expected_sha256: str | None) -> None:
    last_err: Exception | None = None
    for attempt in range(1, 5):
        if attempt > 1:
            time.sleep(attempt)
        cmd = [
            "curl",
            "-fSL",
            "--continue-at",
            "-",
            "--connect-timeout",
            "20",
            "--speed-limit",
            "1024",
            "--speed-time",
            "20",
            "--max-time",
            "300",
            "-H",
            "User-Agent: netfixlinux-packager/1.0",
            "-o",
            dest_path,
            url,
        ]
        res = subprocess.run(cmd, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            last_err = RuntimeError(
                f"curl failed (exit {res.returncode}, attempt {attempt}/4): {res.stderr.strip()}"
            )
            # If server rejected Range (e.g. HTTP 416 / 33), restart clean on next attempt.
            if res.returncode in (33, 36) and os.path.exists(dest_path):
                os.remove(dest_path)
            continue

        if expected_sha256:
            h = hashlib.sha256()
            with open(dest_path, "rb") as fp:
                for chunk in iter(lambda: fp.read(65536), b""):
                    h.update(chunk)
            actual = h.hexdigest().lower()
            if actual != expected_sha256:
                os.remove(dest_path)
                last_err = RuntimeError(
                    f"SHA-256 mismatch (attempt {attempt}/4): expected {expected_sha256}, got {actual}"
                )
                continue
        return

    assert last_err is not None
    raise last_err


def select_asset(assets: list[dict], engine: str, arch: str) -> dict:
    hints = ARCH_HINTS[arch]

    def excluded(name: str) -> bool:
        low = name.lower()
        return any(
            tok in low for tok in ("windows", "win32", "win64", "darwin", "macos", "android")
        ) or low.endswith((".sha256", ".sig", ".asc"))

    if engine == "nfqws":
        for asset in assets:
            low = asset["name"].lower()
            if (
                not excluded(low)
                and "openwrt" not in low
                and low.startswith("zapret-")
                and low.endswith((".tar.gz", ".tgz"))
            ):
                return asset

    for asset in assets:
        low = asset["name"].lower()
        if (
            not excluded(low)
            and any(h in low for h in hints)
            and low.endswith((".tar.gz", ".tgz"))
        ):
            return asset

    for asset in assets:
        low = asset["name"].lower()
        if not excluded(low) and (engine in low or any(h in low for h in hints)):
            return asset

    raise RuntimeError(f"No compatible {engine} asset found for {arch}")


def foreign_arch(path_lower: str, hints: list[str]) -> bool:
    for tok in KNOWN_ARCH_TOKENS:
        if tok in path_lower and not any(tok in h.lower() for h in hints):
            return True
    return False


def extract_binary(archive_path: str, engine: str, arch: str) -> bytes:
    hints = ARCH_HINTS[arch]
    best_score = -10**9
    best_data: bytes | None = None

    with tarfile.open(archive_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            path_lower = member.name.lower()
            base = os.path.basename(path_lower)
            exact = base == engine
            prefixed = base.startswith(f"{engine}-")
            if not exact and not prefixed:
                continue
            if base.endswith(SKIP_SUFFIXES):
                continue

            score = 100 if exact else 50
            matched_idx = next(
                (i for i, h in enumerate(hints) if h.lower() in path_lower), None
            )
            if matched_idx is not None:
                score += 1000 - matched_idx * 10
            elif foreign_arch(path_lower, hints):
                continue

            if score > best_score:
                f = tf.extractfile(member)
                if f is not None:
                    data = f.read()
                    if data:
                        best_score = score
                        best_data = data

    if best_data is None:
        raise RuntimeError(f"Archive did not contain compatible '{engine}' for {arch}")
    return best_data


def fetch_one(engine: str, api_url: str, arch: str, out_dir: str, tmp_dir: str) -> str:
    release = http_get_json(api_url)
    asset = select_asset(release.get("assets", []), engine, arch)
    digest = (asset.get("digest") or "").strip()
    expected = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None

    archive_path = os.path.join(tmp_dir, asset["name"])
    download_file_verified(asset["browser_download_url"], archive_path, expected)

    binary = extract_binary(archive_path, engine, arch)
    dest = os.path.join(out_dir, engine)
    with open(dest, "wb") as fp:
        fp.write(binary)
    os.chmod(dest, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch nfqws & ciadpi binaries for packaging")
    parser.add_argument("--arch", required=True, choices=["x86_64", "aarch64"])
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="netfix-engines-") as tmp_dir:
        for engine, api_url in (("nfqws", ZAPRET_API), ("ciadpi", BYEDPI_API)):
            dest = fetch_one(engine, api_url, args.arch, args.out_dir, tmp_dir)
            print(f"    Fetched {engine} ({args.arch}) -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
