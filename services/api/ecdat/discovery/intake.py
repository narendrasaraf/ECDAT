"""Bounded archive intake. No archive-provided link or executable is followed."""
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import hashlib
import re
import stat
import tarfile
import unicodedata
import zipfile


@dataclass(frozen=True)
class IntakeLimits:
    max_files: int = 5000
    max_file_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_ratio: int = 200
    max_depth: int = 20


def _name(name, seen, limits):
    if not name or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("Unsafe archive path")
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("..", ".") for part in name.split("/")):
        raise ValueError("Absolute or traversal path rejected")
    parts = p.parts
    if len(parts) > limits.max_depth or any(part.endswith((" ", ".")) for part in parts):
        raise ValueError("Ambiguous path or nesting limit exceeded")
    reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)
    if any(reserved.match(part) for part in parts):
        raise ValueError("Windows device path rejected")
    normalized = unicodedata.normalize("NFC", str(p))
    key = normalized.casefold()
    if key in seen:
        raise ValueError("Duplicate or case-colliding archive path")
    seen.add(key)
    return normalized


def _entries(archive, limits):
    seen, entries, total = set(), [], 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            if len(source.infolist()) > limits.max_files:
                raise ValueError("Archive entry limit exceeded")
            for member in source.infolist():
                # ZipInfo normalizes platform separators in filename on Windows;
                # orig_filename preserves the hostile archive name for validation.
                name = _name(member.orig_filename.rstrip("/"), seen, limits)
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or member.flag_bits & 1:
                    raise ValueError("Links, special files and encrypted entries are rejected")
                if member.file_size > limits.max_file_bytes:
                    raise ValueError("Per-file size limit exceeded")
                if member.file_size / max(1, member.compress_size) > limits.max_ratio:
                    raise ValueError("Compression ratio limit exceeded")
                total += member.file_size
                if total > limits.max_total_bytes:
                    raise ValueError("Total expanded size limit exceeded")
                entries.append((name, member.filename, member.file_size, member.is_dir()))
        fmt = "zip"
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as source:
            for index, member in enumerate(source):
                if index >= limits.max_files:
                    raise ValueError("Archive entry limit exceeded")
                name = _name(member.name.rstrip("/"), seen, limits)
                if not (member.isfile() or member.isdir()):
                    raise ValueError("Links and special files are rejected")
                if member.size > limits.max_file_bytes:
                    raise ValueError("Per-file size limit exceeded")
                total += member.size
                if total > limits.max_total_bytes:
                    raise ValueError("Total expanded size limit exceeded")
                entries.append((name, member.name, member.size, member.isdir()))
        if total / max(1, archive.stat().st_size) > limits.max_ratio:
            raise ValueError("Compression ratio limit exceeded")
        fmt = "tar"
    else:
        raise ValueError("Unsupported archive format")
    if total > limits.max_total_bytes:
        raise ValueError("Total expanded size limit exceeded")
    # Reject a file used as an ancestor of another entry before writing anything.
    files = {entry[0].casefold() for entry in entries if not entry[3]}
    for name, _, _, _ in entries:
        if any(str(parent).casefold() in files for parent in PurePosixPath(name).parents):
            raise ValueError("File/directory path collision")
    return fmt, entries


def validate_archive(archive: Path, limits: IntakeLimits | None = None) -> dict:
    try:
        fmt, entries = _entries(Path(archive), limits or IntakeLimits())
        return {"ok": True, "format": fmt, "entries": [
            {"path": name, "size": size, "directory": directory}
            for name, _, size, directory in entries]}
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return {"ok": False, "error": str(exc)}


def safe_extract_archive(archive: Path, destination: Path, limits: IntakeLimits | None = None) -> dict:
    """Extract to a fresh private staging directory; caller atomically publishes on success.

    Failed staging remains untrusted and must not be scanned/published. The caller owns
    cleanup. This helper never recursively deletes or overwrites an existing directory.
    """
    limits = limits or IntakeLimits()
    try:
        archive, destination = Path(archive), Path(destination)
        fmt, entries = _entries(archive, limits)
        if destination.exists():
            raise ValueError("Extraction destination must not already exist")
        destination.mkdir(parents=True)
        root = destination.resolve()
        source = zipfile.ZipFile(archive) if fmt == "zip" else tarfile.open(archive)
        manifest, written = [], 0
        with source:
            for name, original, size, directory in entries:
                target = root.joinpath(*PurePosixPath(name).parts)
                if not target.resolve().is_relative_to(root):
                    raise ValueError("Extraction escaped staging root")
                if directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.open(original) if fmt == "zip" else source.extractfile(original)
                digest, count = hashlib.sha256(), 0
                with stream, target.open("xb") as output:
                    while chunk := stream.read(65536):
                        count += len(chunk)
                        written += len(chunk)
                        if count > limits.max_file_bytes or written > limits.max_total_bytes:
                            raise ValueError("Actual expanded bytes exceed limits")
                        digest.update(chunk)
                        output.write(chunk)
                if count != size:
                    raise ValueError("Archive size declaration mismatch")
                manifest.append({"path": name, "size": count, "sha256": digest.hexdigest()})
        return {"ok": True, "manifest": manifest}
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError, RuntimeError, EOFError) as exc:
        return {"ok": False, "error": str(exc)}
