"""Deterministic, non-executing cryptographic discovery."""
from .scanner import scan_directory
from .intake import safe_extract_archive, validate_archive, IntakeLimits
safe_extract_zip = safe_extract_archive

__all__ = ["scan_directory", "safe_extract_archive", "safe_extract_zip", "validate_archive", "IntakeLimits"]
