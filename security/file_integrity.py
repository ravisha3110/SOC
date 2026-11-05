"""File Integrity Monitoring (FIM) Engine.

Provides cryptographic SHA-256 baseline creation, incremental file hashing,
and filesystem integrity verification for the CyberShield SOC platform.

Key Academic Principles:
- Cryptographic Hashing: SHA-256 produces a deterministic 256-bit (64-character
  hexadecimal) digest of arbitrary file data.
- Incremental Chunking: Reading files in 64 KB blocks prevents memory exhaustion
  when auditing large files.
- Zero Execution & Modification: Scanned files are opened strictly in binary read-only
  ("rb") mode; no scanned code is ever executed or modified.
- Safe Filesystem Traversal: Symbolic link handling prevents circular directory recursion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import os
from pathlib import Path
from typing import Any, Protocol


class IntegrityStatus(str, Enum):
    """Integrity evaluation states for monitored files."""

    UNCHANGED = "UNCHANGED"
    MODIFIED = "MODIFIED"
    NEW = "NEW"
    MISSING = "MISSING"
    ERROR = "ERROR"


@dataclass
class FileIntegrityRecord:
    """Represents the cryptographic integrity state of a single monitored file.

    Attributes:
        file_path: Absolute or normalized filesystem path of the file.
        file_name: Base filename (e.g., 'hosts' or 'config.json').
        file_size: Size of the file in bytes (0 if missing or inaccessible).
        sha256_hash: 64-character hexadecimal SHA-256 digest (empty if missing/error).
        status: Integrity status (UNCHANGED, MODIFIED, NEW, MISSING, ERROR).
        previous_hash: Baseline hash previously recorded (None if new).
        timestamp: ISO-8601 UTC timestamp of the inspection.
        error_message: Explanatory error details if an exception occurred.
    """

    file_path: str
    file_name: str
    file_size: int = 0
    sha256_hash: str = ""
    status: IntegrityStatus = IntegrityStatus.NEW
    previous_hash: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to dictionary for repository persistence or UI display."""
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256_hash": self.sha256_hash,
            "status": self.status.value,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "error_message": self.error_message,
        }


class BaselineRepositoryProtocol(Protocol):
    """Protocol defining the repository operations required for baseline persistence."""

    def create(
        self,
        file_name: str,
        file_hash: str,
        record_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]: ...

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]: ...


def calculate_sha256(file_path: str | Path, chunk_size: int = 65536) -> str:
    """Calculate the cryptographic SHA-256 digest of a file using chunked streaming.

    Args:
        file_path: Target filesystem path to hash.
        chunk_size: Block size in bytes (defaults to 64 KB = 65,536 bytes).

    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If read permissions are denied.
        OSError: On low-level filesystem or I/O failure.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


class FileIntegrityScanner:
    """Engine for performing file integrity monitoring and baseline verification.

    Never executes or uploads file contents. Only stores cryptographic SHA-256
    digests and metadata in accordance with SOC security practices.
    """

    DEFAULT_CHUNK_SIZE = 65536  # 64 KB

    def __init__(
        self,
        baseline_repo: BaselineRepositoryProtocol | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        """Initialize the scanner.

        Args:
            baseline_repo: Optional database repository implementing BaselineRepositoryProtocol.
            chunk_size: Chunk size in bytes for incremental file reads.
        """
        self.baseline_repo = baseline_repo
        self.chunk_size = chunk_size
        self._baseline_cache: dict[str, str] = {}  # Normalized path -> SHA-256 hash

        if self.baseline_repo is not None:
            self.load_baseline_from_repository()

    @property
    def baseline_cache(self) -> dict[str, str]:
        """Return a read-only copy of the active in-memory baseline."""
        return dict(self._baseline_cache)

    def set_baseline(self, baseline: dict[str, str]) -> None:
        """Explicitly set or replace the active baseline in memory.

        Args:
            baseline: Dictionary mapping normalized file paths to expected SHA-256 digests.
        """
        self._baseline_cache = {
            os.path.normpath(path): hash_val.lower().strip()
            for path, hash_val in baseline.items()
        }

    def update_baseline_entry(self, file_path: str | Path, sha256_hash: str) -> None:
        """Update or insert a single baseline entry into the cache."""
        norm_path = os.path.normpath(str(file_path))
        self._baseline_cache[norm_path] = sha256_hash.lower().strip()

    def clear_baseline(self) -> None:
        """Clear all active baseline entries from memory."""
        self._baseline_cache.clear()

    def load_baseline_from_repository(self, limit: int = 500) -> dict[str, str]:
        """Load baseline records from the attached database repository.

        Returns:
            dict[str, str]: Dictionary of loaded baselines (path -> hash).
        """
        if self.baseline_repo is None:
            return {}

        records = self.baseline_repo.list_all(limit=limit)
        loaded: dict[str, str] = {}
        for rec in records:
            file_name = rec.get("file_name")
            file_hash = rec.get("file_hash")
            if file_name and file_hash:
                norm = os.path.normpath(file_name)
                loaded[norm] = file_hash.lower().strip()

        self._baseline_cache.update(loaded)
        return loaded

    def save_baseline_to_repository(
        self,
        records: list[FileIntegrityRecord],
    ) -> int:
        """Persist verified scan records as official baseline entries in the repository.

        Args:
            records: List of successfully scanned FileIntegrityRecord objects.

        Returns:
            int: Count of successfully persisted baseline records.
        """
        if self.baseline_repo is None:
            return 0

        saved_count = 0
        for rec in records:
            if rec.status in (IntegrityStatus.NEW, IntegrityStatus.MODIFIED, IntegrityStatus.UNCHANGED):
                if rec.sha256_hash and not rec.error_message:
                    norm = os.path.normpath(rec.file_path)
                    self.baseline_repo.create(
                        file_name=norm,
                        file_hash=rec.sha256_hash,
                    )
                    self._baseline_cache[norm] = rec.sha256_hash
                    saved_count += 1

        return saved_count

    def scan_file(
        self,
        file_path: str | Path,
        baseline: dict[str, str] | None = None,
    ) -> FileIntegrityRecord:
        """Scan and verify a single file's cryptographic integrity against the baseline.

        Args:
            file_path: Target filesystem path to inspect.
            baseline: Optional custom baseline dictionary. If None, uses active cache.

        Returns:
            FileIntegrityRecord: Detailed evaluation of the file.
        """
        str_path = str(file_path)
        norm_path = os.path.normpath(str_path)
        base_name = os.path.basename(norm_path)
        active_baseline = baseline if baseline is not None else self._baseline_cache
        expected_hash = active_baseline.get(norm_path)

        if not os.path.exists(norm_path):
            if expected_hash:
                return FileIntegrityRecord(
                    file_path=norm_path,
                    file_name=base_name,
                    file_size=0,
                    sha256_hash="",
                    status=IntegrityStatus.MISSING,
                    previous_hash=expected_hash,
                    error_message="File recorded in baseline but missing from filesystem.",
                )
            return FileIntegrityRecord(
                file_path=norm_path,
                file_name=base_name,
                file_size=0,
                sha256_hash="",
                status=IntegrityStatus.ERROR,
                error_message="Target file does not exist.",
            )

        # Check if it is a directory passed as a single file
        if os.path.isdir(norm_path):
            return FileIntegrityRecord(
                file_path=norm_path,
                file_name=base_name,
                file_size=0,
                sha256_hash="",
                status=IntegrityStatus.ERROR,
                error_message="Specified path is a directory, not a regular file.",
            )

        # Read file metadata and calculate SHA-256
        try:
            file_size = os.path.getsize(norm_path)
            current_hash = calculate_sha256(norm_path, chunk_size=self.chunk_size)
        except PermissionError:
            return FileIntegrityRecord(
                file_path=norm_path,
                file_name=base_name,
                file_size=0,
                sha256_hash="",
                status=IntegrityStatus.ERROR,
                previous_hash=expected_hash,
                error_message="Access denied: Insufficient read permissions.",
            )
        except OSError as exc:
            return FileIntegrityRecord(
                file_path=norm_path,
                file_name=base_name,
                file_size=0,
                sha256_hash="",
                status=IntegrityStatus.ERROR,
                previous_hash=expected_hash,
                error_message=f"I/O error during file read: {exc}",
            )

        # Compare against baseline
        if expected_hash is None:
            status = IntegrityStatus.NEW
        elif expected_hash.lower() == current_hash.lower():
            status = IntegrityStatus.UNCHANGED
        else:
            status = IntegrityStatus.MODIFIED

        return FileIntegrityRecord(
            file_path=norm_path,
            file_name=base_name,
            file_size=file_size,
            sha256_hash=current_hash,
            status=status,
            previous_hash=expected_hash,
            error_message=None,
        )

    def scan_files(
        self,
        file_paths: list[str | Path],
        baseline: dict[str, str] | None = None,
        check_missing: bool = True,
    ) -> list[FileIntegrityRecord]:
        """Scan a batch of explicit file paths and detect changes and missing files.

        Args:
            file_paths: List of file paths to inspect.
            baseline: Optional baseline dictionary. Defaults to active cache.
            check_missing: Whether to report baseline files missing from the scanned set.

        Returns:
            list[FileIntegrityRecord]: Complete list of records for scanned and missing files.
        """
        active_baseline = baseline if baseline is not None else self._baseline_cache
        results: list[FileIntegrityRecord] = []
        scanned_normalized: set[str] = set()

        for path in file_paths:
            rec = self.scan_file(path, baseline=active_baseline)
            results.append(rec)
            scanned_normalized.add(os.path.normpath(str(path)))

        if check_missing and active_baseline:
            # Check if any baseline entry was missing
            for b_path, b_hash in active_baseline.items():
                norm_b = os.path.normpath(b_path)
                if norm_b not in scanned_normalized and not os.path.exists(norm_b):
                    results.append(
                        FileIntegrityRecord(
                            file_path=norm_b,
                            file_name=os.path.basename(norm_b),
                            file_size=0,
                            sha256_hash="",
                            status=IntegrityStatus.MISSING,
                            previous_hash=b_hash,
                            error_message="Baseline file was not found during audit.",
                        )
                    )

        return results

    def scan_directory(
        self,
        dir_path: str | Path,
        recursive: bool = True,
        baseline: dict[str, str] | None = None,
        follow_symlinks: bool = False,
    ) -> list[FileIntegrityRecord]:
        """Safely traverse and scan all regular files within a selected directory.

        Protections:
        - Never follows symbolic links by default to prevent loops.
        - Gracefully skips inaccessible files and subdirectories.
        - Detects missing baseline files whose paths reside within the scanned directory.

        Args:
            dir_path: Target directory path to inspect.
            recursive: If True, recursively scans nested subfolders.
            baseline: Optional baseline dictionary. Defaults to active cache.
            follow_symlinks: Whether to traverse symbolic links (default False for safety).

        Returns:
            list[FileIntegrityRecord]: Inspection results for all files in the directory.
        """
        norm_dir = os.path.normpath(str(dir_path))
        active_baseline = baseline if baseline is not None else self._baseline_cache

        if not os.path.exists(norm_dir) or not os.path.isdir(norm_dir):
            return [
                FileIntegrityRecord(
                    file_path=norm_dir,
                    file_name=os.path.basename(norm_dir) or norm_dir,
                    file_size=0,
                    sha256_hash="",
                    status=IntegrityStatus.ERROR,
                    error_message="Specified directory does not exist or is not a directory.",
                )
            ]

        discovered_files: list[str] = []

        if recursive:
            for root, dirs, files in os.walk(norm_dir, followlinks=follow_symlinks):
                # Avoid symlinks in directory traversal if follow_symlinks is False
                if not follow_symlinks:
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for f in sorted(files):
                    f_path = os.path.join(root, f)
                    if not follow_symlinks and os.path.islink(f_path):
                        continue
                    discovered_files.append(f_path)
        else:
            try:
                for entry in sorted(os.scandir(norm_dir), key=lambda e: e.name):
                    if entry.is_file(follow_symlinks=follow_symlinks):
                        discovered_files.append(entry.path)
            except PermissionError:
                return [
                    FileIntegrityRecord(
                        file_path=norm_dir,
                        file_name=os.path.basename(norm_dir) or norm_dir,
                        file_size=0,
                        sha256_hash="",
                        status=IntegrityStatus.ERROR,
                        error_message="Permission denied while opening directory.",
                    )
                ]

        results: list[FileIntegrityRecord] = []
        scanned_paths: set[str] = set()

        for file_p in discovered_files:
            rec = self.scan_file(file_p, baseline=active_baseline)
            results.append(rec)
            scanned_paths.add(rec.file_path)

        # Check for missing baseline files scoped to this directory
        for b_path, b_hash in active_baseline.items():
            norm_b = os.path.normpath(b_path)
            if norm_b not in scanned_paths:
                # Check if norm_b was supposed to be within this directory
                try:
                    rel = os.path.relpath(norm_b, norm_dir)
                    is_inside = not rel.startswith("..") and not os.path.isabs(rel)
                except ValueError:
                    is_inside = False

                if is_inside and not os.path.exists(norm_b):
                    results.append(
                        FileIntegrityRecord(
                            file_path=norm_b,
                            file_name=os.path.basename(norm_b),
                            file_size=0,
                            sha256_hash="",
                            status=IntegrityStatus.MISSING,
                            previous_hash=b_hash,
                            error_message="Baseline file in directory has been deleted.",
                        )
                    )

        return results

