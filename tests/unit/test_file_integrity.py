"""Unit tests for File Integrity Monitoring (FIM) Engine."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.file_integrity import (
    FileIntegrityRecord,
    FileIntegrityScanner,
    IntegrityStatus,
    calculate_sha256,
)


@pytest.fixture
def temp_fim_workspace(tmp_path: Path) -> Path:
    """Fixture providing a temporary folder with mock test files."""
    workspace = tmp_path / "fim_test"
    workspace.mkdir()

    # File 1: Simple content
    f1 = workspace / "file1.txt"
    f1.write_text("CyberShield SOC Security Test", encoding="utf-8")

    # File 2: Empty file
    f2 = workspace / "empty.txt"
    f2.write_text("", encoding="utf-8")

    # Subfolder with file 3
    sub = workspace / "subdir"
    sub.mkdir()
    f3 = sub / "nested.log"
    f3.write_text("Log Entry [2026]: System Initialized", encoding="utf-8")

    return workspace


def test_calculate_sha256_known_hashes(tmp_path: Path) -> None:
    """Verify SHA-256 against known standard test vectors."""
    # Empty file standard SHA-256 hash
    empty_file = tmp_path / "empty_test.txt"
    empty_file.write_bytes(b"")
    assert calculate_sha256(empty_file) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Known content "hello world"
    hello_file = tmp_path / "hello.txt"
    hello_file.write_bytes(b"hello world")
    assert calculate_sha256(hello_file) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_calculate_sha256_chunked_reads(tmp_path: Path) -> None:
    """Verify chunked hashing with custom small chunk size on larger data."""
    large_file = tmp_path / "large_file.bin"
    # Write 150 KB of deterministic binary data
    chunk = b"A" * 1024
    with open(large_file, "wb") as f:
        for _ in range(150):
            f.write(chunk)

    # Hash using small 4KB chunks
    hash_chunked = calculate_sha256(large_file, chunk_size=4096)
    # Hash using default 64KB chunks
    hash_default = calculate_sha256(large_file)
    assert hash_chunked == hash_default
    assert len(hash_chunked) == 64


def test_scan_new_file(temp_fim_workspace: Path) -> None:
    """Verify scanning a file without baseline returns NEW status."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"
    rec = scanner.scan_file(f1)

    assert rec.status == IntegrityStatus.NEW
    assert rec.file_name == "file1.txt"
    assert rec.file_size > 0
    assert len(rec.sha256_hash) == 64
    assert rec.previous_hash is None
    assert rec.error_message is None


def test_scan_unchanged_file(temp_fim_workspace: Path) -> None:
    """Verify scanning a file with matching baseline returns UNCHANGED."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"
    initial_hash = calculate_sha256(f1)

    # Establish baseline
    scanner.set_baseline({str(f1): initial_hash})

    rec = scanner.scan_file(f1)
    assert rec.status == IntegrityStatus.UNCHANGED
    assert rec.sha256_hash == initial_hash
    assert rec.previous_hash == initial_hash


def test_scan_modified_file(temp_fim_workspace: Path) -> None:
    """Verify modifying file contents triggers MODIFIED status."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"
    old_hash = calculate_sha256(f1)

    # Set baseline
    scanner.set_baseline({str(f1): old_hash})

    # Tamper with the file
    f1.write_text("TAMPERED CONTENT: Unauthorized Modification!", encoding="utf-8")

    rec = scanner.scan_file(f1)
    assert rec.status == IntegrityStatus.MODIFIED
    assert rec.previous_hash == old_hash
    assert rec.sha256_hash != old_hash


def test_scan_missing_file_in_baseline(temp_fim_workspace: Path) -> None:
    """Verify deleted baseline file returns MISSING status."""
    scanner = FileIntegrityScanner()
    missing_path = temp_fim_workspace / "deleted_file.txt"
    recorded_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

    scanner.set_baseline({str(missing_path): recorded_hash})

    rec = scanner.scan_file(missing_path)
    assert rec.status == IntegrityStatus.MISSING
    assert rec.sha256_hash == ""
    assert rec.previous_hash == recorded_hash


def test_scan_nonexistent_unregistered_file(temp_fim_workspace: Path) -> None:
    """Verify scanning nonexistent path not in baseline returns ERROR."""
    scanner = FileIntegrityScanner()
    random_path = temp_fim_workspace / "ghost.txt"
    rec = scanner.scan_file(random_path)

    assert rec.status == IntegrityStatus.ERROR
    assert "does not exist" in (rec.error_message or "")


def test_scan_directory_as_single_file_returns_error(temp_fim_workspace: Path) -> None:
    """Verify passing a directory path to scan_file returns an ERROR."""
    scanner = FileIntegrityScanner()
    rec = scanner.scan_file(temp_fim_workspace)
    assert rec.status == IntegrityStatus.ERROR
    assert "is a directory" in (rec.error_message or "")


def test_scan_permission_denied(temp_fim_workspace: Path) -> None:
    """Verify PermissionError is captured gracefully without crashing."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"

    with patch("builtins.open", side_effect=PermissionError("Access denied")):
        rec = scanner.scan_file(f1)
        assert rec.status == IntegrityStatus.ERROR
        assert "Access denied" in (rec.error_message or "")


def test_scan_os_error_handling(temp_fim_workspace: Path) -> None:
    """Verify OSError is captured gracefully."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"

    with patch("builtins.open", side_effect=OSError("Drive I/O failure")):
        rec = scanner.scan_file(f1)
        assert rec.status == IntegrityStatus.ERROR
        assert "I/O error" in (rec.error_message or "")


def test_scan_batch_files(temp_fim_workspace: Path) -> None:
    """Verify scanning multiple explicit file paths and detecting missing."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"
    f2 = temp_fim_workspace / "empty.txt"
    missing = temp_fim_workspace / "deleted.txt"

    scanner.set_baseline({
        str(f1): calculate_sha256(f1),
        str(missing): "abc12345",
    })

    results = scanner.scan_files([f1, f2], check_missing=True)
    statuses = {r.file_name: r.status for r in results}

    assert statuses["file1.txt"] == IntegrityStatus.UNCHANGED
    assert statuses["empty.txt"] == IntegrityStatus.NEW
    assert statuses["deleted.txt"] == IntegrityStatus.MISSING


def test_scan_directory_recursive_and_missing(temp_fim_workspace: Path) -> None:
    """Verify directory traversal finds all files and flags missing baseline."""
    scanner = FileIntegrityScanner()
    f1 = temp_fim_workspace / "file1.txt"
    f3 = temp_fim_workspace / "subdir" / "nested.log"
    missing_in_dir = temp_fim_workspace / "subdir" / "removed.conf"

    scanner.set_baseline({
        str(f1): calculate_sha256(f1),
        str(f3): calculate_sha256(f3),
        str(missing_in_dir): "fakehash123",
    })

    records = scanner.scan_directory(temp_fim_workspace, recursive=True)
    names = {r.file_name: r.status for r in records}

    assert names["file1.txt"] == IntegrityStatus.UNCHANGED
    assert names["empty.txt"] == IntegrityStatus.NEW
    assert names["nested.log"] == IntegrityStatus.UNCHANGED
    assert names["removed.conf"] == IntegrityStatus.MISSING


def test_scan_directory_non_recursive(temp_fim_workspace: Path) -> None:
    """Verify non-recursive directory scan ignores nested subfolders."""
    scanner = FileIntegrityScanner()
    records = scanner.scan_directory(temp_fim_workspace, recursive=False)
    names = [r.file_name for r in records]

    assert "file1.txt" in names
    assert "empty.txt" in names
    assert "nested.log" not in names


def test_scan_directory_nonexistent() -> None:
    """Verify scanning a nonexistent folder returns an ERROR record."""
    scanner = FileIntegrityScanner()
    records = scanner.scan_directory("nonexistent_directory_xyz_123")
    assert len(records) == 1
    assert records[0].status == IntegrityStatus.ERROR
    assert "does not exist" in (records[0].error_message or "")


def test_scan_directory_permission_error(temp_fim_workspace: Path) -> None:
    """Verify PermissionError during non-recursive scandir is handled."""
    scanner = FileIntegrityScanner()
    with patch("os.scandir", side_effect=PermissionError("Directory locked")):
        records = scanner.scan_directory(temp_fim_workspace, recursive=False)
        assert len(records) == 1
        assert records[0].status == IntegrityStatus.ERROR
        assert "Permission denied" in (records[0].error_message or "")


def test_baseline_cache_operations(temp_fim_workspace: Path) -> None:
    """Verify cache manipulation: update, clear, properties."""
    scanner = FileIntegrityScanner()
    p1 = str(temp_fim_workspace / "test.txt")
    scanner.update_baseline_entry(p1, "TESTHASH1234")
    assert scanner.baseline_cache[os.path.normpath(p1)] == "testhash1234"

    scanner.clear_baseline()
    assert len(scanner.baseline_cache) == 0


def test_baseline_repository_operations(temp_fim_workspace: Path) -> None:
    """Verify loading from and saving to a mock baseline repository."""
    mock_repo = MagicMock()
    mock_repo.list_all.return_value = [
        {"file_name": str(temp_fim_workspace / "a.txt"), "file_hash": "hash_a"},
        {"file_name": "", "file_hash": "ignored"},
    ]

    scanner = FileIntegrityScanner(baseline_repo=mock_repo)
    assert os.path.normpath(str(temp_fim_workspace / "a.txt")) in scanner.baseline_cache

    # Test saving baseline records
    rec1 = FileIntegrityRecord(
        file_path=str(temp_fim_workspace / "b.txt"),
        file_name="b.txt",
        file_size=10,
        sha256_hash="hash_b",
        status=IntegrityStatus.NEW,
    )
    rec2_error = FileIntegrityRecord(
        file_path=str(temp_fim_workspace / "c.txt"),
        file_name="c.txt",
        file_size=0,
        sha256_hash="",
        status=IntegrityStatus.ERROR,
        error_message="Fail",
    )

    saved = scanner.save_baseline_to_repository([rec1, rec2_error])
    assert saved == 1
    mock_repo.create.assert_called_once_with(
        file_name=os.path.normpath(str(temp_fim_workspace / "b.txt")),
        file_hash="hash_b",
    )


def test_save_and_load_with_no_repository() -> None:
    """Verify calling repository methods when baseline_repo is None is safe."""
    scanner = FileIntegrityScanner(baseline_repo=None)
    assert scanner.load_baseline_from_repository() == {}
    assert scanner.save_baseline_to_repository([]) == 0


def test_file_integrity_record_serialization() -> None:
    """Verify to_dict serialization of FileIntegrityRecord."""
    rec = FileIntegrityRecord(
        file_path="C:/test/file.txt",
        file_name="file.txt",
        file_size=128,
        sha256_hash="abcdef123456",
        status=IntegrityStatus.MODIFIED,
        previous_hash="oldhash",
        error_message=None,
    )
    d = rec.to_dict()
    assert d["file_name"] == "file.txt"
    assert d["status"] == "MODIFIED"
    assert d["file_size"] == 128
    assert d["previous_hash"] == "oldhash"


def test_scan_directory_symlink_ignored(tmp_path: Path) -> None:
    """Verify symlinks are skipped when follow_symlinks is False."""
    scanner = FileIntegrityScanner()
    target_dir = tmp_path / "sym_dir"
    target_dir.mkdir()
    real_file = target_dir / "real.txt"
    real_file.write_text("Real data", encoding="utf-8")

    with patch("os.path.islink", side_effect=lambda p: "real.txt" in str(p)):
        records = scanner.scan_directory(target_dir, recursive=True, follow_symlinks=False)
        assert len(records) == 0  # skipped because islink was True



def test_scan_directory_missing_file_relpath_value_error(temp_fim_workspace: Path) -> None:
    """Verify handling of ValueError in relpath when baseline file is on a different root/drive."""
    scanner = FileIntegrityScanner()
    scanner.set_baseline({"Z:\\different_drive\\file.txt": "somehash123"})

    with patch("os.path.relpath", side_effect=ValueError("Different drive")):
        records = scanner.scan_directory(temp_fim_workspace, recursive=True)
        # Should complete without crashing
        assert len(records) > 0

