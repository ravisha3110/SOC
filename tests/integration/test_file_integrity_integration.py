"""Integration tests for File Integrity Monitoring with SQLite repository."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from database.repositories.file_integrity_repository import FileIntegrityRepository
from database.sqlite_manager import SQLiteManager
from security.file_integrity import (
    FileIntegrityRecord,
    FileIntegrityScanner,
    IntegrityStatus,
    calculate_sha256,
)


@pytest.fixture
def sqlite_db(tmp_path: Path) -> SQLiteManager:
    """Fixture providing initialized SQLite database."""
    db_path = tmp_path / "test_fim.db"
    manager = SQLiteManager(db_path=db_path)
    manager.initialize_database()
    yield manager
    manager.close()


def test_file_integrity_sqlite_repository_lifecycle(sqlite_db: SQLiteManager, tmp_path: Path) -> None:
    """Verify complete end-to-end integration between FileIntegrityScanner and SQLite repository."""
    repo = FileIntegrityRepository(sqlite_db)
    scanner = FileIntegrityScanner(baseline_repo=repo)

    # Create target test files
    f1 = tmp_path / "secure_app.py"
    f1.write_text("print('Production Release v1.0')", encoding="utf-8")

    f2 = tmp_path / "settings.yaml"
    f2.write_text("env: production\ndebug: false\n", encoding="utf-8")

    # Step 1: Initial scan before baseline
    initial_records = scanner.scan_files([f1, f2])
    assert len(initial_records) == 2
    assert all(r.status == IntegrityStatus.NEW for r in initial_records)

    # Step 2: Persist baseline to SQLite repository
    saved_count = scanner.save_baseline_to_repository(initial_records)
    assert saved_count == 2

    # Verify SQLite records exist
    db_records = repo.list_all()
    assert len(db_records) == 2

    # Step 3: Re-initialize a fresh scanner connected to the same DB
    fresh_scanner = FileIntegrityScanner(baseline_repo=repo)
    assert len(fresh_scanner.baseline_cache) == 2

    # Step 4: Scan again - should be UNCHANGED
    verified_records = fresh_scanner.scan_files([f1, f2])
    assert all(r.status == IntegrityStatus.UNCHANGED for r in verified_records)

    # Step 5: Tamper with f1
    f1.write_text("print('BACKDOOR INJECTED!')", encoding="utf-8")
    tampered_records = fresh_scanner.scan_files([f1, f2])
    statuses = {r.file_name: r.status for r in tampered_records}
    assert statuses["secure_app.py"] == IntegrityStatus.MODIFIED
    assert statuses["settings.yaml"] == IntegrityStatus.UNCHANGED

    # Step 6: Delete f2
    os.remove(f2)
    missing_records = fresh_scanner.scan_files([f1], check_missing=True)
    m_statuses = {r.file_name: r.status for r in missing_records}
    assert m_statuses["settings.yaml"] == IntegrityStatus.MISSING

