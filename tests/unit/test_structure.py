"""Unit tests for verifying project folder structure and file layout."""

from pathlib import Path


def test_required_directories_exist() -> None:
    """Verify that all mandatory Phase 0 project directories exist."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    expected_dirs = [
        "config",
        "frontend",
        "backend",
        "backend/routes",
        "backend/schemas",
        "backend/services",
        "database",
        "database/migrations",
        "database/repositories",
        "models",
        "controllers",
        "security",
        "tests",
        "tests/unit",
        "tests/integration",
        "tests/e2e",
        "assets",
        "reports",
        "docs",
    ]

    for rel_path in expected_dirs:
        target_dir = base_dir / rel_path
        assert target_dir.is_dir(), f"Expected directory does not exist: {rel_path}"


def test_required_package_init_files_exist() -> None:
    """Verify that all Python packages have __init__.py files."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    packages = [
        "config",
        "frontend",
        "backend",
        "backend/routes",
        "backend/schemas",
        "backend/services",
        "database",
        "database/migrations",
        "database/repositories",
        "models",
        "controllers",
        "security",
        "tests",
        "tests/unit",
        "tests/integration",
        "tests/e2e",
    ]

    for pkg in packages:
        init_file = base_dir / pkg / "__init__.py"
        assert init_file.is_file(), f"Missing __init__.py in package: {pkg}"


def test_required_root_files_exist() -> None:
    """Verify that all essential project configuration and root files exist."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    expected_files = [
        "main.py",
        "requirements.txt",
        "requirements-dev.txt",
        ".gitignore",
        "README.md",
        ".env.example",
        "pytest.ini",
        ".coveragerc",
        "docs/DEVELOPMENT_ROADMAP.md",
    ]

    for rel_file in expected_files:
        target_file = base_dir / rel_file
        assert target_file.is_file(), f"Expected project file does not exist: {rel_file}"

