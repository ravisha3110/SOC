"""CyberShield Database Repositories.

Provides simple, clean data access objects (DAOs) for users, scan history,
threats, file integrity records, URL analyses, and network logs.
"""

from database.repositories.file_integrity_repository import FileIntegrityRepository
from database.repositories.network_log_repository import NetworkLogRepository
from database.repositories.scan_repository import ScanRepository
from database.repositories.threat_repository import ThreatRepository
from database.repositories.url_analysis_repository import URLAnalysisRepository
from database.repositories.user_repository import UserRepository

__all__ = [
    "UserRepository",
    "ScanRepository",
    "ThreatRepository",
    "FileIntegrityRepository",
    "URLAnalysisRepository",
    "NetworkLogRepository",
]

