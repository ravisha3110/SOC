"""CyberShield Pydantic Schemas Package."""

from backend.schemas.auth import (
    LoginResponse,
    UpdateRoleRequest,
    UpdateStatusRequest,
    UserListResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from backend.schemas.file import (
    FileIntegrityCreate,
    FileIntegrityResponse,
    FileListResponse,
)
from backend.schemas.network import (
    NetworkListResponse,
    NetworkLogCreate,
    NetworkLogResponse,
)
from backend.schemas.scan import (
    ScanCreate,
    ScanListResponse,
    ScanResponse,
)
from backend.schemas.sync import (
    SyncConflictResponse,
    SyncReportResponse,
    SyncStatusResponse,
    SyncTriggerRequest,
)
from backend.schemas.threat import (
    ThreatCreate,
    ThreatListResponse,
    ThreatResponse,
)
from backend.schemas.url import (
    URLAnalysisCreate,
    URLAnalysisResponse,
    URLListResponse,
)

__all__ = [
    # Auth
    "UserRegisterRequest",
    "UserLoginRequest",
    "UserResponse",
    "LoginResponse",
    "UpdateRoleRequest",
    "UpdateStatusRequest",
    "UserListResponse",
    # Sync
    "SyncTriggerRequest",
    "SyncStatusResponse",
    "SyncConflictResponse",
    "SyncReportResponse",
    # Scans
    "ScanCreate",
    "ScanResponse",
    "ScanListResponse",
    # Threats
    "ThreatCreate",
    "ThreatResponse",
    "ThreatListResponse",
    # Files
    "FileIntegrityCreate",
    "FileIntegrityResponse",
    "FileListResponse",
    # URLs
    "URLAnalysisCreate",
    "URLAnalysisResponse",
    "URLListResponse",
    # Network
    "NetworkLogCreate",
    "NetworkLogResponse",
    "NetworkListResponse",
]

