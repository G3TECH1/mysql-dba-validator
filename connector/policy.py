from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

TARGET_MODE_COMPANY = "COMPANY"
TARGET_MODE_LOCAL = "LOCAL"

_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_IPV4_LITERAL_RE = re.compile(r"^\d+(?:\.\d+){3}$")
# One ASCII label: letters, digits, '_' (kept for existing internal names) and inner '-'.
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
MAX_HOSTNAME_LENGTH = 253
MAX_DISPLAY_NAME_LENGTH = 64
# Control, format (including bidirectional overrides), surrogate, private-use,
# unassigned and line/paragraph separator characters are never accepted in a name.
_UNSAFE_NAME_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

# Per-target TLS trust (stored in CompanyTarget.tls_policy). None means "configured".
TLS_POLICY_CONFIGURED = "configured"
TLS_POLICY_SYSTEM = "system"
_TLS_POLICY_BUNDLE_RE = re.compile(r"^bundle:([0-9a-f]{64})$")


def parse_tls_policy(value: Any) -> tuple[str, str | None]:
    """Return (kind, bundle_sha256). Anything unrecognised raises: never a fallback."""
    if value is None or value == TLS_POLICY_CONFIGURED:
        return TLS_POLICY_CONFIGURED, None
    if value == TLS_POLICY_SYSTEM:
        return TLS_POLICY_SYSTEM, None
    match = _TLS_POLICY_BUNDLE_RE.fullmatch(value) if isinstance(value, str) else None
    if match:
        return "bundle", match.group(1)
    raise ValueError("unknown_tls_policy")


def validate_display_name(value: Any) -> str:
    """A display name the page may submit: 1-64 characters, nothing that can change
    how a terminal renders text."""
    if not isinstance(value, str):
        raise ValueError("invalid_company_target_name")
    name = value.strip()
    if (not name or len(name) > MAX_DISPLAY_NAME_LENGTH
            or any(unicodedata.category(ch) in _UNSAFE_NAME_CATEGORIES for ch in name)):
        raise ValueError("invalid_company_target_name")
    return name


def console_text(value: Any) -> str:
    """Printable ASCII as is; every other character (newlines, escape sequences,
    non-ASCII) as a visible backslash escape, so text cannot alter a terminal display."""
    out = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            out.append(ch.encode("unicode_escape").decode("ascii"))
    return "".join(out)


@dataclass
class CompanyTarget:
    target_id: str
    display_name: str
    mode: str = TARGET_MODE_COMPANY
    host: str = ""
    port: int = 3306
    tls_required: bool = False
    tls_policy: str | None = None
    allowed_database_policy: str | None = None
    approval_state: str = "approved"
    approved_at: float | None = None
    dns_identity_snapshot: dict[str, Any] | None = None
    dns_snapshot_created_at: float | None = None
    tls_hostname: str | None = None
    created_at: float | None = None
    updated_at: float | None = None


@dataclass
class CompanyTargetRegistry:
    targets: dict[str, CompanyTarget] = field(default_factory=dict)

    def register(self, target: CompanyTarget) -> CompanyTarget:
        validated = validate_company_target(target)
        if validated.approval_state == "approved" and validated.dns_identity_snapshot is None:
            validated.approval_state = "needs_reapproval"
        if validated.target_id in self.targets:
            raise ValueError("duplicate_company_target_id")
        self.targets[validated.target_id] = validated
        return validated

    def get(self, target_id: str) -> CompanyTarget | None:
        return self.targets.get(target_id)

    def is_approved(self, target_id: str) -> bool:
        target = self.targets.get(target_id)
        return bool(
            target
            and target.approval_state == "approved"
            and target.dns_identity_snapshot is not None
        )

    def list_approved(self) -> list[dict[str, Any]]:
        approved = []
        for target in self.targets.values():
            if target.approval_state == "approved":
                approved.append({
                    "target_id": target.target_id,
                    "display_name": target.display_name,
                    "mode": target.mode,
                    "host": target.host,
                    "port": target.port,
                    "tls_required": target.tls_required,
                })
        return approved


def validate_company_target(target: CompanyTarget | dict[str, Any]) -> CompanyTarget:
    if isinstance(target, dict):
        target = CompanyTarget(**target)

    if not isinstance(target, CompanyTarget):
        raise ValueError("invalid_company_target")

    target_id = (target.target_id or "").strip()
    if not target_id or not _TARGET_ID_RE.fullmatch(target_id):
        raise ValueError("invalid_company_target_id")

    display_name = (target.display_name or "").strip()
    if not display_name:
        raise ValueError("invalid_company_target_name")

    if target.mode != TARGET_MODE_COMPANY:
        raise ValueError("invalid_company_target_mode")

    host = (target.host or "").strip()
    if not host:
        raise ValueError("invalid_company_target_host")

    normalized = host.lower()
    if normalized in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}:
        raise ValueError("local_target_not_allowed_in_company_mode")
    if _IPV4_LITERAL_RE.fullmatch(host):
        raise ValueError("invalid_company_target_host")
    if "/" in host or " " in host or ":" in host:
        # This stage does not permit raw IP literals or other network-qualified values.
        # Hostnames are the policy object syntax we accept for explicit company targets.
        raise ValueError("invalid_company_target_host")
    # ASCII only: a non-ASCII name can look identical to another host on screen
    # (IDNs are entered in their xn-- form). No trailing dot, no empty labels.
    if not host.isascii() or len(host) > MAX_HOSTNAME_LENGTH:
        raise ValueError("invalid_company_target_host")
    labels = host.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("invalid_company_target_host")
    # The last label must start with a letter: this refuses numeric forms such as
    # "10.1" or "2130706433" that resolvers read as IP addresses.
    if not labels[-1][0].isalpha():
        raise ValueError("invalid_company_target_host")

    if not isinstance(target.port, int) or not (1 <= target.port <= 65535):
        raise ValueError("invalid_company_target_port")

    if target.approval_state not in {"approved", "pending", "revoked", "needs_reapproval"}:
        raise ValueError("invalid_company_target_approval_state")

    if target.tls_required not in {True, False}:
        raise ValueError("invalid_company_target_tls_policy")

    return CompanyTarget(
        target_id=target_id,
        display_name=display_name,
        mode=target.mode,
        host=host,
        port=target.port,
        tls_required=bool(target.tls_required),
        tls_policy=target.tls_policy,
        allowed_database_policy=target.allowed_database_policy,
        approval_state=target.approval_state,
        approved_at=target.approved_at,
        dns_identity_snapshot=target.dns_identity_snapshot,
        dns_snapshot_created_at=target.dns_snapshot_created_at,
        tls_hostname=target.tls_hostname,
        created_at=target.created_at,
        updated_at=target.updated_at,
    )
