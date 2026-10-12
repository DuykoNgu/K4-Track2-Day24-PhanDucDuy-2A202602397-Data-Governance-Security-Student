"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"
_principals_cache: dict | None = None


def _load_principals() -> dict:
    global _principals_cache
    if _principals_cache is None:
        _principals_cache = json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    return _principals_cache


def check(context: PolicyContext) -> tuple[bool, str]:
    """PEP: kiểm tra mọi tool call trước khi execute. Luôn trả (allow, reason)."""

    # Rule tối thiểu bắt buộc: restricted + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: restricted data with egress enabled — exfiltration risk"

    # Kiểm tra expires_at — nếu đã hết hạn thì deny
    if context.expires_at:
        try:
            expires = datetime.fromisoformat(context.expires_at)
            now = datetime.now(timezone.utc)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                return False, f"DENY: run expired at {context.expires_at}"
        except (ValueError, TypeError):
            return False, f"DENY: invalid expires_at format: {context.expires_at}"

    # OBO: kiểm tra principal
    if context.principal_id:
        principals = _load_principals()
        principal = principals.get(context.principal_id)

        if principal is None:
            return False, f"DENY: unknown principal '{context.principal_id}'"

        # Tính quyền hiệu lực
        allowed_tools = set(principal.get("allowed_tools", []))

        if context.agent_scopes:
            effective = allowed_tools & set(context.agent_scopes)
        else:
            effective = allowed_tools

        # Nếu delegation_depth > 0, giao thêm với parent_scopes
        if context.delegation_depth > 0:
            if context.parent_scopes:
                effective = effective & set(context.parent_scopes)
            else:
                # Không có parent_scopes khi delegation > 0 => không có quyền nào
                return False, (
                    f"DENY: delegation_depth={context.delegation_depth} "
                    f"but no parent_scopes provided"
                )

        # Kiểm tra tool có trong quyền hiệu lực không
        if context.requested_tool and context.requested_tool not in effective:
            return False, (
                f"DENY: principal '{context.principal_id}' does not have "
                f"effective scope for tool '{context.requested_tool}' "
                f"(effective={sorted(effective)})"
            )

        # Kiểm tra purpose
        allowed_purposes = principal.get("purposes", [])
        if context.request_purpose and allowed_purposes:
            if context.request_purpose not in allowed_purposes:
                return False, (
                    f"DENY: purpose '{context.request_purpose}' not allowed "
                    f"for principal '{context.principal_id}' "
                    f"(allowed={allowed_purposes})"
                )

    return True, (
        f"ALLOW: {context.requested_tool or 'tool'} for "
        f"principal='{context.principal_id}', "
        f"classification={context.data_classification}, "
        f"purpose={context.request_purpose}"
    )
