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

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


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


def load_principals(path: Path | None = None) -> dict:
    """Nguồn tin cậy MÔ PHỎNG: chỉ đọc data/principals.json, không xác thực ai."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    # Thời điểm không kèm múi giờ thì không biết có phải UTC không -> coi là sai.
    return parsed if parsed.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    ctx = context
    tool = ctx.requested_tool or "(chưa khai báo tool)"

    # 1. Phân loại dữ liệu phải thuộc tập đã biết.
    if ctx.data_classification not in CLASSIFICATIONS:
        return False, (f"deny: data_classification {ctx.data_classification!r} không thuộc "
                       f"{'/'.join(CLASSIFICATIONS)}")

    # 2. Rule tối thiểu, đặt trước mọi kiểm OBO: không principal nào (kể cả dpo) vượt được.
    if ctx.data_classification == "restricted" and ctx.egress_enabled:
        return False, (f"deny: dữ liệu restricted không được đi ra ngoài (egress_enabled=True) "
                       f"khi gọi {tool}, bất kể principal {ctx.principal_id or '(trống)'}")

    # 3. OBO: người ra lệnh phải có trong nguồn tin cậy mô phỏng.
    principal = load_principals().get(ctx.principal_id) if ctx.principal_id else None
    if principal is None:
        return False, f"deny: principal {ctx.principal_id or '(trống)'!r} không có trong data/principals.json"
    if not ctx.requested_tool:
        return False, f"deny: {ctx.principal_id} gọi tool nhưng không khai báo requested_tool"

    # Quyền hiệu lực = allowed_tools ∩ agent_scopes (∩ parent_scopes khi là agent con).
    if ctx.requested_tool not in principal.get("allowed_tools", []):
        return False, f"deny: principal {ctx.principal_id} không có quyền dùng {tool} (allowed_tools)"
    if ctx.requested_tool not in ctx.agent_scopes:
        return False, f"deny: agent {ctx.agent_owner} không có scope {tool} (agent_scopes={list(ctx.agent_scopes)})"
    if ctx.delegation_depth < 0:
        return False, f"deny: delegation_depth={ctx.delegation_depth} không hợp lệ"
    if ctx.delegation_depth > 0 and ctx.requested_tool not in ctx.parent_scopes:
        return False, (f"deny: agent con (depth={ctx.delegation_depth}) xin {tool} vượt quyền agent cha "
                       f"(parent_scopes={list(ctx.parent_scopes)})")

    # Mục đích phải nằm trong các mục đích principal được phép.
    if ctx.request_purpose not in principal.get("purposes", []):
        return False, (f"deny: mục đích {ctx.request_purpose!r} không được phép cho {ctx.principal_id} "
                       f"(purposes={principal.get('purposes', [])})")

    # TTL: expires_at là ISO-8601 UTC và phải còn hạn.
    expires = _parse_utc(ctx.expires_at)
    if expires is None:
        return False, f"deny: expires_at {ctx.expires_at!r} thiếu hoặc không phải ISO-8601 có múi giờ"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny: phiên ủy quyền đã hết hạn lúc {ctx.expires_at}"

    return True, (f"allow: {ctx.principal_id} được dùng {tool} cho mục đích {ctx.request_purpose}, "
                  f"dữ liệu {ctx.data_classification}, egress={ctx.egress_enabled}, "
                  f"depth={ctx.delegation_depth}, hết hạn {ctx.expires_at}")
