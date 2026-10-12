"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=15)

# Agent cha (orchestrator) giữ quyền tối đa; mỗi run con chỉ được một chân của
# trifecta và luôn chạy ở delegation_depth=1, nên không thể vượt parent_scopes.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer", "http_post")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)

# Chỉ tên file đúng dạng ticket-007.md mới ra được ticket id (7);
# "ticket-904b.md" hay mọi thứ trong nội dung file đều không qua được.
_TICKET_FILE_RE = re.compile(r"ticket-(\d+)\.md")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_args(args: dict) -> str:
    """Ledger chỉ giữ hash của tham số, không giữ nguyên văn hồ sơ hay PII."""
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _Session:
    """Một yêu cầu của người dùng: làm thay ai, run nào, hết hạn khi nào."""

    def __init__(self, principal_id: str, ledger_path: Path):
        self.principal_id = principal_id
        self.request_id = uuid.uuid4().hex[:12]
        self.expires_at = (_utc_now() + RUN_TTL).isoformat(timespec="seconds")
        self.ledger_path = ledger_path

    def gate(self, run: str, tool: str, args: dict, *, classification: str,
             purpose: str, scopes: tuple[str, ...], egress: bool = False) -> tuple[bool, str]:
        """PEP: hỏi policy rồi ghi ledger (cả allow lẫn deny) TRƯỚC khi tool chạy."""
        context = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=f"{AGENT_ID}/{run}",
            delegation_depth=1,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=scopes,
            parent_scopes=ORCHESTRATOR_SCOPES,
            expires_at=self.expires_at,
        )
        allow, reason = check(context)
        ledger.append({
            "ts": _utc_now().isoformat(timespec="seconds"),
            "agent_id": AGENT_ID,
            "run_id": f"{self.request_id}-{run}",
            "on_behalf_of": self.principal_id,
            "tool": tool,
            "args_hash": _hash_args(args),
            "classification": classification,
            "purpose": purpose,
            "delegation_depth": context.delegation_depth,
            "egress_enabled": egress,
            "expires_at": self.expires_at,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allow, reason


def _run_a(session: _Session, message: str, llm):
    """Run A: chỉ cầm search_docs. Trả ticket id (từ tên file), doc đã che PII
    để tóm tắt, và chỉ thị injection nếu có (chỉ dùng để quyết định lượt kiểm
    egress — customer_id trong đó KHÔNG được dùng)."""
    allow, reason = session.gate("run-a", "search_docs", {"query": message},
                                 classification="internal", purpose="summarize-tickets",
                                 scopes=RUN_A_SCOPES)
    if not allow:
        return None, reason
    docs = tools.search_docs(message)
    ticket_ids = sorted({int(m.group(1)) for d in docs
                         if (m := _TICKET_FILE_RE.fullmatch(d["id"]))})
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return (ticket_ids, safe_docs, injected), reason


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy duy nhất cho ticket -> customer: related_tickets."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]


def _run_b(session: _Session, ticket_ids: list[int]) -> list[str]:
    """Run B: chỉ nhận list[int] ticket id, không bao giờ nhận text của ticket."""
    if not ticket_ids:
        return []
    restricted = dict(classification="restricted", purpose="support-reply", scopes=RUN_B_SCOPES)
    # Cổng mở private store: deny thì không tra cả bảng mapping.
    allow, _ = session.gate("run-b", "read_customer", {"ticket_ids": ticket_ids}, **restricted)
    if not allow:
        return []
    read = []
    for customer_id in _customers_for_tickets(ticket_ids):
        # Kiểm lại ngay trước từng lần đọc, không đọc rồi mới lọc.
        allow, _ = session.gate("run-b", "read_customer", {"customer_id": customer_id}, **restricted)
        if not allow:
            continue
        try:
            tools.read_customer(customer_id)
        except tools.ToolError:
            continue
        read.append(customer_id)
    return read


def _egress_check(session: _Session, target_url: str, ticket_ids: list[int]) -> None:
    """Lượt kiểm http_post riêng khi lure đòi gửi dữ liệu: chỉ mang URL, không
    mang hồ sơ. Restricted + egress luôn bị policy deny."""
    allow, _ = session.gate("egress", "http_post", {"url": target_url},
                            classification="restricted", purpose="support-reply",
                            scopes=EGRESS_SCOPES, egress=True)
    if allow:
        tools.http_post(target_url, {"ticket_ids": ticket_ids})


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    session = _Session(principal_id, ledger_path)

    result, reason = _run_a(session, message, llm)
    if result is None:
        return f"Yêu cầu bị từ chối: {reason}"
    ticket_ids, safe_docs, injected = result

    _run_b(session, ticket_ids)
    if injected is not None:
        _egress_check(session, injected.target_url, ticket_ids)
    return llm.summarize(safe_docs)
