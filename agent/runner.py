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
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check as policy_check
from agent.pii import redact

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

AGENT_ID = "lab24-agent"
# TTL mặc định 1 giờ cho mỗi run
DEFAULT_TTL_HOURS = 1

_TICKET_NUM_RE = re.compile(r"ticket-(\d+)(?:b)?\.md")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=DEFAULT_TTL_HOURS)).isoformat()


def _args_hash(*args) -> str:
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _load_customers() -> list[dict]:
    return json.loads((DATA_DIR / "customers.json").read_text(encoding="utf-8"))


def _ticket_ids_to_customer_ids(ticket_ids: list[int]) -> list[str]:
    """Map ticket_id -> customer_id qua related_tickets (nguồn tin cậy)."""
    customers = _load_customers()
    result = []
    seen = set()
    for customer in customers:
        for tid in customer.get("related_tickets", []):
            if tid in ticket_ids and customer["customer_id"] not in seen:
                result.append(customer["customer_id"])
                seen.add(customer["customer_id"])
    return result


def _do_policy_and_log(
    tool_name: str,
    args_for_hash,
    classification: str,
    purpose: str,
    run_label: str,
    run_id: str,
    principal_id: str,
    agent_scopes: tuple[str, ...],
    parent_scopes: tuple[str, ...],
    expires_at: str,
    egress_enabled: bool,
    ledger_path: Path,
) -> tuple[bool, str]:
    """Chạy policy check và ghi ledger. Trả về (allow, reason)."""
    ctx = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{AGENT_ID}/{run_label}",
        delegation_depth=0,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )
    allow, reason = policy_check(ctx)
    decision = "allow" if allow else "deny"

    entry = {
        "ts": _now_iso(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(args_for_hash),
        "classification": classification,
        "decision": decision,
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }
    ledger.append(entry, ledger_path)
    return allow, reason


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Trifecta split: Run A (untrusted) -> ticket_ids -> Run B (private)."""
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    expires_at = _expires_iso()

    # Agent scopes: Run A chỉ có search_docs, Run B có read_customer
    run_a_scopes = ("search_docs",)
    run_b_scopes = ("search_docs", "read_customer", "http_post")

    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"

    # ========== RUN A: search_docs (untrusted content) ==========
    allow, reason = _do_policy_and_log(
        tool_name="search_docs",
        args_for_hash=message,
        classification="internal",  # corpus là internal
        purpose="summarize-tickets",
        run_label="run-a",
        run_id=run_a_id,
        principal_id=principal_id,
        agent_scopes=run_a_scopes,
        parent_scopes=(),
        expires_at=expires_at,
        egress_enabled=False,  # Run A không có egress
        ledger_path=ledger_path,
    )

    if not allow:
        return f"Run A search_docs denied: {reason}"

    docs = tools.search_docs(message)

    # Trích ticket_id từ TÊN FILE (không phải nội dung)
    ticket_ids: list[int] = []
    for doc in docs:
        m = _TICKET_NUM_RE.search(doc["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # Chạy find_injection để LOG (không dùng customer_id từ đây)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    # Log injection detection nhưng KHÔNG dùng injected.customer_ids

    # Nếu có injection -> log http_post deny (restricted + egress)
    if injected is not None:
        _do_policy_and_log(
            tool_name="http_post",
            args_for_hash=injected.target_url,
            classification="restricted",
            purpose="reconciliation",
            run_label="run-b",
            run_id=run_b_id,
            principal_id=principal_id,
            agent_scopes=run_b_scopes,
            parent_scopes=(),
            expires_at=expires_at,
            egress_enabled=True,
            ledger_path=ledger_path,
        )

    # ========== RUN B: read_customer (private data) ==========
    # Map ticket_ids -> customer_ids qua related_tickets (nguồn tin cậy)
    customer_ids = _ticket_ids_to_customer_ids(ticket_ids)

    collected = []
    for cid in customer_ids:
        allow, reason = _do_policy_and_log(
            tool_name="read_customer",
            args_for_hash=cid,
            classification="restricted",
            purpose="support-reply",
            run_label="run-b",
            run_id=run_b_id,
            principal_id=principal_id,
            agent_scopes=run_b_scopes,
            parent_scopes=(),
            expires_at=expires_at,
            egress_enabled=False,  # Run B read không có egress
            ledger_path=ledger_path,
        )
        if allow:
            try:
                record = tools.read_customer(cid)
                collected.append(record)
            except tools.ToolError:
                continue

    # Summarize — redact PII trước khi trả về
    summary = llm.summarize(docs)
    return redact(summary)
