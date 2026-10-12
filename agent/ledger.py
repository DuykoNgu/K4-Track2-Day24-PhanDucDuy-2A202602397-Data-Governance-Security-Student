"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ZERO_HASH = "0" * 64


def _compute_hash(entry_without_hash: dict) -> str:
    """SHA-256 của JSON đã sort_keys, không bao gồm field 'hash'."""
    payload = {k: v for k, v in entry_without_hash.items() if k != "hash"}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_last_hash(path: Path) -> str:
    """Đọc hash của dòng cuối cùng trong file, hoặc ZERO_HASH nếu file rỗng/chưa tồn tại."""
    if not path.exists():
        return ZERO_HASH
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return ZERO_HASH
    last_line = content.splitlines()[-1]
    return json.loads(last_line).get("hash", ZERO_HASH)


def append(entry: dict, path: Path) -> dict:
    """Append một entry vào ledger JSONL với hash chain."""
    path.parent.mkdir(parents=True, exist_ok=True)

    entry = dict(entry)  # shallow copy
    entry["prev_hash"] = _get_last_hash(path)
    entry["hash"] = _compute_hash(entry)

    line = json.dumps(entry, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    return entry


def verify(path: Path) -> bool:
    """Kiểm tra toàn bộ hash chain trong file ledger."""
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True

    lines = content.splitlines()
    expected_prev = ZERO_HASH

    for line in lines:
        entry = json.loads(line)

        # Kiểm tra reason non-empty
        if not entry.get("reason"):
            return False

        # Kiểm tra prev_hash liên kết đúng
        if entry.get("prev_hash") != expected_prev:
            return False

        # Tính lại hash và so sánh
        stored_hash = entry.get("hash")
        recomputed = _compute_hash(entry)
        if stored_hash != recomputed:
            return False

        expected_prev = stored_hash

    return True
