# Báo cáo Verification — Kiểm tra hoàn thiện trước khi nộp bài

- **OS / Python / Gitleaks version:**
  - OS: macOS (Darwin 24.3.0 arm64)
  - Python: Python 3.12.10
  - Gitleaks: v8.30.1 (Homebrew bottle)

- **`python -m pytest tests/ -q`:**
  - Kết quả: `33 passed in 0.16s` (100% test pass).
  - Bao gồm:
    - `tests/test_check_lure_cli.py` (3/3 passed)
    - `tests/test_injection.py` (8/8 passed)
    - `tests/test_ledger.py` (3/3 passed)
    - `tests/test_obo.py` (5/5 passed)
    - `tests/test_pii.py` (2/2 passed, precision=1.0, recall=1.0)
    - `tests/test_policy.py` (4/4 passed)
    - `tests/test_scaffold_dispatch.py` (4/4 passed)
    - `tests/test_split.py` (1/1 passed)
    - `tests/test_supply_chain.py` (3/3 passed)

- **`pre-commit run --all-files`:**
  - Kết quả: `Detect hardcoded secrets.................................................Passed`

- **Ledger verify:**
  - Lệnh kiểm tra: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi băm SHA-256 hash chain hợp lệ, phát hiện mọi sửa đổi).

- **Kiểm tra Before / After Attack Log:**
  - `reports/attack-before.log`: Chứa bản ghi PII synthetic của `KH-000999` do baseline agent bị khai thác prompt injection gửi ra sink.
  - `reports/attack-after.log`: Dung lượng 0 bytes (hoàn toàn rỗng), chứng minh dữ liệu bị chặn hoàn toàn sau containment.
  - `reports/ledger.jsonl`: Chứa bản ghi deny `http_post` với reason rõ ràng (`DENY: restricted data with egress enabled — exfiltration risk`) và `on_behalf_of: "dpo"`.

- **Các lỗi còn lại:**
  - Không có lỗi nào còn tồn đọng. Toàn bộ các yêu cầu của Checkpoint 1 đến 5 và các điều kiện trong Rubric đều được đáp ứng đầy đủ.
