# Baseline — Checkpoint 1

1. **Agent có identity riêng mỗi run chưa?** Chưa. Hàm `_naive_loop()` trong `agent/loop.py` (dòng 27–54) không tạo bất kỳ agent_id, run_id hay principal nào. Mỗi lần gọi đều chạy ẩn danh — không phân biệt ai đang ra lệnh, không ghi lại ai đã làm gì.

2. **Ai cho phép `http_post`?** Không ai — không có bước kiểm tra quyền nào. Trong `_naive_loop()` (dòng 44), `tools.http_post()` được gọi trực tiếp khi `llm.find_injection()` trả về chỉ thị và thu thập được dữ liệu khách. Hàm `http_post` trong `agent/tools.py` (dòng 68–85) chỉ kiểm tra allowlist host cứng (127.0.0.1:10024) — đây là safety net của lab, không phải policy enforcement. Không có `policy.check()` nào được gọi trước khi POST.

3. **Bằng chứng gửi sai PII ra sink ở đâu?** Trong `sink/sink.py` (dòng 42–48), mọi POST được ghi vào `reports/sink.log` dưới dạng JSON `{"path": ..., "body": ...}`. Tuy nhiên, trong `_naive_loop()` không có audit ledger nào — không `agent/ledger.py`, không timestamp, không reason, không hash chain. Nếu PII bị gửi ra sink, bằng chứng duy nhất là file `reports/sink.log`, nhưng log này không ghi ai gửi, lý do gì, và không có cơ chế chống sửa đổi (tamper-evident).
