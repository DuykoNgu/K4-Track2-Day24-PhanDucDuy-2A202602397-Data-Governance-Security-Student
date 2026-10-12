# Đánh giá tác động xử lý dữ liệu (DPIA-lite) — Checkpoint 5

### 1. Loại dữ liệu và phân loại
- **Dữ liệu công khai / nội bộ thông thường (`internal` / `public`):**
  - Nội dung các yêu cầu hỗ trợ (ticket khách hàng trong `corpus/*.md`). Chứa thông tin mô tả sự cố, số hiệu ticket, không bao gồm dữ liệu định danh nhạy cảm.
- **Dữ liệu cá nhân nhạy cảm (`restricted`):**
  - Hồ sơ khách hàng trong `data/customers.json`: Mã khách hàng (`customer_id`), Họ và tên (`name`), Số Căn cước công dân (`cccd`), Số điện thoại (`phone`), Số tài khoản ngân hàng (`bank_account`), Địa chỉ thư điện tử (`email`).
  - Các thông tin PII này có nguy cơ cao bị rò rỉ hoặc đánh cắp nếu bị kẻ tấn công exfiltrate ra các endpoint bên ngoài.

### 2. Mục đích xử lý và principal
- **Mục đích hợp lệ:**
  - `summarize-tickets`: Tổng hợp danh sách và tình trạng các ticket mở trong tuần để báo cáo hỗ trợ.
  - `support-reply`: Tra cứu thông tin khách hàng gắn với ticket hợp lệ để phản hồi và hỗ trợ giải quyết sự cố.
- **Vai trò và danh tính ủy quyền (Principals):**
  - `support_l1`: Nhân viên hỗ trợ cấp 1, chỉ được phép tìm kiếm tài liệu (`search_docs`), **không** được phép truy cập hồ sơ khách hàng nhạy cảm (`read_customer`).
  - `dpo` (Data Protection Officer): Cán bộ bảo vệ dữ liệu, được cấp quyền đọc thông tin khách hàng (`read_customer`) cho mục đích `support-reply`.

### 3. Dữ liệu đi qua những run/tool nào, endpoint nào
- **Run A (Unconstrained Boundary):**
  - Thực thi tool `search_docs` để đọc các file trong `corpus/`.
  - Phân loại dữ liệu: `internal`.
  - Chức năng: Đọc và lọc ra danh sách các ticket ID số từ **tên file** (ví dụ `ticket-901.md` -> ID 901). Toàn bộ nội dung free-text chứa payload tấn công hoặc PII tiềm ẩn được lọc qua PII redaction và **không** truyền nguyên văn sang Run B.
- **Run B (Restricted Execution Boundary):**
  - Nhận ticket ID từ Run A, thực hiện ánh xạ đối chiếu sang `data/customers.json` bằng trường `related_tickets` của nguồn tin cậy. Tuyệt đối không đọc ID do attacker tự gán trong free text.
  - Thực thi tool `read_customer` nếu principal có thẩm quyền (`dpo`).
  - Dữ liệu bị ngăn chặn: Khi kẻ tấn công tìm cách gọi `http_post` để gửi dữ liệu tới `http://127.0.0.1:10024/reconcile`, policy PEP chặn ngay lập tức vì dữ liệu mang phân loại `restricted` đi kèm hành động `egress`. Không có byte dữ liệu nào rời khỏi ranh giới hệ thống.

### 4. Bằng chứng deny/allow và giới hạn của mock
- **Bằng chứng Allow:**
  - `search_docs` được allow cho cả `support_l1` và `dpo` vì mục đích `summarize-tickets` trên dữ liệu `internal`.
  - `read_customer` được allow cho `dpo` với mục đích `support-reply` (ghi nhận trong `reports/ledger.jsonl`).
- **Bằng chứng Deny:**
  - `read_customer` bị deny ngay từ PEP khi người gọi là `support_l1` (chứng minh trong `tests/test_obo.py`).
  - `http_post` bị deny tuyệt đối bởi quy tắc tối thiểu `restricted + egress` (ghi nhận trong `reports/ledger.jsonl` dòng 2: `"decision": "deny"`, `"reason": "DENY: restricted data with egress enabled — exfiltration risk"`).
  - Tệp `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
- **Giới hạn của mock:**
  - Toàn bộ dữ liệu khách hàng là dữ liệu tổng hợp (synthetic), không sử dụng PII của cá nhân thật.
  - Endpoint `http://127.0.0.1:10024/reconcile` chạy trên localhost (sink), không kết nối mạng ra Internet bên ngoài.
  - Principal được mô phỏng qua cấu hình `principals.json`, không tích hợp hệ sinh thái IAM/OAuth2 thực tế.
