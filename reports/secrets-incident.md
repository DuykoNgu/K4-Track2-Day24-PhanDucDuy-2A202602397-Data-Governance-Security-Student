# Báo cáo sự cố rò rỉ secret trong lịch sử Git — Checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (sử dụng file cấu hình `.gitleaks.toml`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`).
- **File, rule và kết quả quét lịch sử:**
  - File vi phạm: `lab-fake-secret.txt` (dòng 1).
  - Rule ID: `lab24-synthetic-token` (mô tả: "A deliberately invalid lab token; never use real credentials", regex: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`).
  - Lệnh quét: `gitleaks git --config .gitleaks.toml --redact --verbose .`
  - Kết quả: Phát hiện 1 leak (1 finding) ở commit `1bdd849`.
- **Kết quả quét file hiện tại (HEAD):**
  - Lệnh quét: `gitleaks dir --config .gitleaks.toml .`
  - Kết quả: `no leaks found` (file vi phạm đã được xoá ở commit kế tiếp, sạch sẽ trên HEAD hiện tại).
- **Nếu đây là credential thật, cần xử lý thế nào:**
  - Ngay lập tức thực hiện **thu hồi (revoke) và rotate** credential trên hệ thống dịch vụ/nhà cung cấp cấp phát token đó.
  - Kiểm tra audit log của token để phát hiện xem có truy cập trái phép hoặc dấu hiệu khai thác trong khoảng thời gian bị lộ không.
  - Sử dụng các công cụ như `git filter-repo` hoặc BFG Repo-Cleaner để loại bỏ hoàn toàn commit/blob khỏi toàn bộ lịch sử git và force push lại, xóa sạch cache/forks nếu có thể.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - **Xoá file khỏi HEAD không xóa lịch sử:** Trong mô hình phân tán của Git, mọi commit trong lịch sử đều chứa snapshot đầy đủ của file. Bất kỳ ai clone hoặc pull repo đều có thể checkout lại commit `1bdd849` hoặc đọc git blob object để lấy credential. Do đó, xoá ở HEAD không tương đương với việc hủy bỏ giá trị bí mật của credential.
  - **Pin dependency chỉ bảo vệ tính toàn vẹn gói phần mềm (Supply Chain Integrity):** Hash lock và pin dependency ngăn chặn các gói mã độc hay tấn công chuỗi cung ứng khi build/run, nhưng hoàn toàn vô hiệu đối với bí mật đã bị lọt vào mã nguồn hoặc lịch sử phiên bản.
  - **Biện pháp duy nhất có hiệu lực dứt điểm:** Phải vô hiệu hóa hoàn toàn credential đó ở phía Identity Provider / API Provider (thu hồi và rotate).
