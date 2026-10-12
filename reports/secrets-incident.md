# Secret giả trong lịch sử Git — điền trong checkpoint 4

> Đây là bài tập phát hiện trên **token giả, vô hiệu** (`LAB24-DEMO`) do repo đề bài cài sẵn, không phải sự cố bảo mật thật. Mọi lệnh quét đều chạy với `--redact`; báo cáo này không chép giá trị token.

- **Scanner và phiên bản:** Gitleaks **8.30.1** (`gitleaks version` → `8.30.1`), tải từ release chính thức `github.com/gitleaks/gitleaks/releases/tag/v8.30.1`, file `gitleaks_8.30.1_windows_x64.zip` khớp SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` trong `gitleaks_8.30.1_checksums.txt` của release. Cấu hình `.gitleaks.toml` = rule mặc định của Gitleaks (`[extend] useDefault = true`) + rule `lab24-synthetic-token`. Hook: pre-commit 4.6.2, `.pre-commit-config.yaml` pin `rev: v8.30.1`, hook `gitleaks-system`, `pass_filenames: false`.

- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise", 2026-10-09T16:22:06Z). File bị xoá ở commit sau `ece6ca4` ("feat: publish two-hour L3 student lab…"), nên HEAD không còn file nhưng blob vẫn nằm trong lịch sử.

- **File, rule và kết quả quét lịch sử:**
  `gitleaks git --config .gitleaks.toml --redact .` → `4 commits scanned`, `leaks found: 1`, **exit 1** (đúng như dự kiến). Chạy thêm `--verbose` (lệnh trong CHECKPOINTS): `RuleID: lab24-synthetic-token`, `File: lab-fake-secret.txt`, `Line: 1`, `Commit: 1bdd849922156c868a5ee9293d68f5b72e242d2c`, `Secret: REDACTED`. Sau khi chỉnh allowlist (dưới đây) chạy lại lệnh quét lịch sử vẫn ra đúng 1 finding này → rule bắt token giả **không** bị tắt.

- **Kết quả quét file hiện tại:**
  - Lần đầu: `gitleaks dir --config .gitleaks.toml --redact .` → `leaks found: 1`, exit 1. `--verbose` cho thấy `RuleID: generic-api-key`, `File: .venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py`, `Line: 45`. Dòng đó chỉ gán lại hàm Windows registry `win32api.RegEnumKey` cho một biến cùng tên; rule generic thấy tên biến có chữ "Key" đứng trước dấu gán cùng một chuỗi entropy cao nên báo nhầm là khoá → **false positive** trong thư viện bên thứ ba, không phải file của bài.
  - Ghi chú: bản đầu của chính báo cáo này trích nguyên văn dòng code đó và bị hook `gitleaks-system` chặn khi commit (cùng rule `generic-api-key`); đã viết lại câu thay vì allowlist `reports/` hay dùng `--no-verify`.
  - Chỉnh: thêm vào `.gitleaks.toml` một `[[allowlists]]` chỉ cho đường dẫn `(?:^|/)\.venv/` (virtualenv cục bộ, vốn đã nằm trong `.gitignore`). Không tắt rule nào, không bỏ qua phần còn lại của repo.
  - Lần hai: `gitleaks dir --config .gitleaks.toml --redact .` → `scanned ~403407 bytes`, `no leaks found`, **exit 0**.
  - `pre-commit run --all-files` → `Detect hardcoded secrets....Passed`.

- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay tại dịch vụ đã cấp token** (vô hiệu token cũ, cấp token mới, cập nhật nơi dùng qua secret manager thay vì file trong repo). Đây là bước duy nhất làm token đã lộ hết giá trị.
  2. **Kiểm tra việc sử dụng sai:** xem audit/access log của dịch vụ từ thời điểm commit `1bdd849` (2026-10-09) tới lúc thu hồi; đánh giá phạm vi quyền của token, dữ liệu/hành động có thể đã bị lạm dụng; báo cáo sự cố theo quy trình nội bộ.
  3. **Xử lý các bản sao:** token còn trong mọi clone, fork, mirror, cache CI, PR ref của repo. Sau khi đã rotate, mới viết lại lịch sử (vd `git filter-repo`) và force-push nếu cần, nhờ nền tảng Git xoá cache/ref còn lưu, yêu cầu người cộng tác clone lại. Viết lại lịch sử chỉ giảm lộ thêm, không thay cho thu hồi.
  4. Ghi nhận bài học: giữ hook quét secret, bật secret scanning/push protection ở nền tảng.

- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Commit `ece6ca4` đã xoá file, nhưng ai có bản clone vẫn đọc được blob ở `1bdd849` — Gitleaks tìm ra nó chính vì quét lịch sử. Xoá file không làm token mất hiệu lực ở dịch vụ cấp.
  - `requirements.lock` (11 package, mỗi package có `--hash=sha256:`; `pip install --require-hashes -r requirements.lock` exit 0) chỉ bảo đảm cài đúng phiên bản và đúng file đã kiểm, chống package bị tráo trong supply chain; nó không liên quan gì tới một secret đã bị commit.
  - Hook `gitleaks-system` chạy `gitleaks git --pre-commit --redact --staged --verbose` (xem `.pre-commit-hooks.yaml` của repo gitleaks tại v8.30.1): chỉ quét thay đổi đã stage của **commit mới**, nên chặn được lần lộ tiếp theo nhưng không tìm lại và không thu hồi token đã nằm trong lịch sử; hook cũng chỉ chạy trên máy đã `pre-commit install` và không được bỏ qua bằng `--no-verify`. Pin và hook là phòng ngừa; rotate mới là khắc phục.
