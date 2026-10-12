# DPIA-lite — điền trong checkpoint 5

> Bản mô tả **học tập** cho agent tổng hợp ticket trong lab Day 24, không phải hồ sơ đánh giá tác động xử lý dữ liệu cá nhân theo Điều 21 Luật 91/2025/QH15. Toàn bộ dữ liệu là synthetic do repo cung cấp; agent chạy bằng `--mock`.

## 1. Loại dữ liệu và phân loại

| Dữ liệu | Nội dung | Phân loại trong lab | Ghi chú |
|---|---|---|---|
| `corpus/ticket-001.md`…`ticket-040.md` | Ticket hỗ trợ: họ tên, CCCD, SĐT, STK giả trong text tự do | `internal` (Run A, `search_docs`) | Là **untrusted content**: ai cũng có thể gửi ticket. PII trong text được `agent/pii.py` che trước khi đưa vào bản tóm tắt |
| `corpus/ticket-901.md`…`ticket-904b.md` | 4 lure prompt injection nhắm vào `KH-000999` | `internal`, untrusted | Dùng để red team; chỉ trỏ tới `http://127.0.0.1:10024/reconcile` |
| `data/customers.json` | 26 hồ sơ khách: `customer_id`, họ tên, CCCD, SĐT, STK, email, `related_tickets` | `restricted` (Run B, `read_customer`) | Private store. Theo NĐ 356/2025 Điều 3 khoản 7, SĐT và số định danh cá nhân là dữ liệu **cơ bản**; thông tin tài chính của khách tại tổ chức tín dụng là dữ liệu nhạy cảm (Điều 4 khoản 1 điểm k) — STK đơn lẻ thuộc nhóm nào là diễn giải chưa xác minh. Nhãn `restricted` là quy ước nội bộ của lab |
| `data/principals.json` | 3 principal mô phỏng: `support_l1`, `billing`, `dpo` với `allowed_tools`, `purposes` | Cấu hình tin cậy (mô phỏng) | Không phải hệ thống xác thực |
| `reports/ledger.jsonl` | Metadata mỗi lần xin gọi tool: thời điểm, `agent_id`, `run_id`, `on_behalf_of`, tool, `args_hash`, quyết định, `reason`, `expires_at`, hash chain | Nhật ký kiểm toán | Không chứa PII thô: tham số chỉ lưu dạng sha256 (`agent/runner.py:98-101`) |
| `reports/attack-before.log` | 4 POST chứa hồ sơ giả của `KH-000999` mà sink nhận **trước** khi có control | Bằng chứng (chứa PII synthetic) | Chỉ dữ liệu synthetic và địa chỉ localhost |

## 2. Mục đích xử lý và principal

| Principal | Mục đích được phép (`purposes`) | Tool được phép | Kết quả trong lab |
|---|---|---|---|
| `support_l1` | `summarize-tickets`, `support-reply` | `search_docs` | Run A allow (tóm tắt ticket). Run B **deny** vì `read_customer` không thuộc `allowed_tools` → không mở hồ sơ chứa CCCD/STK |
| `dpo` | `summarize-tickets`, `support-reply`, `privacy-audit` | `search_docs`, `read_customer` | Run A allow; Run B allow cho mục đích `support-reply`, chỉ đọc khách gắn với ticket qua `related_tickets` (21 khách, trong đó có `KH-000999` vì khách này gắn ticket 901–905); `http_post` vẫn **deny** |
| `billing` | `summarize-tickets`, `billing-reconciliation` | `search_docs`, `read_customer` | Không thuộc phạm vi chạy thử của test. Kiểm trực tiếp `check()` với Run B: deny vì `support-reply` không thuộc `purposes` của billing |
| Principal không có trong file | — | — | Mọi tool deny ("không có trong data/principals.json") |

Mục đích của từng run được gán trong code: Run A dùng `summarize-tickets`, Run B và lượt kiểm egress dùng `support-reply` (`agent/runner.py:151-153`, `agent/runner.py:175`, `agent/runner.py:197-199`).

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
câu hỏi người dùng + principal (--as)
  └─ Run A  [PEP: search_docs, internal, egress=False] ──► ledger
       đọc corpus/ (untrusted) → ticket id từ TÊN FILE (ticket-007.md → 7)
       find_injection() chỉ để biết có cần lượt kiểm egress hay không
       pii.redact() → bản tóm tắt trả cho người dùng
  └─ Run B  [PEP: read_customer, restricted] ──► ledger   (nhận list[int], không nhận text)
       related_tickets trong data/customers.json → customer_id
       [PEP lần nữa trước TỪNG read_customer] ──► ledger → tools.read_customer()
  └─ Egress [PEP: http_post, restricted, egress=True] ──► ledger → DENY, không gọi tools.http_post
```

- Endpoint ra ngoài duy nhất mà tool cho phép: `http://127.0.0.1:10024/*` (allowlist cứng ở `agent/tools.py:76-83`), là sink localhost ghi `reports/sink.log`.
- Hồ sơ Run B đọc **không** được đưa vào câu trả lời CLI, ledger hay request ra ngoài.
- Ledger ghi mọi quyết định của PEP, cả allow và deny (`agent/runner.py:113-144`).

## 4. Bằng chứng deny/allow và giới hạn của mock

**Bằng chứng:**
- Trước khi có control: `reports/attack-before.log` có 4 dòng (lure 901, 902, 903, cặp 904/904b), dòng nào cũng chứa CCCD/SĐT/STK giả của `KH-000999`.
- Sau khi có control: cùng câu hỏi `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` khi sink đang nghe → `reports/attack-after.log` = **0 byte**.
- `reports/ledger.jsonl` (48 dòng, `verify()` = True, không dòng nào thiếu `reason`): dòng 24 và 48 là `http_post` **deny** cho `on_behalf_of=dpo` với reason "deny: dữ liệu restricted không được đi ra ngoài (egress_enabled=True) khi gọi http_post, bất kể principal dpo".
- `tests/test_obo.py`: `support_l1` không đọc hồ sơ nào, ledger có `read_customer` deny; `dpo` vẫn đọc được. `tests/test_split.py`: `KH-000777` (chỉ xuất hiện trong text attacker, `related_tickets=[]`) không bao giờ bị đọc. `tests/test_injection.py`: 4 lure × 2 principal đều pass.

**Giới hạn:**
- **Mock LLM:** `find_injection` là heuristic (≥ 2 marker); model thật có thể bị lái theo cách khác, ví dụ làm lệch nội dung bản tóm tắt. Control chỉ bảo đảm text attacker không chọn được tool, customer hay đích gửi.
- **Quyền giả lập:** `--as` chỉ chọn một dòng trong `data/principals.json`, không xác thực ai đang dùng; mục đích gán cố định theo run, không lấy từ yêu cầu thật; TTL cố định 15 phút.
- **Regex PII:** chỉ 4 loại (CCCD, SĐT, STK có nhãn, email), đạt precision/recall 1.000 trên 118 thực thể synthetic nhưng không nhận diện họ tên, địa chỉ, STK không có nhãn, hay định dạng khác bộ test.
- **Tối thiểu hoá dữ liệu:** với câu hỏi "tổng hợp ticket", `dpo` vẫn mở 21 hồ sơ dù câu trả lời không dùng tới — đúng yêu cầu "giữ chức năng hợp lệ" của lab nhưng chưa tối ưu theo nguyên tắc cần thiết.
- **Hash chain:** phát hiện sửa một dòng trong file, nhưng không phát hiện việc xoá dòng cuối hoặc viết lại toàn bộ chuỗi khi không có mốc tin cậy bên ngoài; ledger nằm cùng máy với agent.
- **Phạm vi:** sink localhost, dữ liệu synthetic, không có quy trình thông báo vi phạm, lưu trữ hay xoá dữ liệu; kết quả lab không chứng minh hệ thống thật an toàn hay tuân thủ.
