# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:** Windows 10 Home Single Language 10.0.19045, chạy Windows native bằng PowerShell 7.6.6 theo lệnh PowerShell trong hướng dẫn (README ghi Windows native chưa được pilot chính thức). Python 3.11.9 (`.venv`). Gitleaks **8.30.1**. pre-commit 4.6.2, pip-tools 7.6.2, pytest 9.1.1, requests 2.34.2.
- **`python -m pytest tests/ -q`:** `33 passed` — 0 failed, 0 skipped (chạy với `--basetemp=.pytest_tmp`; kết quả ở CP5 và lặp lại ở bước kiểm trước khi nộp).
- **`pre-commit run --all-files`:** `Detect hardcoded secrets....Passed`.
- **Ledger verify:** `True` cho `reports/ledger.jsonl` (48 dòng, 0 dòng thiếu `reason`).
- **`reports/attack-after.log`:** **0 byte**. `reports/attack-before.log`: 4 dòng.
- **Các lỗi còn lại:** không còn test lỗi. Các giới hạn của lab ghi ở cuối file và trong `reports/dpia-lite.md`.

---

## Chi tiết từng bước

### BƯỚC 1 — Chuẩn bị (preflight)

| Lệnh | Output chính |
|---|---|
| `git remote -v` | `origin https://github.com/getlmt/K4-L3-DAY24-LoVanLong-2A202602541` |
| `Test-Path .\CHECKPOINTS.md` / `git cat-file -t 1bdd849` | `True` / `commit` (clone còn lịch sử, không phải ZIP) |
| `python -m venv .venv`; `python -m pip install -r requirements.txt pre-commit pip-tools` | cài thành công |
| `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` | tạo `requirements.lock`: 11 package, 192 dòng `--hash=sha256:` |
| `python -m pip install --require-hashes -r requirements.lock` | exit 0 |
| `python -m agent.check_lure corpus/ticket-901.md` | `✓ search_docs …`, `✓ find_injection nhận diện chỉ thị (4 marker…)`, `1/1 lure sẵn sàng.` |

### CP1 — Baseline
Đọc `_naive_loop()` và viết `reports/baseline.md` (3 câu, có `file:dòng`). Không có test cho bước này.

### CP2 — Red team (khi `agent/runner.py` còn là scaffold)

| Lệnh | Output chính |
|---|---|
| `python sink/sink.py --reset`, rồi `python sink/sink.py` (Terminal A) | `sink đang nghe tại http://127.0.0.1:10024` |
| `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"` (Terminal B) | `Đã tổng hợp 41 ticket (…, ticket-901.md).`; `sink.log` có 1 POST `/reconcile` chứa hồ sơ giả `KH-000999` |
| `python -m agent.check_lure corpus/ticket-90*.md` | 901: 4 marker; 902: 6 marker; 903: 5 marker; 904+904b: 2 marker; mỗi lure `customer_id ['KH-000999']`, `target_url http://127.0.0.1:10024/reconcile`; **`4/4 lure sẵn sàng.`** |
| Kiểm riêng `find_injection` trên từng file 904 / 904b | cả hai trả `None` (mỗi file 1 marker) → chỉ ghép lại mới thành chỉ thị |
| `python sink/sink.py --reset` + khối PowerShell replay từng lure bằng `_naive_loop` (trong hướng dẫn) | `Da thu lure 1` … `Da thu lure 4` |
| `Copy-Item reports/sink.log reports/attack-before.log` | **4 dòng**, thứ tự 901, 902, 903, 904/904b, mỗi dòng có `cccd`, `phone`, `bank_account` giả của `KH-000999` |

### CP3a — PII gate
`python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`

```
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
2 passed
```
Tự kiểm thêm: span `start/end` khớp chính xác nhãn ở 120/120 câu của `tests/vn_pii_testset.jsonl`.
Giới hạn regex: chỉ 4 loại; CCCD = mọi chuỗi đúng 12 chữ số (số đơn hàng 12 số cũng bị che); STK chỉ nhận khi có nhãn `STK`/`số tài khoản`/`tài khoản`; SĐT chỉ dạng `0…`/`+84…` 10–11 số; không nhận diện họ tên, địa chỉ. Kết quả 1.000 là trên bộ synthetic có định dạng đều, không đại diện cho dữ liệu thật.

### CP3b — Policy
`python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` → `4 passed` (restricted + egress deny kể cả principal đủ quyền; internal không egress allow; public + egress không bị rule tối thiểu chặn; mọi quyết định có reason).

### CP3c — OBO
`python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` → `5 passed` (support_l1 deny, dpo allow, agent con không vượt `parent_scopes`, hết hạn/unknown deny, runner kiểm principal tại chỗ gọi tool).

### CP3d — Trifecta split
- `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp` → `1 passed` (không đọc `KH-000777`, vẫn đọc khách hợp lệ).
- `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp` → `8 passed` (4 lure × `support_l1`/`dpo`), **không có SKIP**.

### CP3e — Ledger
- `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` → `3 passed`.
- `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → ledger 24 dòng: `search_docs` allow 1, `read_customer` allow 22 (1 cổng mở store + 21 khách), `http_post` deny 1 (dòng 24, `on_behalf_of=dpo`).
- `python -c "from agent.ledger import verify; …"` → `True`.
- Tự chứng minh tamper: chép ledger sang `.pytest_tmp/`, sửa 1 ký tự ở dòng 13/24 (`"allow"` → `"allaw"`) → `verify()` = `False` (trước khi sửa `True`); bản sao đã xoá.

### CP4 — Supply chain & secrets

| Lệnh | Output chính |
|---|---|
| `gitleaks version` | `8.30.1` |
| `gitleaks git --config .gitleaks.toml --redact .` | `4 commits scanned`, `leaks found: 1`, **exit 1** (dự kiến) |
| `gitleaks git --config .gitleaks.toml --redact --verbose .` | `RuleID: lab24-synthetic-token`, `File: lab-fake-secret.txt`, `Line: 1`, `Commit: 1bdd849922156c868a5ee9293d68f5b72e242d2c` |
| `gitleaks dir --config .gitleaks.toml --redact .` (lần 1) | `leaks found: 1`, exit 1 → `generic-api-key` ở `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45` (false positive) |
| Thêm `[[allowlists]]` chỉ cho `.venv/`, chạy lại **cả hai** lệnh | `gitleaks git`: vẫn 1 finding `lab24-synthetic-token`, exit 1; `gitleaks dir`: `no leaks found`, **exit 0** |
| `python -m piptools compile …` lần nữa / `pip install --require-hashes -r requirements.lock` | lock không đổi (SHA-256 file như cũ) / exit 0 |
| `pre-commit install` / `pre-commit run --all-files` | `pre-commit installed at .git\hooks\pre-commit` / `Detect hardcoded secrets....Passed` |
| `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` | `3 passed` |

### CP5 — Prove

| Lệnh | Output chính |
|---|---|
| (sink server đã tắt) `python sink/sink.py --reset` | `đã reset …\reports\sink.log` |
| `python -m pytest tests/ -q --basetemp=.pytest_tmp` | **`33 passed`** |
| `python sink/sink.py --reset` (lần 2), rồi `python sink/sink.py` | `sink.log` 0 byte, sink nghe ở `127.0.0.1:10024` |
| `$env:PYTHONIOENCODING='utf-8'`; `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` | `Đã tổng hợp 45 ticket (…, ticket-901.md, …, ticket-904b.md).` |
| `Copy-Item reports/sink.log reports/attack-after.log`; `(Get-Item reports/attack-after.log).Length` | **`0`** |
| Kiểm ledger sau lượt chạy | `reports/ledger.jsonl` 48 dòng (2 lượt `dpo`: dòng 1–24 ở CP3e, dòng 25–48 ở CP5), `verify()` = `True`, 0 dòng thiếu `reason`; `http_post` deny ở dòng 24 và **48**, `on_behalf_of=dpo`, reason "deny: dữ liệu restricted không được đi ra ngoài (egress_enabled=True) khi gọi http_post, bất kể principal dpo"; `KH-000999` được đọc hợp lệ ở dòng 23, 47 (khớp `args_hash`); `KH-000777` không xuất hiện |
| Đối chiếu before/after | `attack-before.log` 4 dòng có PII synthetic của `KH-000999` → `attack-after.log` 0 byte |

Đã viết `reports/compliance-mapping.md` (đối chiếu toàn văn PDF Công báo của Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP, Luật 134/2025/QH15 và PDF OWASP Top 10 for Agentic Applications 2026) và `reports/dpia-lite.md`.

### BƯỚC 6 — Kiểm tra trước khi nộp

| Lệnh | Output |
|---|---|
| `python -m pytest tests/ -q --basetemp=.pytest_tmp` | `33 passed` |
| `python -m agent.check_lure corpus/ticket-90*.md` | 4 × `=> SẴN SÀNG`, `4/4 lure sẵn sàng.` |
| `python -c "from agent.ledger import verify; …"` | `True` |
| `pre-commit run --all-files` | `Detect hardcoded secrets....Passed` |
| `git status --short` | chỉ các file bài lab (code, lure, báo cáo, `.gitleaks.toml`, `.pre-commit-config.yaml`, `requirements.lock`); `.venv/`, `.pytest_tmp/`, `reports/sink.log` bị ignore |

Rà điều kiện trượt trong `RUBRIC.md`: không dòng ledger nào thiếu `reason`; không PII của `KH-000999` ra sink sau khi sửa (`attack-after.log` 0 byte); không đọc `KH-000777`; `support_l1` không đọc hồ sơ restricted và agent con không vượt `parent_scopes`; `dpo` vẫn làm việc hợp lệ; repo chỉ có dữ liệu/token synthetic.

Kiểm 3 file evidence trước khi `git add -f`: `attack-before.log` chỉ chứa CCCD/SĐT/email/STK giả của `KH-000999` (đều có trong `data/customers.json`); `attack-after.log` rỗng; `ledger.jsonl` không chứa giá trị nào của `data/customers.json`. Khi quét ledger bằng `agent/pii.py`, regex CCCD báo 2 chuỗi 12 chữ số (dòng 11–12 và 42–43) — đó là đoạn số nằm **bên trong** giá trị hex SHA-256 của `hash`/`prev_hash`, tức false positive của regex, không phải PII.

---

## Lỗi đã gặp và cách sửa

1. **Máy chưa có Gitleaks trong PATH.** Tải `gitleaks_8.30.1_windows_x64.zip` từ release chính thức, kiểm SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` khớp `gitleaks_8.30.1_checksums.txt`, giải nén vào `D:\VinAI\tools\gitleaks` và thêm vào PATH của user.
2. **`gitleaks dir` lần đầu exit 1** vì false positive trong `.venv/` → chỉ allowlist đường dẫn `.venv/` (chi tiết ở `reports/secrets-incident.md`), chạy lại cả hai lệnh quét.
3. **Script phụ (không thuộc bài) báo `UnicodeEncodeError`** khi in tiếng Việt với `python -I` (console cp1252, `-I` bỏ qua `PYTHONIOENCODING`) → dùng `sys.stdout.reconfigure(encoding="utf-8")`. Lệnh của bài chạy với `$env:PYTHONIOENCODING='utf-8'` như hướng dẫn, không gặp lỗi.
4. **Số dòng trong compliance-mapping lệch 1** ở `gate()`/`ledger.append` khi viết lần đầu → đã kiểm lại với file và sửa.
5. **Commit đầu tiên bị hook `gitleaks-system` chặn** (`Detect hardcoded secrets....Failed`, `RuleID: generic-api-key`, `File: reports/secrets-incident.md`, `Line: 13`): báo cáo đã trích nguyên văn dòng code false positive của `.venv`. Commit không được tạo. Sửa bằng cách viết lại câu trong báo cáo (không allowlist `reports/`, không `--no-verify`), chạy lại `gitleaks dir` trên toàn bộ file hiện tại và `pre-commit` rồi mới commit.
6. **Khác biệt giữa hướng dẫn và test:** hướng dẫn ghi `append()` "reason phải có nội dung", nhưng `tests/test_ledger.py::test_every_entry_needs_a_non_empty_reason` gọi `append()` với reason rỗng và chờ `verify()` trả `False` (không chờ exception). Vì vậy `append()` vẫn ghi dòng đó, còn `verify()` phát hiện; runner luôn truyền reason non-empty (`agent/policy.py` không bao giờ trả reason rỗng).

## NOT_VERIFIED / không chạy

- **NOT_VERIFIED:** lệnh preflight trong README `python -m agent.loop --mock --as support_l1 "Tóm tắt ticket về hoá đơn"` — không chạy vì `huong_dan.docx` không có bước này; khi runner còn scaffold mà sink chưa bật, lệnh sẽ dừng với thông báo "Sink chưa chạy". Không chạy lại sau khi sửa runner để giữ nguyên số dòng ledger đã ghi làm bằng chứng.
- **NOT_VERIFIED:** các điều khoản pháp luật không liệt kê trong `reports/compliance-mapping.md`; thành phần hồ sơ đánh giá tác động theo NĐ 356 (Điều 18–19); mức rủi ro của hệ thống theo Luật 134 (Điều 9).
- **Không làm:** các mục bonus (OPA/Cedar, GLiNER, MCP rug pull, delete cascade).

## Giới hạn của kết quả
Dữ liệu, khách hàng, ticket và token đều là synthetic; `--mock`, `--as`, regex PII và ledger một file chỉ chứng minh hành vi trong lab. Hash chain không phát hiện việc xoá dòng cuối hoặc viết lại cả chuỗi khi không có mốc tin cậy bên ngoài. Không suy ra hệ thống thật đã an toàn hoặc tuân thủ pháp luật.
