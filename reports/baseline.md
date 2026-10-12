# Baseline — điền trong checkpoint 1

Đọc `_naive_loop()` theo thứ tự `search_docs → find_injection → read_customer → http_post`. Số dòng tính trên code scaffold gốc (các file này không bị sửa trong bài).

1. **Agent có identity mỗi run chưa? Dẫn file/hàm:**
   Chưa. `_naive_loop(message, llm)` chỉ nhận câu hỏi và LLM (`agent/loop.py:27`), không có `agent_id`, `run_id` hay principal; `run_once()` có nhận `principal_id` từ `--as` (`agent/loop.py:58`, `agent/loop.py:83`) nhưng khi rơi về baseline thì gọi `_naive_loop(message, llm)` và bỏ mất danh tính đó (`agent/loop.py:74`). Vì vậy không có gì để kiểm quyền hay ghi "ai làm thay ai".

2. **Ai cho phép `http_post`? Dẫn file/hàm:**
   Không có policy nào kiểm mục đích, quyền hay loại dữ liệu trước khi gửi. Người thực sự quyết định là nội dung ticket: nếu `llm.find_injection()` thấy chỉ thị trong text (`agent/loop.py:34-35`, heuristic ở `agent/llm.py:65-79`) thì agent đọc đúng các `customer_id` attacker ghi (`agent/loop.py:37-39`) rồi POST tới URL attacker đưa (`agent/loop.py:44`). `tools.http_post` chỉ chặn host/port khác `127.0.0.1:10024` (`agent/tools.py:76-83`), không xét dữ liệu gửi đi — ticket là dữ liệu nhưng baseline xử lý chỉ thị bên trong như lệnh.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:**
   Body POST được tạo tại `agent/loop.py:44` là `{"records": collected}`, trong đó `collected` là nguyên hồ sơ khách (CCCD, SĐT, STK, email) lấy ở `agent/loop.py:39`; `requests.post` gửi đi ở `agent/tools.py:84`. Sink ghi mỗi POST thành một dòng JSON `{"path", "body"}` vào `reports/sink.log` (`sink/sink.py:37`, `sink/sink.py:45-47`); bản chép giữ lại làm bằng chứng là `reports/attack-before.log`. Baseline không có ledger nên không có dòng nào ghi lại quyết định gửi.
