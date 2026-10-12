"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# STK chỉ nhận khi có nhãn đứng ngay trước ("STK", "số tài khoản", "tài
# khoản"): 8-16 chữ số trần trùng với CCCD (12 số) và SĐT (10 số), nên không
# có nhãn thì không đủ căn cứ gọi là STK. Group 1 là phần số cần che.
_BANK_RE = re.compile(
    r"(?:\bSTK|\bs[ốo] t[àa]i kho[ảa]n|\bt[àa]i kho[ảa]n)\s*[:#]?\s*(\d{8,16})(?!\d)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
# CCCD: đúng 12 chữ số liền nhau, không dính chữ số khác ở hai đầu.
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
# SĐT: 0 (hoặc +84) rồi 9-10 chữ số, cho phép dấu cách/chấm/gạch giữa các số.
_PHONE_RE = re.compile(r"(?<![\d+])(?:\+84|0)(?:[ .-]?\d){9,10}(?!\d)")

# Thứ tự = độ ưu tiên khi hai vùng chồng nhau: STK có nhãn thắng CCCD/SĐT
# (vd "STK 421740666891" là 12 số nhưng là tài khoản), email đứng trước số.
_RECOGNIZERS = (
    ("VN_BANK_ACCOUNT", _BANK_RE, 1),
    ("EMAIL", _EMAIL_RE, 0),
    ("VN_CCCD", _CCCD_RE, 0),
    ("VN_PHONE", _PHONE_RE, 0),
)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    for pii_type, pattern, group in _RECOGNIZERS:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            # Vùng đã được loại ưu tiên cao hơn nhận thì bỏ, tránh báo hai lần.
            if any(start < e["end"] and e["start"] < end for e in entities):
                continue
            entities.append({"type": pii_type, "start": start, "end": end})
    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    # Thay từ cuối về đầu để offset của các vùng phía trước không bị lệch.
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        text = text[: entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text
