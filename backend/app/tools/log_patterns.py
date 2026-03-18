import re

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

TIMESTAMP_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
]

ERROR_PATTERN = re.compile(r"\berror\b|\bexception\b|\bfatal\b|\btraceback\b", re.IGNORECASE)
WARNING_PATTERN = re.compile(r"\bwarning\b|\bwarn\b", re.IGNORECASE)
INFO_PATTERN = re.compile(r"\binfo\b", re.IGNORECASE)
KEY_FRAGMENT_PATTERN = re.compile(
    r"\berror\b|\bexception\b|\btraceback\b|\bfatal\b|\bfailed\b|\bdenied\b|\bunauthorized\b",
    re.IGNORECASE,
)
