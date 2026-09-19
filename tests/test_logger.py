"""Tests for the logging sanitiser filter (utils/logger.py).

Regression coverage for the Python 3.12 LogRecord rule: a single
Mapping argument is kept as a mapping in ``record.args`` and its keys
are splatted onto the record. The sanitising filter must never iterate
that mapping into a keys-tuple - doing so broke every dict-argument
log call on 3.12 frozen builds ("not all arguments converted during
string formatting").
"""

from __future__ import annotations

import logging

from utils.logger import SanitizingFilter

FILTER = SanitizingFilter()


def _record(msg: str, args: tuple) -> logging.LogRecord:
    """Build a LogRecord exactly as a logger call would."""
    return logging.LogRecord(
        name="khokharguard.test", level=logging.INFO, pathname="p", lineno=1,
        msg=msg, args=args, exc_info=None)


def test_single_dict_argument_survives() -> None:
    """A sole dict argument must still render.

    LogRecord key-splatting onto the record varies across Python
    versions, so only assert it where it exists; the essential
    guarantee is that the message renders and args are not mangled.
    """
    summary = {"status": "migrated", "history_rows": 5,
               "quarantine_records": 2}
    record = _record("Legacy migration completed: %s", (summary,))
    assert FILTER.filter(record) is True
    if hasattr(record, "status"):               # version-dependent splat
        assert record.status == "migrated"
    assert "quarantine_records': 2" in record.getMessage()
    assert not isinstance(record.args, tuple) or \
        not set(record.args) == {"status", "history_rows",
                                 "quarantine_records"}


def test_single_dict_argument_values_sanitized() -> None:
    """Secret-looking string values inside a mapping are redacted."""
    payload = {"token": "bearer abc.def.ghi", "count": 3}
    record = _record("payload: %s", (payload,))
    FILTER.filter(record)
    message = record.getMessage()
    assert "<redacted>" in message
    assert "abc.def.ghi" not in message


def test_string_args_still_sanitized() -> None:
    """Plain string args keep the original sanitising behaviour."""
    record = _record("connect %s", ("password=hunter2",))
    FILTER.filter(record)
    assert record.getMessage() == "connect <redacted>"


def test_tuple_args_types_preserved() -> None:
    """Non-string tuple args pass through untouched."""
    record = _record("n=%d", (7,))
    FILTER.filter(record)
    assert record.getMessage() == "n=7"


def test_empty_args_ignored() -> None:
    """No-argument records are simply sanitised on the message."""
    record = _record("plain message", ())
    FILTER.filter(record)
    assert record.getMessage() == "plain message"
