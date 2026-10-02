"""Shared pytest configuration.

Importing ``asante_secure_multi_agent.main`` configures OpenTelemetry. The default
console exporter flushes at interpreter exit, after pytest has closed captured
stdout, which logs "I/O operation on closed file". Tests that need spans use
their own in-memory exporters, so global export is disabled unless overridden.

The approval store defaults to a SQLite file under ``.asante/``; tests use an
in-memory database so runs never create or reuse local approval state.
"""

import os

os.environ.setdefault("ASANTE_OTEL_EXPORTER", "none")
os.environ.setdefault("ASANTE_APPROVAL_DB_PATH", ":memory:")
