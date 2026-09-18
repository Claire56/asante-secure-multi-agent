"""Bridge OpenAI Agents SDK tracing into the application's OpenTelemetry trace.

The Agents SDK keeps its native tracing enabled. This processor is registered as
an additional destination and mirrors only structural metadata into OTel. It
intentionally does not copy prompts, completions, tool arguments, tool outputs,
or other model content.
"""

from __future__ import annotations

from threading import Lock
from typing import Any

from agents.tracing import TracingProcessor
from opentelemetry import context as otel_context
from opentelemetry import trace as otel_trace
from opentelemetry.trace import Status, StatusCode, Tracer


class OpenAIAgentsOpenTelemetryProcessor(TracingProcessor):
    """Mirror Agents SDK trace structure into OpenTelemetry without content."""

    def __init__(self, tracer: Tracer) -> None:
        self._tracer = tracer
        self._trace_roots: dict[str, Any] = {}
        self._trace_parent_contexts: dict[str, Any] = {}
        self._spans: dict[str, Any] = {}
        self._lock = Lock()

    def on_trace_start(self, trace) -> None:
        """Create an OTel workflow span beneath the current application span."""
        parent_context = otel_context.get_current()
        root = self._tracer.start_span(
            "openai.agents.workflow",
            context=parent_context,
            attributes={
                "asante.component": "agent_runtime",
                "gen_ai.operation.name": "agent_workflow",
                "openai.agents.workflow.name": getattr(trace, "name", "Agent workflow"),
            },
        )
        with self._lock:
            self._trace_roots[trace.trace_id] = root
            self._trace_parent_contexts[trace.trace_id] = parent_context

    def on_trace_end(self, trace) -> None:
        """Finish the mirrored workflow span and clear processor state."""
        with self._lock:
            root = self._trace_roots.pop(trace.trace_id, None)
            self._trace_parent_contexts.pop(trace.trace_id, None)
        if root is not None:
            root.end()

    def on_span_start(self, span) -> None:
        """Mirror one Agents SDK structural span with its parent relationship."""
        data = span.span_data
        span_type = str(getattr(data, "type", "unknown"))
        attributes: dict[str, object] = {
            "asante.component": "agent_runtime",
            "openai.agents.span.type": span_type,
        }
        gen_ai_operation = _gen_ai_operation(span_type)
        if gen_ai_operation is not None:
            attributes["gen_ai.operation.name"] = gen_ai_operation

        # These are structural names only. Do not export inputs, outputs, arguments,
        # prompts, completions, or tool results from span_data.
        safe_name = getattr(data, "name", None)
        if isinstance(safe_name, str) and safe_name:
            attributes["openai.agents.operation.name"] = safe_name
        safe_model = getattr(data, "model", None)
        if isinstance(safe_model, str) and safe_model:
            attributes["gen_ai.request.model"] = safe_model

        with self._lock:
            parent = self._spans.get(span.parent_id)
            if parent is None:
                parent = self._trace_roots.get(span.trace_id)

        parent_context = (
            otel_trace.set_span_in_context(parent)
            if parent is not None
            else otel_context.get_current()
        )
        mirrored = self._tracer.start_span(
            _otel_span_name(span_type, safe_name),
            context=parent_context,
            attributes=attributes,
        )
        with self._lock:
            self._spans[span.span_id] = mirrored

    def on_span_end(self, span) -> None:
        """Finish one mirrored Agents SDK span and preserve error status only."""
        with self._lock:
            mirrored = self._spans.pop(span.span_id, None)
        if mirrored is None:
            return

        error = getattr(span, "error", None)
        if error:
            mirrored.set_status(Status(StatusCode.ERROR))
            mirrored.set_attribute("error.type", "openai.agents.span_error")
        mirrored.end()

    def shutdown(self) -> None:
        """End any outstanding mirrored spans during process shutdown."""
        with self._lock:
            spans = list(self._spans.values())
            roots = list(self._trace_roots.values())
            self._spans.clear()
            self._trace_roots.clear()
            self._trace_parent_contexts.clear()
        for span in spans:
            span.end()
        for root in roots:
            root.end()

    def force_flush(self) -> None:
        """The OpenTelemetry provider owns buffering and flushing."""
        return


def _otel_span_name(span_type: str, safe_name: object) -> str:
    """Build a low-cardinality span name from Agents SDK structural metadata."""
    if span_type == "agent" and isinstance(safe_name, str) and safe_name:
        return f"openai.agent {safe_name}"
    if span_type == "function" and isinstance(safe_name, str) and safe_name:
        return f"openai.tool {safe_name}"
    return f"openai.{span_type}"


def _gen_ai_operation(span_type: str) -> str | None:
    """Map only span types with clear OpenTelemetry GenAI operation semantics."""
    return {
        "agent": "invoke_agent",
        "generation": "chat",
        "function": "execute_tool",
    }.get(span_type)
