"""OpenTelemetry regressions for Phase 5 observability boundaries."""

from __future__ import annotations

from types import SimpleNamespace

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from asante_secure_multi_agent.telemetry import (
    OpenAIAgentsOpenTelemetryProcessor,
    current_trace_id,
    inject_current_trace_headers,
)


def _tracer_with_exporter():
    """Return an isolated tracer/exporter without mutating the global provider."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("phase5-test"), exporter, provider


def test_trace_id_and_w3c_traceparent_are_available_inside_active_span() -> None:
    """Current context can be correlated and propagated over the MCP HTTP hop."""
    tracer, _, provider = _tracer_with_exporter()

    with tracer.start_as_current_span("test.request"):
        trace_id = current_trace_id()
        headers = inject_current_trace_headers()

    assert trace_id is not None
    assert len(trace_id) == 32
    assert headers["traceparent"].startswith(f"00-{trace_id}-")
    provider.shutdown()


def test_agents_bridge_preserves_structure_without_copying_model_content() -> None:
    """Agent spans enter OTel, but prompt/tool content is not exported as attributes."""
    tracer, exporter, provider = _tracer_with_exporter()
    processor = OpenAIAgentsOpenTelemetryProcessor(tracer)
    fake_trace = SimpleNamespace(trace_id="trace-test", name="Agent workflow")
    fake_span = SimpleNamespace(
        span_id="span-test",
        trace_id="trace-test",
        parent_id=None,
        span_data=SimpleNamespace(
            type="function",
            name="issue_guest_credit",
            model=None,
            input="SECRET PROMPT DATA",
            output="SECRET TOOL OUTPUT",
        ),
        error=None,
    )

    with tracer.start_as_current_span("http.request"):
        processor.on_trace_start(fake_trace)
        processor.on_span_start(fake_span)
        processor.on_span_end(fake_span)
        processor.on_trace_end(fake_trace)

    spans = exporter.get_finished_spans()
    names = {span.name for span in spans}
    assert "openai.agents.workflow" in names
    assert "openai.tool issue_guest_credit" in names

    mirrored_tool = next(span for span in spans if span.name == "openai.tool issue_guest_credit")
    serialized_attributes = repr(dict(mirrored_tool.attributes))
    assert "SECRET PROMPT DATA" not in serialized_attributes
    assert "SECRET TOOL OUTPUT" not in serialized_attributes
    assert mirrored_tool.attributes["openai.agents.span.type"] == "function"
    provider.shutdown()


def test_agents_bridge_keeps_mirrored_spans_in_parent_request_trace() -> None:
    """The agent workflow is a child of the active application request trace."""
    tracer, exporter, provider = _tracer_with_exporter()
    processor = OpenAIAgentsOpenTelemetryProcessor(tracer)
    fake_trace = SimpleNamespace(trace_id="trace-parent", name="Agent workflow")
    fake_span = SimpleNamespace(
        span_id="span-agent",
        trace_id="trace-parent",
        parent_id=None,
        span_data=SimpleNamespace(type="agent", name="Guest Support", model=None),
        error=None,
    )

    with tracer.start_as_current_span("asante.agent.run"):
        processor.on_trace_start(fake_trace)
        processor.on_span_start(fake_span)
        processor.on_span_end(fake_span)
        processor.on_trace_end(fake_trace)

    spans = exporter.get_finished_spans()
    request = next(span for span in spans if span.name == "asante.agent.run")
    workflow = next(span for span in spans if span.name == "openai.agents.workflow")
    agent = next(span for span in spans if span.name == "openai.agent Guest Support")

    assert workflow.context.trace_id == request.context.trace_id
    assert workflow.parent.span_id == request.context.span_id
    assert agent.context.trace_id == request.context.trace_id
    assert agent.parent.span_id == workflow.context.span_id
    provider.shutdown()
