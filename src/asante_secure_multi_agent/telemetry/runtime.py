"""Application OpenTelemetry configuration and small observability helpers.

Phase 5 keeps telemetry vendor-neutral. The application can export to the
console for local learning, to OTLP for a collector/backend, or nowhere while
still retaining instrumentation code paths for tests.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock

from opentelemetry import metrics, propagate, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Tracer

SERVICE_NAME = "asante-secure-multi-agent"
SERVICE_VERSION = "0.5.0"
DEFAULT_EXPORTER = "console"

_TRACER_NAME = "asante-secure-multi-agent"
_METER_NAME = "asante-secure-multi-agent"
_runtime: TelemetryRuntime | None = None
_runtime_lock = Lock()


@dataclass(frozen=True)
class TelemetryRuntime:
    """Configured application telemetry providers."""

    tracer_provider: TracerProvider
    meter_provider: MeterProvider
    exporter: str

    def shutdown(self) -> None:
        """Flush and stop background telemetry workers."""
        self.tracer_provider.force_flush()
        self.meter_provider.force_flush()
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()


def _resource() -> Resource:
    """Describe this application without attaching user or reservation data."""
    return Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.version": SERVICE_VERSION,
            "deployment.environment.name": os.getenv("ASANTE_ENVIRONMENT", "local"),
        }
    )


def _build_providers(exporter: str) -> tuple[TracerProvider, MeterProvider]:
    """Create trace and metric providers for console, OTLP, or no export."""
    resource = _resource()
    tracer_provider = TracerProvider(resource=resource)

    metric_readers = []
    if exporter == "console":
        tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        metric_readers.append(
            PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=10_000,
            )
        )
    elif exporter == "otlp":
        # The exporters honor the standard OTEL_EXPORTER_OTLP_* environment variables.
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        metric_readers.append(
            PeriodicExportingMetricReader(
                OTLPMetricExporter(),
                export_interval_millis=10_000,
            )
        )
    elif exporter != "none":
        raise RuntimeError("ASANTE_OTEL_EXPORTER must be 'console', 'otlp', or 'none'")

    meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
    return tracer_provider, meter_provider


def configure_telemetry() -> TelemetryRuntime:
    """Configure process-global OpenTelemetry once and return its providers."""
    global _runtime
    if _runtime is not None:
        return _runtime

    with _runtime_lock:
        if _runtime is not None:
            return _runtime

        exporter = os.getenv("ASANTE_OTEL_EXPORTER", DEFAULT_EXPORTER).strip().lower()
        tracer_provider, meter_provider = _build_providers(exporter)
        trace.set_tracer_provider(tracer_provider)
        metrics.set_meter_provider(meter_provider)
        _runtime = TelemetryRuntime(
            tracer_provider=tracer_provider,
            meter_provider=meter_provider,
            exporter=exporter,
        )
        return _runtime


def get_tracer() -> Tracer:
    """Return the application tracer through the OpenTelemetry API."""
    return trace.get_tracer(_TRACER_NAME, SERVICE_VERSION)


def get_meter():
    """Return the application meter through the OpenTelemetry API."""
    return metrics.get_meter(_METER_NAME, SERVICE_VERSION)


def current_trace_id() -> str | None:
    """Return the current W3C-compatible trace ID as 32 lowercase hex characters."""
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return None
    return f"{span_context.trace_id:032x}"


def inject_current_trace_headers(
    headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Inject W3C trace context into outbound headers for the MCP HTTP hop."""
    carrier = dict(headers or {})
    propagate.inject(carrier)
    return carrier


def instrument_fastapi(app, runtime: TelemetryRuntime) -> None:
    """Add HTTP tracing/metrics while excluding the high-frequency health probe."""
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=runtime.tracer_provider,
        meter_provider=runtime.meter_provider,
        excluded_urls="/health",
        exclude_spans=["receive", "send"],
    )
