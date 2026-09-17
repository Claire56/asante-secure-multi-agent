"""Trusted task registry shared by the HTTP runtime and MCP tool server.

MCP tool arguments are model-controlled input. The task and Ruhusa delegation
chain therefore live in trusted application state and are looked up by a
request-scoped reference carried in MCP ``_meta`` rather than supplied as tool
arguments.
"""

from __future__ import annotations

from asante_secure_multi_agent.context import AsanteRunContext


class TrustedTaskNotFoundError(LookupError):
    """Raised when an MCP call cannot resolve canonical task authority."""


class TrustedTaskRegistry:
    """Process-local canonical task/delegation registry for the current in-process deployment.

    This is intentionally small and in-memory. A later production deployment in
    which the MCP service runs in a separate process or replica will replace it
    with shared trusted state without changing the MCP tool contract.
    """

    def __init__(self) -> None:
        self._contexts: dict[str, AsanteRunContext] = {}

    def register(self, context: AsanteRunContext) -> None:
        """Register one canonical run context under its Ruhusa task ID."""
        task_id = context.task.task_id
        existing = self._contexts.get(task_id)
        if existing is not None and existing != context:
            raise ValueError(f"trusted task already registered: {task_id}")
        self._contexts[task_id] = context

    def require(self, task_id: str) -> AsanteRunContext:
        """Return canonical task authority or fail closed for an unknown ID."""
        try:
            return self._contexts[task_id]
        except KeyError as exc:
            raise TrustedTaskNotFoundError("unknown or expired trusted task") from exc

    def unregister(self, task_id: str) -> None:
        """Remove trusted state when an agent run has completed."""
        self._contexts.pop(task_id, None)

    def contains(self, task_id: str) -> bool:
        """Return whether canonical state is currently registered for a task."""
        return task_id in self._contexts
