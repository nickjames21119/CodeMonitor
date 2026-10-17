"""ResearchMonitor — monitoring and incident notification for long-running research jobs."""
__version__ = "0.2.2"

from .progress import checkpoint, message, report, result, should_stop  # noqa: F401  (stdlib-only, safe to import)
