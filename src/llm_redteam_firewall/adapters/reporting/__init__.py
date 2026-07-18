"""Reporter implementations.

Importing this package registers all in-tree reporters with
:data:`llm_redteam_firewall.plugins.REPORTERS`. Of these,
:class:`.console_reporter.ConsoleReporter`,
:class:`.json_reporter.JSONReporter`, and
:class:`.html_reporter.HTMLReporter` are functional; ``markdown`` is a
scaffold placeholder.
"""

from . import console_reporter, html_reporter, json_reporter, markdown_reporter  # noqa: F401

__all__ = ["console_reporter", "html_reporter", "json_reporter", "markdown_reporter"]
