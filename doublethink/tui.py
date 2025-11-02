"""Textual TUI for viewing DoubleThink analysis results."""
from __future__ import annotations

from typing import List
from urllib.parse import parse_qs, urlparse

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.progress_bar import ProgressBar as RichProgressBar
from rich.rule import Rule as RichRule
from rich.table import Table
from rich.text import Text

from .rules import AnalysisResult

try:  # pragma: no cover - import guard for optional UI dependency
    from textual.app import App, ComposeResult
    from textual.containers import VerticalScroll
    from textual.widgets import Footer, Header, Static
except Exception as exc:  # pragma: no cover - propagate for caller to handle
    raise RuntimeError("Textual dependency is required to render the interactive TUI") from exc


def _severity_style(severity: str) -> str:
    mapping = {
        "critical": "bold red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold green",
        "informational": "bold cyan",
    }
    return mapping.get(severity.lower(), "bold white")


class DoubleThinkReportApp(App[None]):
    """Interactive report viewer built with Textual."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #overview-scroll {
        height: 1fr;
        padding: 1;
    }

    #overview-panel {
        padding: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self._result = result

    def compose(self) -> ComposeResult:  # noqa: D401 - textual protocol
        yield Header(show_clock=False)
        yield VerticalScroll(
            Static(self._build_overview_panel(), id="overview-panel"),
            id="overview-scroll",
        )
        yield Footer()

    def _build_overview_panel(self) -> Panel:
        summary = self._build_summary_table()
        risk_bar = self._build_risk_bar()
        top_triggers = self._build_top_triggers_table()
        url_breakdown = self._build_url_breakdown_table()
        metadata = self._build_metadata_table()
        red_flags = self._build_red_flags_badges()
        actions = self._build_suggested_actions()

        content = Group(
            summary,
            Align.left(Text("Risk level", style="bold")),
            Align.left(risk_bar),
            RichRule("Top triggers"),
            top_triggers,
            RichRule("URL breakdown"),
            url_breakdown,
            RichRule("Metadata"),
            metadata,
            RichRule("Red flags"),
            red_flags,
            RichRule("Suggested actions"),
            actions,
        )
        return Panel(content, title="DoubleThink overview", border_style="cyan")

    def _build_summary_table(self) -> Table:
        verdict_text = self._verdict_badge()
        table = Table.grid(padding=(0, 1))
        table.add_row("Target", Text(self._result.target, style="bold"))
        table.add_row("Verdict", verdict_text)
        table.add_row(
            "Score",
            Text(
                f"{self._clamped_score()} / 100 ({self._result.severity.title()})",
                style=_severity_style(self._result.severity),
            ),
        )
        table.add_row("Triggered rules", str(len(self._result.matches)))
        return table

    def _build_risk_bar(self) -> RichProgressBar:
        severity = self._normalized_severity()
        color = {
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
        }[severity]
        return RichProgressBar(
            total=100,
            completed=self._clamped_score(),
            complete_style=color,
            finished_style=color,
        )

    def _build_top_triggers_table(self):
        if not self._result.matches:
            return Text("No rule triggers recorded.", style="dim")
        sorted_matches = sorted(self._result.matches, key=lambda match: match.weight, reverse=True)
        top_three = sorted_matches[:3]
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column("Rule", ratio=2, style="bold")
        table.add_column("Weight", justify="right")
        table.add_column("Why", ratio=3)
        for match in top_three:
            reason = match.message or match.description
            table.add_row(match.title, str(match.weight), Text(reason, overflow="fold"))
        return table

    def _build_url_breakdown_table(self):
        parsed = urlparse(self._result.target)
        host = parsed.hostname or ""
        registrable, subdomain = self._split_domain(host)
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        query_params = parse_qs(parsed.query)

        table = Table.grid(padding=(0, 1))
        table.add_row("Scheme", parsed.scheme or "—")
        table.add_row("Registrable domain", registrable or "—")
        table.add_row("Subdomain", subdomain or "—")
        table.add_row("Path segments", str(len(path_segments)))
        table.add_row("Query parameters", str(sum(len(values) for values in query_params.values())))
        return table

    def _build_metadata_table(self):
        if not self._result.metadata:
            return Text("No metadata provided.", style="dim")
        table = Table.grid(padding=(0, 1))
        for key, value in self._result.metadata.items():
            table.add_row(Text(key, style="bold"), Text(str(value)))
        return table

    def _build_red_flags_badges(self):
        flags = self._collect_red_flags()
        if not flags:
            return Text("No red flags detected.", style="dim")
        text = Text()
        for flag in flags:
            text.append(f" {flag} ", style="bold white on red")
            text.append(" ")
        return text

    def _build_suggested_actions(self):
        severity = self._normalized_severity()
        if severity == "High":
            suggestions = [
                "Do not enter credentials.",
                "Open the target inside an isolated sandbox.",
                "Verify hosting and WHOIS information before proceeding.",
            ]
        elif severity == "Medium":
            suggestions = [
                "Be cautious with any forms or credential prompts.",
                "Open the link in a controlled environment first.",
                "Validate the domain ownership if action is required.",
            ]
        else:
            suggestions = [
                "Proceed carefully and monitor for unexpected redirects.",
                "Capture a screenshot or recording for further review.",
            ]
        bullet_list = "\n".join(f"- {line}" for line in suggestions)
        return Text(bullet_list)

    def _verdict_badge(self) -> Text:
        severity = self._normalized_severity()
        color = {
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
        }[severity]
        return Text(f" {severity} ", style=f"bold white on {color}")

    def _normalized_severity(self) -> str:
        severity = self._result.severity.lower()
        if severity in {"critical", "high"}:
            return "High"
        if severity == "medium":
            return "Medium"
        return "Low"

    def _clamped_score(self) -> int:
        return max(0, min(self._result.score, 100))

    def _split_domain(self, host: str) -> tuple[str, str]:
        parts = [segment for segment in host.split(".") if segment]
        if len(parts) >= 2:
            registrable = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
        else:
            registrable = host
            subdomain = ""
        return registrable, subdomain

    def _collect_red_flags(self) -> List[str]:
        flags = set()
        for match in self._result.matches:
            blob = " ".join(
                filter(
                    None,
                    [
                        match.rule_id,
                        match.title,
                        match.message,
                        match.description,
                        match.evidence,
                    ],
                )
            ).lower()
            if any(keyword in blob for keyword in ("typo", "squat")):
                flags.add("typosquat")
            if "redirect" in blob:
                flags.add("http-redirect")
            if any(keyword in blob for keyword in ("credential", "password", "login")):
                flags.add("credential-keyword")

        metadata_blob = " ".join(str(value).lower() for value in self._result.metadata.values())
        if "redirect" in metadata_blob:
            flags.add("http-redirect")
        if "credential" in metadata_blob:
            flags.add("credential-keyword")

        return sorted(flags)


def run_textual_report(result: AnalysisResult) -> None:
    """Run the Textual application to display an analysis result."""

    app = DoubleThinkReportApp(result)
    app.run()
