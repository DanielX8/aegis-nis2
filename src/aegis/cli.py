"""
Aegis NIS2 - Interactive Command Line Interface.
"""
from __future__ import annotations
import json
import pathlib
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from aegis.db import IncidentDB
from aegis.normalizer import normalize_wazuh
from aegis.triage import triage_alert
from aegis.playbooks import PlaybookRunner
from aegis.reporter import NIS2Reporter
from aegis.threat_intel import ThreatIntelExporter

console = Console()

@click.group()
def cli():
    """Aegis NIS2: Autonomous Incident Triage, Containment & Compliance CLI."""
    pass

@cli.command()
@click.option("--file", "-f", type=click.Path(exists=True), help="Path to raw JSON alert file")
def triage(file):
    """Normalize and triage incoming alerts against MITRE and NIS2 criteria."""
    db = IncidentDB()
    if not file:
        console.print("[yellow]No alert file specified. Loading default samples...[/yellow]")
        file = pathlib.Path("samples/wazuh-alerts.json")
    
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    alerts = [normalize_wazuh(item) for item in data]
    incidents = [triage_alert(a) for a in alerts]

    table = Table(title="NIS2 Incident Triage Radar", show_header=True, header_style="bold magenta")
    table.add_column("Incident ID", style="dim")
    table.add_column("Severity")
    table.add_column("MITRE Technique")
    table.add_column("NIS2 Reportable?")
    table.add_column("Description")

    for inc in incidents:
        db.save(inc)
        color = "red" if inc.severity.value in ("critical", "high") else "green"
        table.add_row(
            inc.id,
            f"[{color}]{inc.severity.value.upper()}[/{color}]",
            f"{inc.mitre_technique_id or 'N/A'} ({inc.mitre_technique_name or 'N/A'})",
            "[bold red]YES[/bold red]" if inc.is_nis2_reportable else "[dim]No[/dim]",
            inc.description[:45],
        )

    console.print(table)
    console.print(f"[bold green]Saved {len(incidents)} triaged incidents to local database.[/bold green]")

@cli.command()
@click.argument("incident_id")
def respond(incident_id):
    """Trigger automated containment playbooks for a triaged incident."""
    db = IncidentDB()
    inc = db.get(incident_id)
    if not inc:
        console.print(f"[bold red]Error:[/bold red] Incident {incident_id} not found in DB.")
        sys.exit(1)

    runner = PlaybookRunner()
    result = runner.run_for_incident(inc)
    db.save(inc)

    console.print(Panel(f"[bold]Playbook:[/bold] {result.playbook_id}\n[bold]Status:[/bold] {result.status}\n[bold]Steps executed:[/bold] {len(result.steps)}", title=f"Containment Action - {incident_id}"))

@cli.command()
@click.argument("incident_id")
@click.option("--type", "report_type", default="24h", type=click.Choice(["24h", "72h"]))
def report(incident_id, report_type):
    """Generate NIS2 Article 23 compliance notifications in Markdown."""
    db = IncidentDB()
    inc = db.get(incident_id)
    if not inc:
        console.print(f"[bold red]Error:[/bold red] Incident {incident_id} not found.")
        sys.exit(1)

    reporter = NIS2Reporter()
    if report_type == "24h":
        doc = reporter.generate_early_warning(inc)
    else:
        doc = reporter.generate_incident_notification(inc)

    console.print(doc)

@cli.command()
@click.argument("incident_id")
def export_stix(incident_id):
    """Export incident and indicators to STIX 2.1 JSON bundle."""
    db = IncidentDB()
    inc = db.get(incident_id)
    if not inc:
        console.print(f"[bold red]Error:[/bold red] Incident {incident_id} not found.")
        sys.exit(1)

    bundle = ThreatIntelExporter.to_stix_bundle(inc)
    console.print_json(data=bundle)

if __name__ == "__main__":
    cli()
