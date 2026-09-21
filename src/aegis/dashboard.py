"""
Aegis NIS2 - Web Operations Dashboard (Flask + HTMX).
"""
from __future__ import annotations
from flask import Flask, jsonify, render_template_string, request
from aegis.db import IncidentDB
from aegis.playbooks import PlaybookRunner

app = Flask(__name__)
db = IncidentDB()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis NIS2 Operations Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 md:p-10">
    <div class="max-w-7xl mx-auto space-y-8">
        <!-- Top Nav -->
        <header class="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-6 gap-4">
            <div>
                <div class="flex items-center gap-3">
                    <span class="inline-block w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
                    <h1 class="text-3xl font-black tracking-tight text-white">AEGIS <span class="text-indigo-400">NIS2</span></h1>
                </div>
                <p class="text-slate-400 text-sm mt-1">Autonomous Incident Triage & Article 23 Compliance Radar</p>
            </div>
            <div class="flex items-center gap-3">
                <a href="/docs/architecture" target="_blank" class="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-slate-300 text-xs font-medium transition">
                    View Archify Diagram ↗
                </a>
                <div class="px-3.5 py-1.5 bg-indigo-950/80 border border-indigo-700/60 rounded-lg text-indigo-300 text-xs font-semibold">
                    Engine: Active (SQLite/Local)
                </div>
            </div>
        </header>

        <!-- KPI Metrics Grid -->
        <div id="metrics-grid" class="grid grid-cols-1 md:grid-cols-4 gap-4" hx-get="/api/metrics" hx-trigger="every 10s">
            <div class="bg-slate-900/90 border border-slate-800 p-5 rounded-xl shadow-lg">
                <div class="text-slate-400 text-xs uppercase font-bold tracking-wider">Total Ingested</div>
                <div class="text-3xl font-bold mt-2 text-white">{{ incidents|length }}</div>
            </div>
            <div class="bg-slate-900/90 border border-slate-800 p-5 rounded-xl shadow-lg">
                <div class="text-slate-400 text-xs uppercase font-bold tracking-wider">NIS2 Reportable</div>
                <div class="text-3xl font-bold mt-2 text-rose-400">{{ reportable_count }}</div>
            </div>
            <div class="bg-slate-900/90 border border-slate-800 p-5 rounded-xl shadow-lg">
                <div class="text-slate-400 text-xs uppercase font-bold tracking-wider">Contained</div>
                <div class="text-3xl font-bold mt-2 text-emerald-400">{{ contained_count }}</div>
            </div>
            <div class="bg-slate-900/90 border border-slate-800 p-5 rounded-xl shadow-lg">
                <div class="text-slate-400 text-xs uppercase font-bold tracking-wider">Open Triage</div>
                <div class="text-3xl font-bold mt-2 text-amber-400">{{ open_count }}</div>
            </div>
        </div>

        <!-- Radar Table -->
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div class="p-5 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
                <h2 class="font-semibold text-slate-200">Incident Radar & 24h Early Warning Timers</h2>
                <button hx-get="/partials/table" hx-target="#radar-body" class="text-xs text-indigo-400 hover:text-indigo-300 font-medium">
                    Refresh Radar
                </button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-950 text-slate-400 uppercase text-xs">
                        <tr>
                            <th class="p-4">Incident ID</th>
                            <th class="p-4">Severity</th>
                            <th class="p-4">MITRE Technique</th>
                            <th class="p-4">Status</th>
                            <th class="p-4">24h Deadline</th>
                            <th class="p-4 text-right">Containment Action</th>
                        </tr>
                    </thead>
                    <tbody id="radar-body" class="divide-y divide-slate-800/60 font-mono text-xs">
                        {% for inc in incidents %}
                        <tr class="hover:bg-slate-800/40 transition">
                            <td class="p-4 text-indigo-300">{{ inc.id }}</td>
                            <td class="p-4">
                                <span class="px-2 py-1 rounded text-xs font-semibold {% if inc.severity.value in ['critical', 'high'] %}bg-rose-950 text-rose-300 border border-rose-800{% else %}bg-slate-800 text-slate-300{% endif %}">
                                    {{ inc.severity.value|upper }}
                                </span>
                            </td>
                            <td class="p-4 text-slate-300">{{ inc.mitre_technique_id or 'N/A' }} <span class="text-slate-500">({{ inc.mitre_technique_name or 'N/A' }})</span></td>
                            <td class="p-4 capitalize text-slate-300">{{ inc.status.value }}</td>
                            <td class="p-4 text-slate-400">{{ inc.early_warning_deadline.strftime('%Y-%m-%d %H:%M UTC') }}</td>
                            <td class="p-4 text-right">
                                {% if inc.status.value != 'contained' %}
                                <button hx-post="/api/contain/{{ inc.id }}" hx-target="closest tr" hx-swap="outerHTML" class="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-sans transition">
                                    Contain Now
                                </button>
                                {% else %}
                                <span class="text-emerald-400 text-xs font-sans font-medium">✓ Contained</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    incidents = db.list_all()
    reportable_count = sum(1 for inc in incidents if inc.is_nis2_reportable)
    contained_count = sum(1 for inc in incidents if inc.status.value == "contained")
    open_count = len(incidents) - contained_count
    return render_template_string(
        HTML_TEMPLATE,
        incidents=incidents,
        reportable_count=reportable_count,
        contained_count=contained_count,
        open_count=open_count,
    )

@app.route("/docs/architecture")
def arch():
    arch_file = pathlib.Path(__file__).parent.parent.parent / "docs" / "architecture.html"
    if arch_file.exists():
        return arch_file.read_text(encoding="utf-8")
    return "<h1>Architecture diagram</h1>"

@app.route("/api/contain/<incident_id>", methods=["POST"])
def contain_incident(incident_id: str):
    inc = db.get(incident_id)
    if not inc:
        return "<tr class='text-rose-400'><td colspan='6' class='p-4'>Incident not found</td></tr>"
    runner = PlaybookRunner()
    runner.run_for_incident(inc)
    db.save(inc)
    return f"""
    <tr class="hover:bg-slate-800/40 bg-emerald-950/20 font-mono text-xs transition">
        <td class="p-4 text-indigo-300">{inc.id}</td>
        <td class="p-4"><span class="px-2 py-1 rounded text-xs font-semibold bg-rose-950 text-rose-300 border border-rose-800">{inc.severity.value.upper()}</span></td>
        <td class="p-4 text-slate-300">{inc.mitre_technique_id or 'N/A'} <span class="text-slate-500">({inc.mitre_technique_name or 'N/A'})</span></td>
        <td class="p-4 capitalize text-emerald-300">{inc.status.value}</td>
        <td class="p-4 text-slate-400">{inc.early_warning_deadline.strftime('%Y-%m-%d %H:%M UTC')}</td>
        <td class="p-4 text-right"><span class="text-emerald-400 text-xs font-sans font-medium">✓ Contained</span></td>
    </tr>
    """

def create_app():
    return app
