"""
Aegis NIS2 - Web Operations Dashboard.
"""
from __future__ import annotations
from flask import Flask, jsonify, render_template_string
from aegis.db import IncidentDB

app = Flask(__name__)
db = IncidentDB()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis NIS2 Operations Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-8">
    <div class="max-w-6xl mx-auto">
        <header class="mb-8 flex justify-between items-center border-b border-slate-800 pb-4">
            <div>
                <h1 class="text-3xl font-bold tracking-tight text-indigo-400">AEGIS NIS2</h1>
                <p class="text-slate-400 text-sm">Autonomous Incident Triage & Article 23 Compliance Radar</p>
            </div>
            <div class="px-4 py-2 bg-indigo-950 border border-indigo-700 rounded-lg text-indigo-300 text-sm">
                Status: Operational (Local Engine)
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                <div class="text-slate-400 text-xs uppercase font-semibold">Active Incidents</div>
                <div class="text-3xl font-bold mt-2 text-white">{{ incidents|length }}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                <div class="text-slate-400 text-xs uppercase font-semibold">NIS2 Reportable</div>
                <div class="text-3xl font-bold mt-2 text-rose-400">{{ reportable_count }}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                <div class="text-slate-400 text-xs uppercase font-semibold">Contained</div>
                <div class="text-3xl font-bold mt-2 text-emerald-400">{{ contained_count }}</div>
            </div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div class="p-4 border-b border-slate-800 font-semibold text-slate-200">Recent Incident Radar</div>
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-950 text-slate-400 uppercase text-xs">
                    <tr>
                        <th class="p-4">ID</th>
                        <th class="p-4">Severity</th>
                        <th class="p-4">MITRE Technique</th>
                        <th class="p-4">Status</th>
                        <th class="p-4">24h Early Warning Deadline</th>
                    </tr>
                </thead>
                <tbody class="divide-y border-slate-800">
                    {% for inc in incidents %}
                    <tr class="hover:bg-slate-800/50">
                        <td class="p-4 font-mono text-xs text-indigo-300">{{ inc.id }}</td>
                        <td class="p-4"><span class="px-2 py-1 rounded text-xs font-semibold {% if inc.severity.value in ['critical', 'high'] %}bg-rose-950 text-rose-300 border border-rose-800{% else %}bg-slate-800 text-slate-300{% endif %}">{{ inc.severity.value|upper }}</span></td>
                        <td class="p-4 font-mono text-xs">{{ inc.mitre_technique_id or 'N/A' }} ({{ inc.mitre_technique_name or 'N/A' }})</td>
                        <td class="p-4 capitalize text-slate-300">{{ inc.status.value }}</td>
                        <td class="p-4 font-mono text-xs text-slate-400">{{ inc.early_warning_deadline.strftime('%Y-%m-%d %H:%M UTC') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
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
    return render_template_string(HTML_TEMPLATE, incidents=incidents, reportable_count=reportable_count, contained_count=contained_count)

@app.route("/api/incidents")
def api_incidents():
    incidents = db.list_all()
    return jsonify([inc.model_dump(mode="json") for inc in incidents])

def create_app():
    return app
