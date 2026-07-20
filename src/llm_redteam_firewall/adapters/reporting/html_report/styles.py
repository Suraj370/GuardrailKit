"""Embedded CSS for the standalone HTML campaign report.

No external CDN dependencies. Supports light/dark themes and print/PDF.
"""

from __future__ import annotations

CSS = """
:root {
  --bg: #f4f6f9;
  --bg-elevated: #ffffff;
  --bg-muted: #eef1f6;
  --text: #1a2332;
  --text-muted: #5b677a;
  --border: #d8dee9;
  --border-strong: #b7c0d0;
  --accent: #2563eb;
  --accent-soft: #dbeafe;
  --sidebar-width: 240px;
  --radius: 10px;
  --shadow: 0 1px 3px rgba(16, 24, 40, 0.08), 0 1px 2px rgba(16, 24, 40, 0.04);
  --font: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
  --sev-critical: #b91c1c;
  --sev-critical-bg: #fee2e2;
  --sev-high: #c2410c;
  --sev-high-bg: #ffedd5;
  --sev-medium: #a16207;
  --sev-medium-bg: #fef3c7;
  --sev-low: #1d4ed8;
  --sev-low-bg: #dbeafe;
  --sev-info: #475569;
  --sev-info-bg: #e2e8f0;
  --pass: #15803d;
  --pass-bg: #dcfce7;
  --fail: #b91c1c;
  --fail-bg: #fee2e2;
  --chart-1: #2563eb;
  --chart-2: #dc2626;
  --chart-3: #d97706;
  --chart-4: #059669;
  --chart-5: #7c3aed;
}

[data-theme="dark"] {
  --bg: #0f1419;
  --bg-elevated: #1a222d;
  --bg-muted: #243041;
  --text: #e8eef7;
  --text-muted: #9aa8bc;
  --border: #2f3b4d;
  --border-strong: #44536a;
  --accent: #60a5fa;
  --accent-soft: #1e3a5f;
  --shadow: 0 1px 3px rgba(0, 0, 0, 0.35);
  --sev-critical: #fca5a5;
  --sev-critical-bg: #7f1d1d;
  --sev-high: #fdba74;
  --sev-high-bg: #7c2d12;
  --sev-medium: #fcd34d;
  --sev-medium-bg: #713f12;
  --sev-low: #93c5fd;
  --sev-low-bg: #1e3a5f;
  --sev-info: #cbd5e1;
  --sev-info-bg: #334155;
  --pass: #86efac;
  --pass-bg: #14532d;
  --fail: #fca5a5;
  --fail-bg: #7f1d1d;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1419;
    --bg-elevated: #1a222d;
    --bg-muted: #243041;
    --text: #e8eef7;
    --text-muted: #9aa8bc;
    --border: #2f3b4d;
    --border-strong: #44536a;
    --accent: #60a5fa;
    --accent-soft: #1e3a5f;
    --shadow: 0 1px 3px rgba(0, 0, 0, 0.35);
    --sev-critical: #fca5a5;
    --sev-critical-bg: #7f1d1d;
    --sev-high: #fdba74;
    --sev-high-bg: #7c2d12;
    --sev-medium: #fcd34d;
    --sev-medium-bg: #713f12;
    --sev-low: #93c5fd;
    --sev-low-bg: #1e3a5f;
    --sev-info: #cbd5e1;
    --sev-info-bg: #334155;
    --pass: #86efac;
    --pass-bg: #14532d;
    --fail: #fca5a5;
    --fail-bg: #7f1d1d;
  }
}

*, *::before, *::after { box-sizing: border-box; }

html { scroll-behavior: smooth; }

body {
  margin: 0;
  font-family: var(--font);
  font-size: 15px;
  line-height: 1.5;
  color: var(--text);
  background: var(--bg);
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Layout */
.app {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: var(--sidebar-width);
  background: var(--bg-elevated);
  border-right: 1px solid var(--border);
  padding: 1.25rem 0.85rem;
  overflow-y: auto;
  z-index: 100;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.sidebar-brand {
  font-weight: 700;
  font-size: 0.95rem;
  letter-spacing: 0.02em;
  padding: 0.35rem 0.65rem 0.85rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0.5rem;
  color: var(--text);
}

.sidebar-brand span {
  display: block;
  font-weight: 400;
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-top: 0.2rem;
}

.sidebar nav {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  flex: 1;
}

.sidebar nav a {
  display: block;
  padding: 0.5rem 0.7rem;
  border-radius: 8px;
  color: var(--text-muted);
  font-size: 0.9rem;
  text-decoration: none;
}

.sidebar nav a:hover,
.sidebar nav a.active {
  background: var(--accent-soft);
  color: var(--accent);
  text-decoration: none;
}

.sidebar-actions {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border);
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.35rem;
  border: 1px solid var(--border-strong);
  background: var(--bg-elevated);
  color: var(--text);
  border-radius: 8px;
  padding: 0.45rem 0.75rem;
  font: inherit;
  font-size: 0.85rem;
  cursor: pointer;
}

.btn:hover { border-color: var(--accent); color: var(--accent); }
.btn-primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.btn-primary:hover { filter: brightness(1.08); color: #fff; }

.main {
  margin-left: var(--sidebar-width);
  flex: 1;
  min-width: 0;
  padding: 1.5rem 1.75rem 3rem;
}

.page-header {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.65rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.page-header .subtitle {
  margin: 0.25rem 0 0;
  color: var(--text-muted);
  font-size: 0.95rem;
}

section {
  margin-bottom: 2.25rem;
  scroll-margin-top: 1rem;
}

section > h2 {
  margin: 0 0 1rem;
  font-size: 1.2rem;
  font-weight: 650;
  letter-spacing: -0.01em;
}

.card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1rem 1.15rem;
}

/* Summary grid */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.summary-item {
  background: var(--bg-muted);
  border-radius: 8px;
  padding: 0.75rem 0.9rem;
}

.summary-item .label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
  margin-bottom: 0.25rem;
}

.summary-item .value {
  font-size: 1.05rem;
  font-weight: 600;
  word-break: break-word;
}

.chip-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.25rem;
}

.chip {
  display: inline-block;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.15rem 0.55rem;
  font-size: 0.8rem;
}

/* Stat cards */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 0.75rem;
}

.stat-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 0.9rem 1rem;
  text-align: center;
}

.stat-card .stat-value {
  font-size: 1.6rem;
  font-weight: 700;
  line-height: 1.2;
  letter-spacing: -0.02em;
}

.stat-card .stat-label {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
  margin-top: 0.25rem;
}

.stat-card.critical .stat-value { color: var(--sev-critical); }
.stat-card.high .stat-value { color: var(--sev-high); }
.stat-card.medium .stat-value { color: var(--sev-medium); }
.stat-card.low .stat-value { color: var(--sev-low); }
.stat-card.informational .stat-value { color: var(--sev-info); }

/* Tables */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg-elevated);
  box-shadow: var(--shadow);
}

table.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.92rem;
}

table.data-table th,
table.data-table td {
  padding: 0.65rem 0.85rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

table.data-table th {
  background: var(--bg-muted);
  font-weight: 600;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--text-muted);
  white-space: nowrap;
}

table.data-table tr:last-child td { border-bottom: none; }
table.data-table tbody tr:hover { background: var(--bg-muted); }

/* Badges */
.badge {
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0.18rem 0.5rem;
  border-radius: 999px;
  white-space: nowrap;
}

.badge-critical { color: var(--sev-critical); background: var(--sev-critical-bg); }
.badge-high { color: var(--sev-high); background: var(--sev-high-bg); }
.badge-medium { color: var(--sev-medium); background: var(--sev-medium-bg); }
.badge-low { color: var(--sev-low); background: var(--sev-low-bg); }
.badge-informational { color: var(--sev-info); background: var(--sev-info-bg); }
.badge-blocked { color: var(--pass); background: var(--pass-bg); }
.badge-compromised { color: var(--fail); background: var(--fail-bg); }
.badge-leaked { color: var(--fail); background: var(--fail-bg); }
.badge-unsafe { color: var(--sev-high); background: var(--sev-high-bg); }
.badge-errored { color: var(--text-muted); background: var(--bg-muted); border: 1px solid var(--border); }
.badge-status { color: var(--text-muted); background: var(--bg-muted); border: 1px solid var(--border); }

/* Charts */
.chart-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

.chart-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1rem;
}

.chart-card h3 {
  margin: 0 0 0.75rem;
  font-size: 0.95rem;
  font-weight: 600;
}

.chart-card canvas {
  width: 100%;
  height: 220px;
  display: block;
}

/* Filters */
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem;
  margin-bottom: 1rem;
  align-items: flex-end;
}

.filters label {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--text-muted);
}

.filters select,
.filters input[type="search"] {
  min-width: 160px;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--border-strong);
  border-radius: 8px;
  background: var(--bg-elevated);
  color: var(--text);
  font: inherit;
  font-size: 0.9rem;
  font-weight: 400;
  text-transform: none;
  letter-spacing: normal;
}

.filters input[type="search"] { min-width: 220px; }

.filter-meta {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
  color: var(--text-muted);
}

/* Finding cards */
.findings-list,
.evidence-list {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.finding-card,
.evidence-card {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
}

.finding-card.hidden,
.evidence-card.hidden { display: none; }

.finding-card > summary,
.evidence-card > summary {
  list-style: none;
  cursor: pointer;
  padding: 0.85rem 1rem;
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 0.65rem 0.85rem;
  align-items: center;
}

.finding-card > summary::-webkit-details-marker,
.evidence-card > summary::-webkit-details-marker { display: none; }

.finding-card > summary:hover,
.evidence-card > summary:hover { background: var(--bg-muted); }

.finding-title {
  font-weight: 600;
  font-size: 0.95rem;
}

.finding-meta {
  grid-column: 1 / -1;
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  align-items: center;
  font-size: 0.82rem;
  color: var(--text-muted);
}

.finding-id {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text-muted);
}

.finding-body,
.evidence-body {
  border-top: 1px solid var(--border);
  padding: 0.85rem 1rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.detail-block details {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-muted);
}

.detail-block details > summary {
  cursor: pointer;
  padding: 0.5rem 0.75rem;
  font-weight: 600;
  font-size: 0.85rem;
  list-style: none;
}

.detail-block details > summary::-webkit-details-marker { display: none; }

.detail-block details[open] > summary {
  border-bottom: 1px solid var(--border);
}

.detail-block pre,
.mono-block {
  margin: 0;
  padding: 0.75rem;
  font-family: var(--mono);
  font-size: 0.8rem;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 280px;
  overflow: auto;
  background: var(--bg-elevated);
  color: var(--text);
}

.kv-grid {
  display: grid;
  grid-template-columns: minmax(120px, 180px) 1fr;
  gap: 0.35rem 0.75rem;
  font-size: 0.88rem;
}

.kv-grid .k { color: var(--text-muted); font-weight: 600; }
.kv-grid .v { word-break: break-word; font-family: var(--mono); font-size: 0.82rem; }

.empty-state {
  padding: 1.25rem;
  text-align: center;
  color: var(--text-muted);
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  background: var(--bg-elevated);
}

/* Mobile */
.menu-toggle {
  display: none;
  position: fixed;
  top: 0.75rem;
  left: 0.75rem;
  z-index: 120;
}

@media (max-width: 900px) {
  .sidebar {
    transform: translateX(-100%);
    transition: transform 0.2s ease;
  }
  .sidebar.open { transform: translateX(0); }
  .main {
    margin-left: 0;
    padding: 3.5rem 1rem 2rem;
  }
  .menu-toggle { display: inline-flex; }
  .sidebar-backdrop {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    z-index: 90;
  }
  .sidebar-backdrop.show { display: block; }
}

/* Print / PDF */
@media print {
  :root {
    --bg: #fff;
    --bg-elevated: #fff;
    --bg-muted: #f5f5f5;
    --text: #000;
    --text-muted: #333;
    --border: #ccc;
    --shadow: none;
  }

  body { background: #fff; color: #000; font-size: 11pt; }
  .sidebar,
  .menu-toggle,
  .sidebar-backdrop,
  .sidebar-actions,
  .filters,
  .no-print { display: none !important; }
  .main { margin-left: 0; padding: 0; }
  .card,
  .stat-card,
  .chart-card,
  .finding-card,
  .evidence-card,
  .table-wrap {
    box-shadow: none;
    break-inside: avoid;
  }
  .finding-card,
  .evidence-card { page-break-inside: avoid; }
  details[open] > summary,
  details > summary { list-style: none; }
  details:not([open]) > *:not(summary) { display: block !important; }
  details > summary { font-weight: 700; }
  .detail-block pre { max-height: none; overflow: visible; }
  canvas { max-width: 100%; }
  a { color: inherit; text-decoration: none; }
  .page-header { margin-bottom: 1rem; }
  section { margin-bottom: 1.25rem; }
}
"""
