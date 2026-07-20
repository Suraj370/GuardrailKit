"""Embedded client-side JavaScript for charts, filters, and export.

Lightweight, dependency-free. Designed to stay responsive with hundreds
to ~1000 attack rows by using event delegation and class toggles only.
"""

from __future__ import annotations

JS = r"""
(function () {
  "use strict";

  var REPORT = window.__REPORT_DATA__ || {};
  var charts = REPORT.charts || {};

  function $(id) { return document.getElementById(id); }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function chartColors() {
    return [
      cssVar("--chart-1") || "#2563eb",
      cssVar("--chart-2") || "#dc2626",
      cssVar("--chart-3") || "#d97706",
      cssVar("--chart-4") || "#059669",
      cssVar("--chart-5") || "#7c3aed"
    ];
  }

  /* ---- Simple canvas bar / pie charts ---- */

  function clearCanvas(canvas) {
    var ctx = canvas.getContext("2d");
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    var w = Math.max(1, Math.floor(rect.width * dpr));
    var h = Math.max(1, Math.floor(rect.height * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);
    return { ctx: ctx, width: rect.width, height: rect.height };
  }

  function drawBarChart(canvasId, data, options) {
    var canvas = $(canvasId);
    if (!canvas) return;
    var surface = clearCanvas(canvas);
    var ctx = surface.ctx;
    var width = surface.width;
    var height = surface.height;
    var labels = Object.keys(data || {});
    var values = labels.map(function (k) { return Number(data[k]) || 0; });
    var max = Math.max.apply(null, values.concat([1]));
    var pad = { top: 16, right: 12, bottom: 48, left: 36 };
    var plotW = width - pad.left - pad.right;
    var plotH = height - pad.top - pad.bottom;
    var n = labels.length || 1;
    var gap = 8;
    var barW = Math.max(8, (plotW - gap * (n - 1)) / n);
    var colors = (options && options.colors) || chartColors();
    var textColor = cssVar("--text-muted") || "#5b677a";

    ctx.strokeStyle = cssVar("--border") || "#d8dee9";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top);
    ctx.lineTo(pad.left, pad.top + plotH);
    ctx.lineTo(pad.left + plotW, pad.top + plotH);
    ctx.stroke();

    labels.forEach(function (label, i) {
      var v = values[i];
      var h = (v / max) * plotH;
      var x = pad.left + i * (barW + gap);
      var y = pad.top + plotH - h;
      ctx.fillStyle = colors[i % colors.length];
      ctx.fillRect(x, y, barW, h);

      ctx.fillStyle = textColor;
      ctx.font = "11px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(String(v), x + barW / 2, y - 4);

      ctx.save();
      ctx.translate(x + barW / 2, pad.top + plotH + 10);
      ctx.rotate(-Math.PI / 5);
      ctx.textAlign = "right";
      var short = label.length > 16 ? label.slice(0, 14) + "…" : label;
      ctx.fillText(short, 0, 0);
      ctx.restore();
    });

    if (!labels.length) {
      ctx.fillStyle = textColor;
      ctx.font = "13px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No data", width / 2, height / 2);
    }
  }

  function drawPieChart(canvasId, data) {
    var canvas = $(canvasId);
    if (!canvas) return;
    var surface = clearCanvas(canvas);
    var ctx = surface.ctx;
    var width = surface.width;
    var height = surface.height;
    var labels = Object.keys(data || {});
    var values = labels.map(function (k) { return Number(data[k]) || 0; });
    var total = values.reduce(function (a, b) { return a + b; }, 0);
    var colors = chartColors();
    var textColor = cssVar("--text-muted") || "#5b677a";
    var cx = width * 0.38;
    var cy = height / 2;
    var radius = Math.min(width, height) * 0.32;

    if (total <= 0) {
      ctx.fillStyle = textColor;
      ctx.font = "13px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No data", width / 2, height / 2);
      return;
    }

    var start = -Math.PI / 2;
    values.forEach(function (v, i) {
      var slice = (v / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, radius, start, start + slice);
      ctx.closePath();
      ctx.fillStyle = colors[i % colors.length];
      ctx.fill();
      start += slice;
    });

    var legendX = width * 0.68;
    var legendY = height * 0.22;
    labels.forEach(function (label, i) {
      var y = legendY + i * 22;
      ctx.fillStyle = colors[i % colors.length];
      ctx.fillRect(legendX, y, 12, 12);
      ctx.fillStyle = textColor;
      ctx.font = "12px system-ui, sans-serif";
      ctx.textAlign = "left";
      ctx.fillText(label + " (" + values[i] + ")", legendX + 18, y + 11);
    });
  }

  var severityColors = {
    critical: "#b91c1c",
    high: "#c2410c",
    medium: "#a16207",
    low: "#1d4ed8",
    informational: "#475569"
  };

  function renderCharts() {
    var sev = charts.findings_by_severity || {};
    var sevColors = Object.keys(sev).map(function (k) {
      return severityColors[k] || chartColors()[0];
    });
    drawBarChart("chart-severity", sev, { colors: sevColors });
    drawBarChart("chart-findings-vuln", charts.findings_by_vulnerability || {});
    drawPieChart("chart-pass-fail", charts.pass_vs_fail || {});
    drawBarChart("chart-attacks-vuln", charts.attacks_per_vulnerability || {});
  }

  /* ---- Filters ---- */

  function normalize(s) {
    return (s || "").toString().toLowerCase();
  }

  function applyFilters() {
    var vuln = ($("filter-vulnerability") || {}).value || "";
    var severity = ($("filter-severity") || {}).value || "";
    var status = ($("filter-status") || {}).value || "";
    var result = ($("filter-result") || {}).value || "";
    var q = normalize(($("filter-search") || {}).value || "");

    var findingCards = document.querySelectorAll(".finding-card");
    var visibleFindings = 0;
    findingCards.forEach(function (card) {
      var match = true;
      if (vuln && card.getAttribute("data-vulnerability") !== vuln) match = false;
      if (severity && card.getAttribute("data-severity") !== severity) match = false;
      if (status && card.getAttribute("data-status") !== status) match = false;
      if (result) {
        var passed = card.getAttribute("data-passed") === "true";
        if (result === "Blocked" && !passed) match = false;
        if (result === "Compromised" && passed) match = false;
      }
      if (q) {
        var hay = normalize(card.getAttribute("data-search") || "");
        if (hay.indexOf(q) === -1) match = false;
      }
      card.classList.toggle("hidden", !match);
      if (match) visibleFindings += 1;
    });

    var evidenceCards = document.querySelectorAll(".evidence-card");
    var visibleEvidence = 0;
    evidenceCards.forEach(function (card) {
      var match = true;
      if (vuln && card.getAttribute("data-vulnerability") !== vuln) match = false;
      if (severity && card.getAttribute("data-severity") !== severity) match = false;
      if (result) {
        var passed = card.getAttribute("data-passed") === "true";
        if (result === "Blocked" && !passed) match = false;
        if (result === "Compromised" && passed) match = false;
      }
      if (q) {
        var hay = normalize(card.getAttribute("data-search") || "");
        if (hay.indexOf(q) === -1) match = false;
      }
      card.classList.toggle("hidden", !match);
      if (match) visibleEvidence += 1;
    });

    var findingsMeta = $("findings-filter-meta");
    if (findingsMeta) {
      findingsMeta.textContent =
        "Showing " + visibleFindings + " of " + findingCards.length + " findings";
    }
    var evidenceMeta = $("evidence-filter-meta");
    if (evidenceMeta) {
      evidenceMeta.textContent =
        "Showing " + visibleEvidence + " of " + evidenceCards.length + " attacks";
    }
  }

  function wireFilters() {
    ["filter-vulnerability", "filter-severity", "filter-status", "filter-result", "filter-search"]
      .forEach(function (id) {
        var el = $(id);
        if (!el) return;
        el.addEventListener("input", applyFilters);
        el.addEventListener("change", applyFilters);
      });
    var clearBtn = $("filter-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        ["filter-vulnerability", "filter-severity", "filter-status", "filter-result"].forEach(
          function (id) {
            var el = $(id);
            if (el) el.value = "";
          }
        );
        var search = $("filter-search");
        if (search) search.value = "";
        applyFilters();
      });
    }
    applyFilters();
  }

  /* ---- Theme ---- */

  function wireTheme() {
    var btn = $("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme");
      var next;
      if (current === "dark") next = "light";
      else if (current === "light") next = "dark";
      else {
        var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        next = prefersDark ? "light" : "dark";
      }
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("rtf-report-theme", next); } catch (e) { /* ignore */ }
      renderCharts();
    });
    try {
      var saved = localStorage.getItem("rtf-report-theme");
      if (saved === "light" || saved === "dark") {
        document.documentElement.setAttribute("data-theme", saved);
      }
    } catch (e) { /* ignore */ }
  }

  /* ---- Export ---- */

  function wireExport() {
    var htmlBtn = $("export-html");
    if (htmlBtn) {
      htmlBtn.addEventListener("click", function () {
        var html = "<!doctype html>\n" + document.documentElement.outerHTML;
        var blob = new Blob([html], { type: "text/html;charset=utf-8" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        var name = (REPORT.executive_summary && REPORT.executive_summary.campaign_name) || "campaign";
        a.href = url;
        a.download = name.replace(/[^\w.-]+/g, "_") + "-report.html";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      });
    }
    var printBtn = $("export-print");
    if (printBtn) {
      printBtn.addEventListener("click", function () { window.print(); });
    }
  }

  /* ---- Mobile nav ---- */

  function wireNav() {
    var toggle = $("menu-toggle");
    var sidebar = document.querySelector(".sidebar");
    var backdrop = $("sidebar-backdrop");
    function close() {
      if (sidebar) sidebar.classList.remove("open");
      if (backdrop) backdrop.classList.remove("show");
    }
    function open() {
      if (sidebar) sidebar.classList.add("open");
      if (backdrop) backdrop.classList.add("show");
    }
    if (toggle) toggle.addEventListener("click", open);
    if (backdrop) backdrop.addEventListener("click", close);
    document.querySelectorAll(".sidebar nav a").forEach(function (a) {
      a.addEventListener("click", close);
    });
  }

  /* ---- Init ---- */

  function init() {
    wireTheme();
    renderCharts();
    wireFilters();
    wireExport();
    wireNav();
    window.addEventListener("resize", function () {
      window.clearTimeout(window.__chartResizeTimer);
      window.__chartResizeTimer = window.setTimeout(renderCharts, 120);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
"""
